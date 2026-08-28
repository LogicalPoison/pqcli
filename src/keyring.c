#define _POSIX_C_SOURCE 200809L
#include "keyring.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef _WIN32
#  include <direct.h>
#  include <io.h>
#  define rmdir _rmdir
#else
#  include <unistd.h>
#endif
#include <dirent.h>

/* Keyring is stored as one .pqpub-style text file per contact under
 * ~/.pqcli/keyring/<name>.pqpub
 * Own identities under ~/.pqcli/keys/<name>/{kem.sk,sig.sk,meta}
 */

static char *keyring_dir(void) {
    char *cfg = pq_get_config_dir();
    if (!cfg) return NULL;
    char *d = pq_path_join(cfg, PQCLI_KEYRING_DIR);
    free(cfg);
    return d;
}

static char *keys_dir(void) {
    char *cfg = pq_get_config_dir();
    if (!cfg) return NULL;
    char *d = pq_path_join(cfg, PQCLI_KEYS_DIR);
    free(cfg);
    return d;
}

static int ensure_dirs(void) {
    char *cfg = pq_get_config_dir();
    if (!cfg) return -1;
    if (pq_ensure_dir(cfg) != 0) { free(cfg); return -1; }
    char *kd = pq_path_join(cfg, PQCLI_KEYS_DIR);
    char *rd = pq_path_join(cfg, PQCLI_KEYRING_DIR);
    free(cfg);
    if (!kd || !rd) { free(kd); free(rd); return -1; }
    int r = 0;
    if (pq_ensure_dir(kd) != 0 || pq_ensure_dir(rd) != 0) r = -1;
    free(kd); free(rd);
    return r;
}

void pq_keyring_free(pq_keyring_t *kr) {
    if (!kr) return;
    for (size_t i = 0; i < kr->count; i++) {
        free(kr->entries[i].name);
        free(kr->entries[i].comment);
        free(kr->entries[i].fingerprint);
        free(kr->entries[i].kem_alg);
        free(kr->entries[i].sig_alg);
        free(kr->entries[i].kem_pk);
        free(kr->entries[i].sig_pk);
    }
    free(kr->entries);
    memset(kr, 0, sizeof(*kr));
}

/* Public key file format (text, PEM-like):
 * -----BEGIN PQ PUBLIC KEY-----
 * Name: alice
 * Comment: ...
 * KEM: ML-KEM-768
 * SIG: ML-DSA-65
 * Fingerprint: <hex>
 * Trusted: yes|no
 * KEM-PK: <base64>
 * SIG-PK: <base64>
 * -----END PQ PUBLIC KEY-----
 */

int pq_write_public_key_file(const char *path,
                             const char *name, const char *comment,
                             const char *kem_alg, const uint8_t *kem_pk, size_t kem_pk_len,
                             const char *sig_alg, const uint8_t *sig_pk, size_t sig_pk_len) {
    char *kem_b64 = pq_bin_to_b64(kem_pk, kem_pk_len);
    char *sig_b64 = pq_bin_to_b64(sig_pk, sig_pk_len);
    if (!kem_b64 || !sig_b64) { free(kem_b64); free(sig_b64); return -1; }

    /* Combined fingerprint of kem_pk || sig_pk */
    size_t combined_len = kem_pk_len + sig_pk_len;
    uint8_t *combined = malloc(combined_len);
    if (!combined) { free(kem_b64); free(sig_b64); return -1; }
    memcpy(combined, kem_pk, kem_pk_len);
    memcpy(combined + kem_pk_len, sig_pk, sig_pk_len);
    char *fp = pq_fingerprint(combined, combined_len);
    free(combined);
    if (!fp) { free(kem_b64); free(sig_b64); return -1; }

    FILE *f = fopen(path, "w");
    if (!f) { free(kem_b64); free(sig_b64); free(fp); return -1; }
    fprintf(f, "-----BEGIN PQ PUBLIC KEY-----\n");
    fprintf(f, "Name: %s\n", name ? name : "");
    fprintf(f, "Comment: %s\n", comment ? comment : "");
    fprintf(f, "KEM: %s\n", kem_alg);
    fprintf(f, "SIG: %s\n", sig_alg);
    fprintf(f, "Fingerprint: %s\n", fp);
    fprintf(f, "Trusted: no\n");
    fprintf(f, "KEM-PK: %s\n", kem_b64);
    fprintf(f, "SIG-PK: %s\n", sig_b64);
    fprintf(f, "-----END PQ PUBLIC KEY-----\n");
    fclose(f);

    free(kem_b64); free(sig_b64); free(fp);
    return 0;
}

int pq_read_public_key_file(const char *path,
                            char **name, char **comment,
                            char **kem_alg, uint8_t **kem_pk, size_t *kem_pk_len,
                            char **sig_alg, uint8_t **sig_pk, size_t *sig_pk_len) {
    *name = *comment = *kem_alg = *sig_alg = NULL;
    *kem_pk = *sig_pk = NULL;
    *kem_pk_len = *sig_pk_len = 0;

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (pq_read_file(path, &raw, &raw_len) != 0) return -1;

    char *text = (char *)raw;
    char *line = text;
    char *kem_b64 = NULL, *sig_b64 = NULL;
    int in_block = 0;

    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        /* trim CR */
        size_t L = strlen(line);
        if (L && line[L-1] == '\r') line[L-1] = 0;

        if (strcmp(line, "-----BEGIN PQ PUBLIC KEY-----") == 0) {
            in_block = 1;
        } else if (strcmp(line, "-----END PQ PUBLIC KEY-----") == 0) {
            break;
        } else if (in_block) {
            if (strncmp(line, "Name: ", 6) == 0) *name = strdup(line + 6);
            else if (strncmp(line, "Comment: ", 9) == 0) *comment = strdup(line + 9);
            else if (strncmp(line, "KEM: ", 5) == 0) *kem_alg = strdup(line + 5);
            else if (strncmp(line, "SIG: ", 5) == 0) *sig_alg = strdup(line + 5);
            else if (strncmp(line, "KEM-PK: ", 8) == 0) kem_b64 = strdup(line + 8);
            else if (strncmp(line, "SIG-PK: ", 8) == 0) sig_b64 = strdup(line + 8);
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(raw);

    if (!*kem_alg || !*sig_alg || !kem_b64 || !sig_b64) {
        free(*name); free(*comment); free(*kem_alg); free(*sig_alg);
        free(kem_b64); free(sig_b64);
        *name = *comment = *kem_alg = *sig_alg = NULL;
        return -1;
    }

    if (pq_b64_to_bin(kem_b64, kem_pk, kem_pk_len) != 0 ||
        pq_b64_to_bin(sig_b64, sig_pk, sig_pk_len) != 0) {
        free(*name); free(*comment); free(*kem_alg); free(*sig_alg);
        free(kem_b64); free(sig_b64);
        free(*kem_pk); free(*sig_pk);
        *name = *comment = *kem_alg = *sig_alg = NULL;
        *kem_pk = *sig_pk = NULL;
        return -1;
    }
    free(kem_b64); free(sig_b64);
    return 0;
}

static int load_entry_from_file(const char *path, pq_keyring_entry_t *e) {
    memset(e, 0, sizeof(*e));
    char *name = NULL, *comment = NULL, *kem_alg = NULL, *sig_alg = NULL;
    uint8_t *kem_pk = NULL, *sig_pk = NULL;
    size_t kem_pk_len = 0, sig_pk_len = 0;

    if (pq_read_public_key_file(path, &name, &comment, &kem_alg, &kem_pk, &kem_pk_len,
                                &sig_alg, &sig_pk, &sig_pk_len) != 0)
        return -1;

    /* Recompute fingerprint */
    size_t clen = kem_pk_len + sig_pk_len;
    uint8_t *c = malloc(clen);
    if (!c) {
        free(name); free(comment); free(kem_alg); free(sig_alg); free(kem_pk); free(sig_pk);
        return -1;
    }
    memcpy(c, kem_pk, kem_pk_len);
    memcpy(c + kem_pk_len, sig_pk, sig_pk_len);
    char *fp = pq_fingerprint(c, clen);
    free(c);

    /* Check Trusted line by re-reading quickly */
    e->trusted = false;
    uint8_t *raw = NULL; size_t raw_len = 0;
    if (pq_read_file(path, &raw, &raw_len) == 0) {
        if (strstr((char *)raw, "Trusted: yes")) e->trusted = true;
        free(raw);
    }

    e->name = name;
    e->comment = comment;
    e->fingerprint = fp;
    e->kem_alg = kem_alg;
    e->sig_alg = sig_alg;
    e->kem_pk = kem_pk;
    e->kem_pk_len = kem_pk_len;
    e->sig_pk = sig_pk;
    e->sig_pk_len = sig_pk_len;
    return 0;
}

int pq_keyring_load(pq_keyring_t *kr) {
    memset(kr, 0, sizeof(*kr));
    if (ensure_dirs() != 0) return -1;
    char *dir = keyring_dir();
    if (!dir) return -1;

    /* Simple: scan directory for *.pqpub using system/dirent would be ideal;
       for maximal portability we keep a simple index file "index" listing names. */
    char *index_path = pq_path_join(dir, "index");
    free(dir);
    if (!index_path) return -1;

    if (!pq_file_exists(index_path)) {
        free(index_path);
        return 0; /* empty keyring is fine */
    }

    uint8_t *raw = NULL; size_t raw_len = 0;
    if (pq_read_file(index_path, &raw, &raw_len) != 0) {
        free(index_path); return -1;
    }
    free(index_path);

    char *text = (char *)raw;
    char *line = text;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t L = strlen(line);
        if (L && line[L-1] == '\r') line[L-1] = 0;
        if (L > 0 && line[0] != '#') {
            char *dir2 = keyring_dir();
            char *path = pq_path_join(dir2, line);
            free(dir2);
            if (path) {
                /* append .pqpub if not present */
                char *full = path;
                if (!strstr(path, ".pqpub")) {
                    full = malloc(strlen(path) + 8);
                    if (full) sprintf(full, "%s.pqpub", path);
                    free(path);
                }
                if (full) {
                    pq_keyring_entry_t e;
                    if (load_entry_from_file(full, &e) == 0) {
                        if (kr->count >= kr->capacity) {
                            size_t nc = kr->capacity ? kr->capacity * 2 : 8;
                            pq_keyring_entry_t *ne = realloc(kr->entries, nc * sizeof(*ne));
                            if (!ne) {
                                free(e.name); free(e.comment); free(e.fingerprint);
                                free(e.kem_alg); free(e.sig_alg); free(e.kem_pk); free(e.sig_pk);
                            } else {
                                kr->entries = ne;
                                kr->capacity = nc;
                                kr->entries[kr->count++] = e;
                            }
                        } else {
                            kr->entries[kr->count++] = e;
                        }
                    }
                    free(full);
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(raw);
    return 0;
}

int pq_keyring_save(const pq_keyring_t *kr) {
    if (ensure_dirs() != 0) return -1;
    char *dir = keyring_dir();
    if (!dir) return -1;
    char *index_path = pq_path_join(dir, "index");
    if (!index_path) { free(dir); return -1; }

    FILE *f = fopen(index_path, "w");
    if (!f) { free(dir); free(index_path); return -1; }

    for (size_t i = 0; i < kr->count; i++) {
        const pq_keyring_entry_t *e = &kr->entries[i];
        char fname[512];
        snprintf(fname, sizeof(fname), "%s.pqpub", e->name);
        fprintf(f, "%s\n", fname);

        char *path = pq_path_join(dir, fname);
        if (path) {
            pq_write_public_key_file(path, e->name, e->comment,
                                     e->kem_alg, e->kem_pk, e->kem_pk_len,
                                     e->sig_alg, e->sig_pk, e->sig_pk_len);
            /* Update Trusted flag by rewriting the Trusted line */
            if (e->trusted) {
                uint8_t *raw = NULL; size_t raw_len = 0;
                if (pq_read_file(path, &raw, &raw_len) == 0) {
                    char *t = strstr((char *)raw, "Trusted: no");
                    if (t) {
                        memcpy(t, "Trusted: yes", 12);
                        pq_write_file(path, raw, raw_len, 0600);
                    }
                    free(raw);
                }
            }
            free(path);
        }
    }
    fclose(f);
    free(dir); free(index_path);
    return 0;
}

int pq_keyring_add(pq_keyring_t *kr, const char *name, const char *comment,
                   const char *kem_alg, const uint8_t *kem_pk, size_t kem_pk_len,
                   const char *sig_alg, const uint8_t *sig_pk, size_t sig_pk_len) {
    /* replace if exists */
    for (size_t i = 0; i < kr->count; i++) {
        if (strcmp(kr->entries[i].name, name) == 0) {
            free(kr->entries[i].comment);
            free(kr->entries[i].fingerprint);
            free(kr->entries[i].kem_alg);
            free(kr->entries[i].sig_alg);
            free(kr->entries[i].kem_pk);
            free(kr->entries[i].sig_pk);
            kr->entries[i].comment = comment ? strdup(comment) : NULL;
            kr->entries[i].kem_alg = strdup(kem_alg);
            kr->entries[i].sig_alg = strdup(sig_alg);
            kr->entries[i].kem_pk = malloc(kem_pk_len);
            kr->entries[i].sig_pk = malloc(sig_pk_len);
            if (!kr->entries[i].kem_pk || !kr->entries[i].sig_pk) return -1;
            memcpy(kr->entries[i].kem_pk, kem_pk, kem_pk_len);
            memcpy(kr->entries[i].sig_pk, sig_pk, sig_pk_len);
            kr->entries[i].kem_pk_len = kem_pk_len;
            kr->entries[i].sig_pk_len = sig_pk_len;
            size_t cl = kem_pk_len + sig_pk_len;
            uint8_t *c = malloc(cl);
            memcpy(c, kem_pk, kem_pk_len);
            memcpy(c + kem_pk_len, sig_pk, sig_pk_len);
            kr->entries[i].fingerprint = pq_fingerprint(c, cl);
            free(c);
            return 0;
        }
    }

    if (kr->count >= kr->capacity) {
        size_t nc = kr->capacity ? kr->capacity * 2 : 8;
        pq_keyring_entry_t *ne = realloc(kr->entries, nc * sizeof(*ne));
        if (!ne) return -1;
        kr->entries = ne;
        kr->capacity = nc;
    }
    pq_keyring_entry_t *e = &kr->entries[kr->count];
    memset(e, 0, sizeof(*e));
    e->name = strdup(name);
    e->comment = comment ? strdup(comment) : NULL;
    e->kem_alg = strdup(kem_alg);
    e->sig_alg = strdup(sig_alg);
    e->kem_pk = malloc(kem_pk_len);
    e->sig_pk = malloc(sig_pk_len);
    if (!e->name || !e->kem_alg || !e->sig_alg || !e->kem_pk || !e->sig_pk) return -1;
    memcpy(e->kem_pk, kem_pk, kem_pk_len);
    memcpy(e->sig_pk, sig_pk, sig_pk_len);
    e->kem_pk_len = kem_pk_len;
    e->sig_pk_len = sig_pk_len;
    size_t cl = kem_pk_len + sig_pk_len;
    uint8_t *c = malloc(cl);
    memcpy(c, kem_pk, kem_pk_len);
    memcpy(c + kem_pk_len, sig_pk, sig_pk_len);
    e->fingerprint = pq_fingerprint(c, cl);
    free(c);
    e->trusted = false;
    kr->count++;
    return 0;
}

int pq_keyring_remove(pq_keyring_t *kr, const char *name) {
    for (size_t i = 0; i < kr->count; i++) {
        if (strcmp(kr->entries[i].name, name) == 0) {
            free(kr->entries[i].name);
            free(kr->entries[i].comment);
            free(kr->entries[i].fingerprint);
            free(kr->entries[i].kem_alg);
            free(kr->entries[i].sig_alg);
            free(kr->entries[i].kem_pk);
            free(kr->entries[i].sig_pk);
            memmove(&kr->entries[i], &kr->entries[i+1],
                    (kr->count - i - 1) * sizeof(pq_keyring_entry_t));
            kr->count--;
            /* also remove file */
            char *dir = keyring_dir();
            if (dir) {
                char fname[512];
                snprintf(fname, sizeof(fname), "%s.pqpub", name);
                char *path = pq_path_join(dir, fname);
                if (path) { remove(path); free(path); }
                free(dir);
            }
            return 0;
        }
    }
    return -1;
}

pq_keyring_entry_t *pq_keyring_find(pq_keyring_t *kr, const char *name) {
    for (size_t i = 0; i < kr->count; i++)
        if (strcmp(kr->entries[i].name, name) == 0) return &kr->entries[i];
    return NULL;
}

pq_keyring_entry_t *pq_keyring_find_by_fp(pq_keyring_t *kr, const char *fp) {
    for (size_t i = 0; i < kr->count; i++)
        if (kr->entries[i].fingerprint && strcmp(kr->entries[i].fingerprint, fp) == 0)
            return &kr->entries[i];
    return NULL;
}

void pq_keyring_list(const pq_keyring_t *kr) {
    if (kr->count == 0) {
        printf("Keyring is empty.\n");
        return;
    }
    printf("%-16s  %-10s  %-32s  %s\n", "NAME", "TRUSTED", "FINGERPRINT", "ALGS");
    for (size_t i = 0; i < kr->count; i++) {
        const pq_keyring_entry_t *e = &kr->entries[i];
        printf("%-16s  %-10s  %-32s  %s / %s\n",
               e->name,
               e->trusted ? "yes" : "no",
               e->fingerprint ? e->fingerprint : "-",
               e->kem_alg, e->sig_alg);
        if (e->comment && e->comment[0])
            printf("    comment: %s\n", e->comment);
    }
}

int pq_keyring_set_trusted(pq_keyring_t *kr, const char *name, bool trusted) {
    pq_keyring_entry_t *e = pq_keyring_find(kr, name);
    if (!e) return -1;
    e->trusted = trusted;
    return 0;
}

/* Own identity storage: binary secret keys + meta text */
int pq_identity_save(const pq_identity_t *id, const char *name, const char *passphrase) {
    if (ensure_dirs() != 0) return -1;
    char *kd = keys_dir();
    if (!kd) return -1;
    char *idir = pq_path_join(kd, name);
    free(kd);
    if (!idir) return -1;
    if (pq_ensure_dir(idir) != 0) { free(idir); return -1; }

    char *meta = pq_path_join(idir, "meta");
    char *kem_sk = pq_path_join(idir, "kem.sk");
    char *sig_sk = pq_path_join(idir, "sig.sk");
    char *kem_pk = pq_path_join(idir, "kem.pk");
    char *sig_pk = pq_path_join(idir, "sig.pk");
    if (!meta || !kem_sk || !sig_sk || !kem_pk || !sig_pk) {
        free(meta); free(kem_sk); free(sig_sk); free(kem_pk); free(sig_pk); free(idir);
        return -1;
    }

    FILE *f = fopen(meta, "w");
    if (!f) {
        free(meta); free(kem_sk); free(sig_sk); free(kem_pk); free(sig_pk); free(idir);
        return -1;
    }
    fprintf(f, "kem_alg=%s\n", id->kem_alg);
    fprintf(f, "sig_alg=%s\n", id->sig_alg);
    fprintf(f, "protected=%s\n", passphrase ? "yes" : "no");
    fclose(f);

    if (!passphrase && !getenv("PQCLI_ALLOW_PLAINTEXT_KEYS")) {
        /* Refuse writing plaintext secret keys */
        free(meta); free(kem_sk); free(sig_sk); free(kem_pk); free(sig_pk); free(idir);
        return -1;
    }

    int r = 0;
    if (passphrase) {
        uint8_t *blob = NULL; size_t blen = 0;
        if (pq_protect_secret(id->kem.secret_key, id->kem.secret_key_len, passphrase, &blob, &blen) != 0)
            r = -1;
        else {
            if (pq_write_file(kem_sk, blob, blen, 0600) != 0) r = -1;
            free(blob);
        }
        blob = NULL; blen = 0;
        if (r == 0 && pq_protect_secret(id->sig.secret_key, id->sig.secret_key_len, passphrase, &blob, &blen) != 0)
            r = -1;
        else if (r == 0) {
            if (pq_write_file(sig_sk, blob, blen, 0600) != 0) r = -1;
            free(blob);
        }
    } else {
        if (pq_write_file(kem_sk, id->kem.secret_key, id->kem.secret_key_len, 0600) != 0) r = -1;
        if (pq_write_file(sig_sk, id->sig.secret_key, id->sig.secret_key_len, 0600) != 0) r = -1;
    }
    if (pq_write_file(kem_pk, id->kem.public_key, id->kem.public_key_len, 0644) != 0) r = -1;
    if (pq_write_file(sig_pk, id->sig.public_key, id->sig.public_key_len, 0644) != 0) r = -1;

    free(meta); free(kem_sk); free(sig_sk); free(kem_pk); free(sig_pk); free(idir);
    return r;
}

int pq_identity_load(const char *name, pq_identity_t *id, const char *passphrase) {
    memset(id, 0, sizeof(*id));
    char *kd = keys_dir();
    if (!kd) return -1;
    char *idir = pq_path_join(kd, name);
    free(kd);
    if (!idir) return -1;

    char *meta = pq_path_join(idir, "meta");
    char *kem_sk_path = pq_path_join(idir, "kem.sk");
    char *sig_sk_path = pq_path_join(idir, "sig.sk");
    char *kem_pk_path = pq_path_join(idir, "kem.pk");
    char *sig_pk_path = pq_path_join(idir, "sig.pk");
    free(idir);
    if (!meta || !kem_sk_path || !sig_sk_path || !kem_pk_path || !sig_pk_path) {
        free(meta); free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
        return -1;
    }

    uint8_t *mraw = NULL; size_t mlen = 0;
    if (pq_read_file(meta, &mraw, &mlen) != 0) {
        free(meta); free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
        return -1;
    }
    free(meta);
    int protected = 0;
    char *line = (char *)mraw;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strncmp(line, "kem_alg=", 8) == 0) id->kem_alg = strdup(line + 8);
        else if (strncmp(line, "sig_alg=", 8) == 0) id->sig_alg = strdup(line + 8);
        else if (strncmp(line, "protected=", 10) == 0)
            protected = (strcmp(line + 10, "yes") == 0);
        if (!nl) break;
        line = nl + 1;
    }
    free(mraw);

    if (!id->kem_alg || !id->sig_alg) {
        free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
        pq_identity_free(id);
        return -1;
    }

    id->kem.alg = strdup(id->kem_alg);
    id->sig.alg = strdup(id->sig_alg);

    uint8_t *kem_raw = NULL, *sig_raw = NULL;
    size_t kem_raw_len = 0, sig_raw_len = 0;
    if (pq_read_file(kem_sk_path, &kem_raw, &kem_raw_len) != 0 ||
        pq_read_file(sig_sk_path, &sig_raw, &sig_raw_len) != 0 ||
        pq_read_file(kem_pk_path, &id->kem.public_key, &id->kem.public_key_len) != 0 ||
        pq_read_file(sig_pk_path, &id->sig.public_key, &id->sig.public_key_len) != 0) {
        free(kem_raw); free(sig_raw);
        free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
        pq_identity_free(id);
        return -1;
    }

    if (protected) {
        if (!passphrase) {
            free(kem_raw); free(sig_raw);
            free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
            pq_identity_free(id);
            return -2; /* need passphrase */
        }
        if (pq_unprotect_secret(kem_raw, kem_raw_len, passphrase,
                                &id->kem.secret_key, &id->kem.secret_key_len) != 0 ||
            pq_unprotect_secret(sig_raw, sig_raw_len, passphrase,
                                &id->sig.secret_key, &id->sig.secret_key_len) != 0) {
            free(kem_raw); free(sig_raw);
            free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
            pq_identity_free(id);
            return -1;
        }
        free(kem_raw); free(sig_raw);
    } else {
        id->kem.secret_key = kem_raw;
        id->kem.secret_key_len = kem_raw_len;
        id->sig.secret_key = sig_raw;
        id->sig.secret_key_len = sig_raw_len;
    }

    free(kem_sk_path); free(sig_sk_path); free(kem_pk_path); free(sig_pk_path);
    return 0;
}

int pq_identity_is_protected(const char *name) {
    char *kd = keys_dir();
    if (!kd) return -1;
    char *idir = pq_path_join(kd, name);
    free(kd);
    if (!idir) return -1;
    char *meta = pq_path_join(idir, "meta");
    free(idir);
    if (!meta) return -1;
    uint8_t *raw = NULL; size_t len = 0;
    if (pq_read_file(meta, &raw, &len) != 0) { free(meta); return -1; }
    free(meta);
    int p = (strstr((char *)raw, "protected=yes") != NULL) ? 1 : 0;
    free(raw);
    return p;
}

int pq_identity_list(void) {
    char *kd = keys_dir();
    if (!kd) {
        printf("No identities found (cannot resolve keys dir).\n");
        return -1;
    }

    char **names = NULL;
    size_t ncount = 0, ncap = 0;

    DIR *dir = opendir(kd);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_name[0] == '.') continue;
            /* skip the identities index file */
            if (strcmp(ent->d_name, "identities") == 0) continue;
            char *subdir = pq_path_join(kd, ent->d_name);
            if (!subdir) continue;
            char *meta = pq_path_join(subdir, "meta");
            free(subdir);
            if (!meta) continue;
            int is_id = pq_file_exists(meta);
            free(meta);
            if (!is_id) continue;
            if (ncount >= ncap) {
                ncap = ncap ? ncap * 2 : 8;
                char **nn = realloc(names, ncap * sizeof(char *));
                if (!nn) break;
                names = nn;
            }
            names[ncount++] = strdup(ent->d_name);
        }
        closedir(dir);
    }

    if (ncount == 0) {
        char *list_path = pq_path_join(kd, "identities");
        if (list_path && pq_file_exists(list_path)) {
            uint8_t *raw = NULL; size_t len = 0;
            if (pq_read_file(list_path, &raw, &len) == 0) {
                char *line = (char *)raw;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = 0;
                    size_t L = strlen(line);
                    while (L > 0 && (line[L-1] == '\r' || line[L-1] == ' ')) line[--L] = 0;
                    if (line[0] && line[0] != '#') {
                        if (ncount >= ncap) {
                            ncap = ncap ? ncap * 2 : 8;
                            names = realloc(names, ncap * sizeof(char *));
                        }
                        names[ncount++] = strdup(line);
                    }
                    if (!nl) break;
                    line = nl + 1;
                }
                free(raw);
            }
        }
        free(list_path);
    }

    if (ncount == 0) {
        printf("No identities found.\n");
        printf("  Create one with: pqcli genkey <name>\n");
        printf("  Expected dir: %s\n", kd);
        free(kd);
        free(names);
        return 0;
    }

    printf("%-16s  %-18s  %-18s  %s\n", "NAME", "KEM", "SIG", "FINGERPRINT");
    for (size_t i = 0; i < ncount; i++) {
        char *name = names[i];
        /* strip CR just in case */
        size_t L = strlen(name);
        while (L > 0 && (name[L-1] == '\r' || name[L-1] == ' ')) name[--L] = 0;

        char *idir = pq_path_join(kd, name);
        char *meta_path = idir ? pq_path_join(idir, "meta") : NULL;
        char *kem_pk_path = idir ? pq_path_join(idir, "kem.pk") : NULL;
        char *sig_pk_path = idir ? pq_path_join(idir, "sig.pk") : NULL;

        char *kem_alg = NULL, *sig_alg = NULL;
        if (meta_path) {
            uint8_t *mraw = NULL; size_t mlen = 0;
            if (pq_read_file(meta_path, &mraw, &mlen) == 0) {
                char *line = (char *)mraw;
                while (line && *line) {
                    char *nl = strchr(line, '\n');
                    if (nl) *nl = 0;
                    size_t ll = strlen(line);
                    while (ll > 0 && line[ll-1] == '\r') line[--ll] = 0;
                    if (strncmp(line, "kem_alg=", 8) == 0) kem_alg = strdup(line + 8);
                    else if (strncmp(line, "sig_alg=", 8) == 0) sig_alg = strdup(line + 8);
                    if (!nl) break;
                    line = nl + 1;
                }
                free(mraw);
            }
        }

        char *fp = NULL;
        if (kem_pk_path && sig_pk_path) {
            uint8_t *kpk = NULL, *spk = NULL;
            size_t klen = 0, slen = 0;
            if (pq_read_file(kem_pk_path, &kpk, &klen) == 0 &&
                pq_read_file(sig_pk_path, &spk, &slen) == 0) {
                size_t cl = klen + slen;
                uint8_t *comb = malloc(cl);
                if (comb) {
                    memcpy(comb, kpk, klen);
                    memcpy(comb + klen, spk, slen);
                    fp = pq_fingerprint(comb, cl);
                    free(comb);
                }
            }
            free(kpk); free(spk);
        }

        int prot = pq_identity_is_protected(name);
        printf("%-16s  %-18s  %-18s  %s%s\n",
               name[0] ? name : "(unnamed)",
               kem_alg ? kem_alg : "?",
               sig_alg ? sig_alg : "?",
               fp ? fp : "-",
               prot == 1 ? "  [protected]" : "");

        free(idir); free(meta_path); free(kem_pk_path); free(sig_pk_path);
        free(kem_alg); free(sig_alg); free(fp);
        free(names[i]);
    }
    free(names);
    free(kd);
    return 0;
}

static int identity_register(const char *name) {
    if (ensure_dirs() != 0) return -1;
    char *kd = keys_dir();
    if (!kd) return -1;
    char *list_path = pq_path_join(kd, "identities");
    free(kd);
    if (!list_path) return -1;

    /* append if not present */
    int exists = 0;
    if (pq_file_exists(list_path)) {
        uint8_t *raw = NULL; size_t len = 0;
        if (pq_read_file(list_path, &raw, &len) == 0) {
            char *line = (char *)raw;
            while (line && *line) {
                char *nl = strchr(line, '\n');
                if (nl) *nl = 0;
                if (strcmp(line, name) == 0) { exists = 1; break; }
                if (!nl) break;
                line = nl + 1;
            }
            free(raw);
        }
    }
    if (!exists) {
        FILE *f = fopen(list_path, "a");
        if (f) {
            fprintf(f, "%s\n", name);
            fclose(f);
        }
    }
    free(list_path);
    return 0;
}

int pq_identity_export_public(const char *name, const char *out_path) {
    char *kd = keys_dir();
    if (!kd) return -1;
    char *idir = pq_path_join(kd, name);
    free(kd);
    if (!idir) return -1;
    char *meta = pq_path_join(idir, "meta");
    char *kem_pk_path = pq_path_join(idir, "kem.pk");
    char *sig_pk_path = pq_path_join(idir, "sig.pk");
    free(idir);
    if (!meta || !kem_pk_path || !sig_pk_path) {
        free(meta); free(kem_pk_path); free(sig_pk_path); return -1;
    }
    uint8_t *mraw = NULL; size_t mlen = 0;
    char *kem_alg = NULL, *sig_alg = NULL;
    if (pq_read_file(meta, &mraw, &mlen) != 0) {
        free(meta); free(kem_pk_path); free(sig_pk_path); return -1;
    }
    free(meta);
    char *line = (char *)mraw;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strncmp(line, "kem_alg=", 8) == 0) kem_alg = strdup(line + 8);
        else if (strncmp(line, "sig_alg=", 8) == 0) sig_alg = strdup(line + 8);
        if (!nl) break;
        line = nl + 1;
    }
    free(mraw);
    uint8_t *kem_pk = NULL, *sig_pk = NULL;
    size_t kem_pk_len = 0, sig_pk_len = 0;
    if (!kem_alg || !sig_alg ||
        pq_read_file(kem_pk_path, &kem_pk, &kem_pk_len) != 0 ||
        pq_read_file(sig_pk_path, &sig_pk, &sig_pk_len) != 0) {
        free(kem_alg); free(sig_alg); free(kem_pk); free(sig_pk);
        free(kem_pk_path); free(sig_pk_path);
        return -1;
    }
    free(kem_pk_path); free(sig_pk_path);
    int r = pq_write_public_key_file(out_path, name, NULL,
                                     kem_alg, kem_pk, kem_pk_len,
                                     sig_alg, sig_pk, sig_pk_len);
    free(kem_alg); free(sig_alg); free(kem_pk); free(sig_pk);
    return r;
}

int pq_identity_import_public(const char *path, const char *name, const char *comment) {
    char *n = NULL, *c = NULL, *kem_alg = NULL, *sig_alg = NULL;
    uint8_t *kem_pk = NULL, *sig_pk = NULL;
    size_t kem_pk_len = 0, sig_pk_len = 0;
    if (pq_read_public_key_file(path, &n, &c, &kem_alg, &kem_pk, &kem_pk_len,
                                &sig_alg, &sig_pk, &sig_pk_len) != 0)
        return -1;

    pq_keyring_t kr;
    if (pq_keyring_load(&kr) != 0) {
        free(n); free(c); free(kem_alg); free(sig_alg); free(kem_pk); free(sig_pk);
        return -1;
    }
    const char *use_name = name ? name : (n ? n : "imported");
    const char *use_comment = comment ? comment : c;
    int r = pq_keyring_add(&kr, use_name, use_comment,
                           kem_alg, kem_pk, kem_pk_len,
                           sig_alg, sig_pk, sig_pk_len);
    if (r == 0) r = pq_keyring_save(&kr);
    pq_keyring_free(&kr);
    free(n); free(c); free(kem_alg); free(sig_alg); free(kem_pk); free(sig_pk);
    return r;
}

/* Expose register helper for genkey */
int pq_identity_register(const char *name) {
    return identity_register(name);
}


int pq_identity_delete(const char *name) {
    char *kd = keys_dir();
    if (!kd) return -1;
    char *idir = pq_path_join(kd, name);
    if (!idir) { free(kd); return -1; }
    const char *files[] = {"meta", "kem.sk", "sig.sk", "kem.pk", "sig.pk", NULL};
    for (int i = 0; files[i]; i++) {
        char *fp = pq_path_join(idir, files[i]);
        if (fp) { remove(fp); free(fp); }
    }
#ifdef _WIN32
    _rmdir(idir);
#else
    rmdir(idir);
#endif
    free(idir);
    /* remove from identities list */
    char *list_path = pq_path_join(kd, "identities");
    free(kd);
    if (!list_path) return 0;
    uint8_t *raw = NULL; size_t len = 0;
    if (pq_read_file(list_path, &raw, &len) != 0) { free(list_path); return 0; }
    char *out = malloc(len + 1);
    size_t ou = 0;
    char *line = (char *)raw;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strcmp(line, name) != 0 && line[0]) {
            size_t L = strlen(line);
            memcpy(out + ou, line, L); ou += L; out[ou++] = '\n';
        }
        if (!nl) break;
        line = nl + 1;
    }
    out[ou] = 0;
    pq_write_file(list_path, (uint8_t *)out, ou, 0600);
    free(out); free(raw); free(list_path);
    /* clear default if matched */
    char *def = pq_config_get("default_identity");
    if (def && strcmp(def, name) == 0)
        pq_config_set("default_identity", "");
    free(def);
    return 0;
}

int pq_identity_names(char ***names, size_t *count) {
    *names = NULL; *count = 0;
    char *kd = keys_dir();
    if (!kd) return -1;
    char *list_path = pq_path_join(kd, "identities");
    free(kd);
    if (!list_path) return -1;
    uint8_t *raw = NULL; size_t len = 0;
    if (pq_read_file(list_path, &raw, &len) != 0) { free(list_path); return 0; }
    free(list_path);
    size_t cap = 8, n = 0;
    char **arr = calloc(cap, sizeof(char *));
    char *line = (char *)raw;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (line[0] && line[0] != '#') {
            if (n >= cap) {
                cap *= 2;
                arr = realloc(arr, cap * sizeof(char *));
            }
            arr[n++] = strdup(line);
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(raw);
    *names = arr;
    *count = n;
    return 0;
}
