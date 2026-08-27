#define _POSIX_C_SOURCE 200809L
#include "commands.h"
#include "crypto.h"
#include "keyring.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include "monocypher.h"

extern char *pq_config_get(const char *key);
extern int pq_config_set(const char *key, const char *value);

/* Shared UX helpers from commands.c - redeclare */
char *pq_get_passphrase(const char *prompt);
char *pq_get_passphrase_confirm(const char *prompt, const char *confirm_prompt);

static char *resolve_passphrase_local(const char *pass_opt, int need) {
    if (pass_opt && pass_opt[0]) return strdup(pass_opt);
    const char *env = getenv("PQCLI_PASSPHRASE");
    if (env && env[0]) return strdup(env);
    if (need) return pq_get_passphrase("Passphrase: ");
    return NULL;
}

static char *resolve_id_local(const char *explicit) {
    if (explicit && explicit[0]) return strdup(explicit);
    char *def = pq_config_get("default_identity");
    if (def && def[0]) return def;
    free(def);
    char **names = NULL; size_t n = 0;
    if (pq_identity_names(&names, &n) == 0 && n == 1) {
        char *r = names[0];
        for (size_t i = 1; i < n; i++) free(names[i]);
        free(names);
        return r;
    }
    for (size_t i = 0; i < n; i++) free(names[i]);
    free(names);
    return NULL;
}

/* ---- inspect ciphertext ---- */
int cmd_inspect(int argc, char **argv) {
    const char *path = argc >= 2 ? argv[1] : NULL;
    if (!path) { pq_error("usage: pqcli inspect <file.pqcl|.asc>"); return 1; }

    uint8_t *raw = NULL; size_t raw_len = 0;
    if (pq_read_file(path, &raw, &raw_len) != 0) {
        pq_error("cannot read %s", path); return 1;
    }
    if (raw_len > 20 && memcmp(raw, "-----BEGIN", 10) == 0) {
        uint8_t *bin = NULL; size_t bl = 0;
        if (pq_armor_decode((char *)raw, raw_len, &bin, &bl) != 0) {
            free(raw); pq_error("invalid armor"); return 1;
        }
        free(raw); raw = bin; raw_len = bl;
        printf("Encoding:     ASCII armor\n");
    } else {
        printf("Encoding:     binary\n");
    }

    if (raw_len < 8 || memcmp(raw, "PQCL", 4) != 0) {
        pq_error("not a pqcli ciphertext"); free(raw); return 1;
    }
    const uint8_t *p = raw + 4;
    const uint8_t *end = raw + raw_len;
    uint8_t ver = *p++, flags = *p++;
    printf("Format:       PQCL v%u\n", ver);
    printf("Signed:       %s\n", (flags & 1) ? "yes" : "no");

    if (ver != 3) {
        printf("(older format — limited inspect)\n");
        free(raw); return 0;
    }
    if (p + 2 > end) { free(raw); return 1; }
    uint16_t n_rcp = ((uint16_t)p[0] << 8) | p[1]; p += 2;
    printf("Recipients:   %u\n", n_rcp);

    for (uint16_t i = 0; i < n_rcp; i++) {
        if (p >= end) break;
        uint8_t fp_len = *p++;
        char fp[256] = {0};
        if (fp_len && p + fp_len <= end) {
            memcpy(fp, p, fp_len); p += fp_len;
        } else if (fp_len) break;
        if (p + 2 > end) break;
        uint16_t al = ((uint16_t)p[0] << 8) | p[1]; p += 2;
        char alg[128] = {0};
        if (al < sizeof(alg) && p + al <= end) {
            memcpy(alg, p, al); p += al;
        } else break;
        if (p + 4 > end) break;
        uint32_t ctlen = ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
        p += 4;
        if (p + ctlen + 24 + 16 + 32 > end) break;
        p += ctlen + 24 + 16 + 32; /* skip kem ct + cek wrap */
        printf("  [%u] alg=%s  fp=%s\n", i + 1, alg, fp[0] ? fp : "(none)");
    }
    printf("Size:         %zu bytes\n", raw_len);
    free(raw);
    return 0;
}

/* ---- identity info ---- */
int cmd_info(int argc, char **argv) {
    const char *name = argc >= 2 ? argv[1] : NULL;
    if (!name) {
        char *def = pq_config_get("default_identity");
        name = def;
        if (!name || !name[0]) {
            pq_error("usage: pqcli info <identity|contact>");
            free(def); return 1;
        }
    } else {
        name = argv[1];
    }

    /* try identity first via export public */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/pqinfo_%d.pqpub", (int)getpid());
    if (pq_identity_export_public(name, tmp) == 0) {
        char *nm=NULL,*cm=NULL,*ka=NULL,*sa=NULL;
        uint8_t *kpk=NULL,*spk=NULL; size_t klen=0,slen=0;
        pq_read_public_key_file(tmp, &nm, &cm, &ka, &kpk, &klen, &sa, &spk, &slen);
        remove(tmp);
        size_t cl = klen + slen;
        uint8_t *c = malloc(cl);
        memcpy(c, kpk, klen); memcpy(c+klen, spk, slen);
        char *fp = pq_fingerprint(c, cl);
        int prot = pq_identity_is_protected(name);
        char *def = pq_config_get("default_identity");
        printf("Type:         local identity\n");
        printf("Name:         %s%s\n", name,
               (def && strcmp(def, name)==0) ? " (default)" : "");
        printf("Fingerprint:  %s\n", fp ? fp : "-");
        printf("KEM:          %s  (pk %zu bytes)\n", ka, klen);
        printf("SIG:          %s  (pk %zu bytes)\n", sa, slen);
        printf("Protected:    %s\n", prot == 1 ? "yes (Argon2id)" : "no");
        free(c); free(fp); free(nm); free(cm); free(ka); free(sa);
        free(kpk); free(spk); free(def);
        return 0;
    }
    remove(tmp);

    pq_keyring_t kr;
    if (pq_keyring_load(&kr) == 0) {
        pq_keyring_entry_t *e = pq_keyring_find(&kr, name);
        if (!e) e = pq_keyring_find_by_fp(&kr, name);
        if (e) {
            printf("Type:         keyring contact\n");
            printf("Name:         %s\n", e->name);
            printf("Fingerprint:  %s\n", e->fingerprint ? e->fingerprint : "-");
            printf("Comment:      %s\n", e->comment ? e->comment : "");
            printf("KEM:          %s\n", e->kem_alg);
            printf("SIG:          %s\n", e->sig_alg);
            printf("Trusted:      %s\n", e->trusted ? "yes" : "no");
            pq_keyring_free(&kr);
            return 0;
        }
        pq_keyring_free(&kr);
    }
    pq_error("not found: %s", name);
    return 1;
}

int cmd_rm_key(int argc, char **argv) {
    const char *name = argc >= 2 ? argv[1] : NULL;
    int force = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) force = 1;
        else if (argv[i][0] != '-') name = argv[i];
    }
    if (!name) { pq_error("usage: pqcli rm-key <name> [--force]"); return 1; }
    if (!force) {
        printf("Delete local identity '%s'? This cannot be undone.\nType the name to confirm: ", name);
        fflush(stdout);
        char buf[256];
        if (!fgets(buf, sizeof(buf), stdin)) return 1;
        size_t n = strlen(buf);
        while (n && (buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n]=0;
        if (strcmp(buf, name) != 0) {
            pq_error("aborted"); return 1;
        }
    }
    if (pq_identity_delete(name) != 0) {
        pq_error("delete failed"); return 1;
    }
    pq_success("Deleted identity '%s'", name);
    return 0;
}

int cmd_passwd(int argc, char **argv) {
    const char *name = argc >= 2 ? argv[1] : NULL;
    if (!name) {
        name = NULL;
        char *id = resolve_id_local(NULL);
        if (!id) { pq_error("usage: pqcli passwd <identity>"); return 1; }
        /* use resolved - need mutable */
        static char buf[256];
        snprintf(buf, sizeof(buf), "%s", id);
        free(id);
        name = buf;
    }
    char *oldp = resolve_passphrase_local(NULL, 1);
    if (!oldp) return 1;
    pq_identity_t id;
    int lr = pq_identity_load(name, &id, oldp);
    pq_secure_free(oldp, strlen(oldp));
    if (lr != 0) {
        pq_error(lr == -2 ? "passphrase required" : "cannot load identity (wrong passphrase?)");
        return 1;
    }
    char *newp = pq_get_passphrase_confirm("New passphrase: ", "Confirm new passphrase: ");
    if (!newp) {
        /* allow empty via second prompt path - if user wants remove protection */
        pq_identity_free(&id); return 1;
    }
    if (pq_identity_save(&id, name, newp[0] ? newp : NULL) != 0) {
        pq_error("failed to re-save identity");
        pq_secure_free(newp, strlen(newp));
        pq_identity_free(&id); return 1;
    }
    pq_secure_free(newp, strlen(newp));
    pq_identity_free(&id);
    pq_success("Passphrase updated for '%s'", name);
    return 0;
}

int cmd_config(int argc, char **argv) {
    if (argc < 2) {
        char *def = pq_config_get("default_identity");
        printf("default_identity=%s\n", def ? def : "");
        free(def);
        return 0;
    }
    if (strcmp(argv[1], "get") == 0 && argc >= 3) {
        char *v = pq_config_get(argv[2]);
        printf("%s\n", v ? v : "");
        free(v);
        return 0;
    }
    if (strcmp(argv[1], "set") == 0 && argc >= 4) {
        if (pq_config_set(argv[2], argv[3]) != 0) {
            pq_error("failed to set"); return 1;
        }
        pq_success("%s=%s", argv[2], argv[3]);
        return 0;
    }
    /* config key=value */
    char *eq = strchr(argv[1], '=');
    if (eq) {
        *eq = 0;
        if (pq_config_set(argv[1], eq + 1) != 0) { pq_error("failed"); return 1; }
        pq_success("set %s", argv[1]);
        return 0;
    }
    printf("Usage: pqcli config [get KEY | set KEY VALUE | KEY=VALUE]\n");
    return 1;
}

int cmd_fingerprint(int argc, char **argv) {
    const char *target = argc >= 2 ? argv[1] : NULL;
    if (!target) {
        char *id = resolve_id_local(NULL);
        if (!id) { pq_error("usage: pqcli fingerprint <identity|contact|.pqpub>"); return 1; }
        target = id;
        int rc = cmd_info(2, (char *[]){ "info", (char *)target });
        /* print only fp via info is verbose - do dedicated */
        free(id);
        return rc;
    }
    if (pq_file_exists(target)) {
        char *nm=NULL,*cm=NULL,*ka=NULL,*sa=NULL;
        uint8_t *kpk=NULL,*spk=NULL; size_t klen=0,slen=0;
        if (pq_read_public_key_file(target, &nm, &cm, &ka, &kpk, &klen, &sa, &spk, &slen) != 0) {
            pq_error("not a public key file"); return 1;
        }
        size_t cl = klen + slen;
        uint8_t *c = malloc(cl);
        memcpy(c, kpk, klen); memcpy(c+klen, spk, slen);
        char *fp = pq_fingerprint(c, cl);
        printf("%s\n", fp ? fp : "");
        free(c); free(fp); free(nm); free(cm); free(ka); free(sa); free(kpk); free(spk);
        return 0;
    }
    /* identity or contact */
    char *args[] = { "info", (char *)target };
    return cmd_info(2, args);
}

int cmd_wipe(int argc, char **argv) {
    const char *path = argc >= 2 ? argv[1] : NULL;
    if (!path) { pq_error("usage: pqcli wipe <file>"); return 1; }
    FILE *f = fopen(path, "r+b");
    if (!f) { pq_error("cannot open %s", path); return 1; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return 1; }
    rewind(f);
    uint8_t buf[4096];
    long left = sz;
    while (left > 0) {
        size_t n = left > (long)sizeof(buf) ? sizeof(buf) : (size_t)left;
        if (pq_random_bytes(buf, n) != 0) { fclose(f); return 1; }
        if (fwrite(buf, 1, n, f) != n) { fclose(f); return 1; }
        left -= (long)n;
    }
    fflush(f);
    fclose(f);
    if (remove(path) != 0) {
        pq_error("overwritten but could not unlink"); return 1;
    }
    pq_success("Wiped %s (%ld bytes)", path, sz);
    return 0;
}

/* backup identity to armored encrypted blob */
int cmd_backup(int argc, char **argv) {
    const char *name = NULL;
    const char *out = NULL;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--out") == 0) && i + 1 < argc)
            out = argv[++i];
        else if (argv[i][0] != '-') name = argv[i];
    }
    if (!name) {
        char *id = resolve_id_local(NULL);
        if (!id) { pq_error("usage: pqcli backup <identity> [-o file]"); return 1; }
        name = id;
    }
    char *pass = resolve_passphrase_local(NULL, 1);
    if (!pass) return 1;
    pq_identity_t id;
    if (pq_identity_load(name, &id, pass) != 0) {
        pq_error("cannot load identity");
        pq_secure_free(pass, strlen(pass)); return 1;
    }
    /* pack: simple text format then protect */
    size_t cap = id.kem.secret_key_len + id.sig.secret_key_len +
                 id.kem.public_key_len + id.sig.public_key_len + 512;
    char *pack = malloc(cap);
    char *kem_sk_b64 = pq_bin_to_b64(id.kem.secret_key, id.kem.secret_key_len);
    char *sig_sk_b64 = pq_bin_to_b64(id.sig.secret_key, id.sig.secret_key_len);
    char *kem_pk_b64 = pq_bin_to_b64(id.kem.public_key, id.kem.public_key_len);
    char *sig_pk_b64 = pq_bin_to_b64(id.sig.public_key, id.sig.public_key_len);
    int n = snprintf(pack, cap,
        "PQCLI-BACKUP-1\nname=%s\nkem_alg=%s\nsig_alg=%s\n"
        "kem_sk=%s\nsig_sk=%s\nkem_pk=%s\nsig_pk=%s\n",
        name, id.kem_alg, id.sig_alg, kem_sk_b64, sig_sk_b64, kem_pk_b64, sig_pk_b64);
    free(kem_sk_b64); free(sig_sk_b64); free(kem_pk_b64); free(sig_pk_b64);

    uint8_t *blob = NULL; size_t blen = 0;
    if (pq_protect_secret((uint8_t *)pack, (size_t)n, pass, &blob, &blen) != 0) {
        pq_error("backup encrypt failed");
        pq_secure_free(pass, strlen(pass));
        pq_memzero(pack, (size_t)n); free(pack);
        pq_identity_free(&id); return 1;
    }
    pq_memzero(pack, (size_t)n); free(pack);
    pq_secure_free(pass, strlen(pass));
    pq_identity_free(&id);

    char *text = NULL;
    pq_armor_encode(blob, blen, &text);
    free(blob);
    char *auto_out = NULL;
    if (!out) {
        size_t L = strlen(name) + 16;
        auto_out = malloc(L);
        snprintf(auto_out, L, "%s.pqbackup", name);
        out = auto_out;
    }
    FILE *f = fopen(out, "w");
    if (!f) {
        pq_error("cannot write %s", out);
        free(text); free(auto_out); return 1;
    }
    /* retarget armor header */
    fprintf(f, "-----BEGIN PQ IDENTITY BACKUP-----\n");
    /* strip begin/end from text and rewrite */
    char *body = text;
    char *b = strstr(text, "-----\n");
    if (b) body = b + 6;
    char *e = strstr(body, "-----END");
    if (e) {
        fwrite(body, 1, (size_t)(e - body), f);
    } else {
        fputs(body, f);
    }
    fprintf(f, "-----END PQ IDENTITY BACKUP-----\n");
    fclose(f);
    free(text); free(auto_out);
    pq_success("Backup written to %s", out);
    return 0;
}

int cmd_restore(int argc, char **argv) {
    const char *path = NULL;
    const char *name_override = NULL;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-n") == 0) && i + 1 < argc) name_override = argv[++i];
        else if (argv[i][0] != '-') path = argv[i];
    }
    if (!path) { pq_error("usage: pqcli restore <file.pqbackup> [-n name]"); return 1; }

    uint8_t *raw = NULL; size_t raw_len = 0;
    if (pq_read_file(path, &raw, &raw_len) != 0) {
        pq_error("cannot read"); return 1;
    }
    /* normalize armor */
    char *data = (char *)raw;
    if (strstr(data, "BEGIN PQ IDENTITY BACKUP")) {
        /* convert to standard armor for decode helper */
        char *tmp = malloc(raw_len + 64);
        snprintf(tmp, raw_len + 64, "-----BEGIN PQ MESSAGE-----\n");
        char *b = strstr(data, "-----\n");
        if (b) b += 6;
        else b = data;
        char *e = strstr(b, "-----END");
        size_t body_len = e ? (size_t)(e - b) : strlen(b);
        memcpy(tmp + strlen(tmp), b, body_len);
        strcat(tmp, "-----END PQ MESSAGE-----\n");
        free(raw);
        uint8_t *bin = NULL; size_t bl = 0;
        if (pq_armor_decode(tmp, strlen(tmp), &bin, &bl) != 0) {
            free(tmp); pq_error("bad backup encoding"); return 1;
        }
        free(tmp);
        raw = bin; raw_len = bl;
    }

    char *pass = resolve_passphrase_local(NULL, 1);
    if (!pass) { free(raw); return 1; }
    uint8_t *plain = NULL; size_t plen = 0;
    if (pq_unprotect_secret(raw, raw_len, pass, &plain, &plen) != 0) {
        pq_error("wrong passphrase or corrupt backup");
        pq_secure_free(pass, strlen(pass)); free(raw); return 1;
    }
    pq_secure_free(pass, strlen(pass));
    free(raw);
    plain[plen < 1 ? 0 : plen] = 0; /* ensure NUL if space - careful */
    char *buf = malloc(plen + 1);
    memcpy(buf, plain, plen); buf[plen] = 0;
    pq_secure_free(plain, plen);

    char *name = NULL, *kem_alg = NULL, *sig_alg = NULL;
    char *kem_sk_b64 = NULL, *sig_sk_b64 = NULL, *kem_pk_b64 = NULL, *sig_pk_b64 = NULL;
    char *line = buf;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (strncmp(line, "name=", 5) == 0) name = strdup(line + 5);
        else if (strncmp(line, "kem_alg=", 8) == 0) kem_alg = strdup(line + 8);
        else if (strncmp(line, "sig_alg=", 8) == 0) sig_alg = strdup(line + 8);
        else if (strncmp(line, "kem_sk=", 7) == 0) kem_sk_b64 = strdup(line + 7);
        else if (strncmp(line, "sig_sk=", 7) == 0) sig_sk_b64 = strdup(line + 7);
        else if (strncmp(line, "kem_pk=", 7) == 0) kem_pk_b64 = strdup(line + 7);
        else if (strncmp(line, "sig_pk=", 7) == 0) sig_pk_b64 = strdup(line + 7);
        if (!nl) break;
        line = nl + 1;
    }
    pq_memzero(buf, plen); free(buf);

    if (name_override) { free(name); name = strdup(name_override); }
    if (!name || !kem_alg || !sig_alg || !kem_sk_b64 || !sig_sk_b64) {
        pq_error("incomplete backup"); return 1;
    }

    pq_identity_t id;
    memset(&id, 0, sizeof(id));
    id.kem_alg = kem_alg;
    id.sig_alg = sig_alg;
    id.kem.alg = strdup(kem_alg);
    id.sig.alg = strdup(sig_alg);
    pq_b64_to_bin(kem_sk_b64, &id.kem.secret_key, &id.kem.secret_key_len);
    pq_b64_to_bin(sig_sk_b64, &id.sig.secret_key, &id.sig.secret_key_len);
    pq_b64_to_bin(kem_pk_b64, &id.kem.public_key, &id.kem.public_key_len);
    pq_b64_to_bin(sig_pk_b64, &id.sig.public_key, &id.sig.public_key_len);
    free(kem_sk_b64); free(sig_sk_b64); free(kem_pk_b64); free(sig_pk_b64);

    char *newp = pq_get_passphrase_confirm("New passphrase for restored identity: ",
                                          "Confirm passphrase: ");
    if (pq_identity_save(&id, name, newp) != 0) {
        pq_error("save failed");
        if (newp) pq_secure_free(newp, strlen(newp));
        pq_identity_free(&id); free(name); return 1;
    }
    if (newp) pq_secure_free(newp, strlen(newp));
    pq_identity_register(name);
    pq_success("Restored identity '%s'", name);
    pq_identity_free(&id);
    free(name);
    return 0;
}

int cmd_reencrypt(int argc, char **argv) {
    const char *infile = NULL;
    const char *outfile = NULL;
    const char *recipients = NULL;
    int force = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) recipients = argv[++i];
        else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) outfile = argv[++i];
        else if (strcmp(argv[i], "--force") == 0) force = 1;
        else if (argv[i][0] != '-') {
            if (!infile) infile = argv[i];
            else if (!recipients) recipients = argv[i];
            else if (!outfile) outfile = argv[i];
        }
    }
    if (!infile || !recipients) {
        pq_error("usage: pqcli reencrypt <in.pqcl> -r recip1,recip2 [-o out.pqcl]");
        return 1;
    }

    char tmp_plain[] = "/tmp/pqcli_reenc_XXXXXX";
    int fd = mkstemp(tmp_plain);
    if (fd < 0) { pq_error("temp file"); return 1; }
    close(fd);

    char *dargv[] = { "decrypt", (char *)infile, tmp_plain, NULL };
    if (cmd_decrypt(3, dargv) != 0) {
        remove(tmp_plain); return 1;
    }

    char *oargv[16];
    int oa = 0;
    oargv[oa++] = "encrypt";
    oargv[oa++] = tmp_plain;
    char *rdup = strdup(recipients);
    char *save = NULL;
    for (char *tok = strtok_r(rdup, ",", &save); tok && oa < 12; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        oargv[oa++] = tok;
    }
    if (force) oargv[oa++] = "--force";
    oargv[oa] = NULL;

    int er = cmd_encrypt(oa, oargv);
    free(rdup);

    char *produced = pq_default_out_path(tmp_plain, ".pqcl");
    remove(tmp_plain);
    if (er != 0) { free(produced); return 1; }

    if (outfile && produced) {
        rename(produced, outfile);
        pq_success("Re-encrypted → %s", outfile);
    } else if (produced) {
        pq_success("Re-encrypted → %s", produced);
    }
    free(produced);
    return 0;
}
