#define _POSIX_C_SOURCE 200809L
#include "commands.h"
#include "crypto.h"
#include "keyring.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <oqs/oqs.h>
#include "monocypher.h"

static char *resolve_passphrase(const char *pass_opt, int protected_required) {
    if (pass_opt && pass_opt[0]) return strdup(pass_opt);
    const char *env = getenv("PQCLI_PASSPHRASE");
    if (env && env[0]) return strdup(env);
    if (protected_required)
        return pq_get_passphrase("Passphrase: ");
    return NULL;
}


/* ---- UX helpers: less to think about ---- */

static char *first_identity_name(void) {
    char *cfg = pq_get_config_dir();
    if (!cfg) return NULL;
    char *kd = pq_path_join(cfg, PQCLI_KEYS_DIR);
    free(cfg);
    if (!kd) return NULL;
    char *list_path = pq_path_join(kd, "identities");
    free(kd);
    if (!list_path) return NULL;
    uint8_t *raw = NULL; size_t len = 0;
    if (pq_read_file(list_path, &raw, &len) != 0) { free(list_path); return NULL; }
    free(list_path);
    char *line = (char *)raw;
    char *first = NULL;
    int count = 0;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (line[0] && line[0] != '#') {
            count++;
            if (!first) first = strdup(line);
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(raw);
    if (count != 1) { free(first); return NULL; } /* only auto-pick if exactly one */
    return first;
}

static char *resolve_identity(const char *explicit) {
    if (explicit && explicit[0]) return strdup(explicit);
    char *def = pq_config_get("default_identity");
    if (def && def[0]) return def;
    free(def);
    return first_identity_name();
}

static int ensure_default_identity(const char *name) {
    char *cur = pq_config_get("default_identity");
    if (cur && cur[0]) { free(cur); return 0; }
    free(cur);
    return pq_config_set("default_identity", name);
}



void pq_profile_algs(const char *profile, const char **kem, const char **sig) {
    if (!profile || strcmp(profile, "nist") == 0) {
        *kem = "ML-KEM-768"; *sig = "ML-DSA-65";
    } else if (strcmp(profile, "small") == 0) {
        *kem = "ML-KEM-512"; *sig = "ML-DSA-44";
    } else if (strcmp(profile, "paranoid") == 0) {
        *kem = "ML-KEM-1024"; *sig = "ML-DSA-87";
    } else {
        *kem = PQCLI_DEFAULT_KEM; *sig = PQCLI_DEFAULT_SIG;
    }
}

int cmd_help(int argc, char **argv) {
    (void)argc; (void)argv;
    printf(
"pqcli — Post-Quantum CLI (liboqs + Monocypher)\n"
"\n"
"Getting started:\n"
"  pqcli genkey alice              # create identity (passphrase prompted)\n"
"  pqcli export alice              # -> alice.pqpub\n"
"  pqcli import bob.pqpub          # add contact\n"
"  pqcli trust bob                 # after checking fingerprint\n"
"  pqcli encrypt secret.txt bob    # -> secret.txt.pqcl\n"
"  pqcli decrypt secret.txt.pqcl   # uses your default identity\n"
"\n"
"Identity:   genkey | list-keys | export | import | use <name>\n"
"Keyring:    keyring list|add|remove|trust|untrust|verify\n"
"            (shortcuts: trust, untrust, contacts)\n"
"Crypto:     encrypt | decrypt | sign | verify\n"
"Misc:       doctor | list-algs | version | help\n"
"\n"
"Also: inspect | reencrypt | backup | restore | passwd | rm-key | info\n"
"      fingerprint | wipe | config | use\n"
"\n"
"Smart defaults: inferred -o, default identity, FILE.sig auto-find\n"
"Profiles: nist | small | paranoid\n"
"Trust: blocked unless trusted or --force; import --trust available\n"
"Defaults: KEM=%s  SIG=%s\n",
        PQCLI_DEFAULT_KEM, PQCLI_DEFAULT_SIG);
    return 0;
}

int cmd_version(int argc, char **argv) {
    (void)argc; (void)argv;
    printf("pqcli %s\n", PQCLI_VERSION);
    return 0;
}

int cmd_list_algs(int argc, char **argv) {
    (void)argc; (void)argv;
    pq_list_kems();
    printf("\n");
    pq_list_sigs();
    return 0;
}

int cmd_genkey(int argc, char **argv) {
    const char *name = NULL;
    const char *kem_alg = PQCLI_DEFAULT_KEM;
    const char *sig_alg = PQCLI_DEFAULT_SIG;
    const char *profile = NULL;
    int want_pass = 1;
    const char *pass_opt = NULL;
    int kem_set = 0, sig_set = 0;

    static struct option long_opts[] = {
        {"name",          required_argument, 0, 'n'},
        {"kem",           required_argument, 0, 'k'},
        {"sig",           required_argument, 0, 's'},
        {"profile",       required_argument, 0, 'F'},
        {"passphrase",    optional_argument, 0, 'p'},
        {"no-passphrase", no_argument,       0, 'P'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "n:k:s:F:p::Ph", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'n': name = optarg; break;
        case 'k': kem_alg = optarg; kem_set = 1; break;
        case 's': sig_alg = optarg; sig_set = 1; break;
        case 'F': profile = optarg; break;
        case 'p': want_pass = 1; pass_opt = optarg; break;
        case 'P':
            if (!getenv("PQCLI_ALLOW_PLAINTEXT_KEYS")) {
                pq_error("--no-passphrase disabled (secrets must be encrypted at rest)\n"
                         "  Set PQCLI_ALLOW_PLAINTEXT_KEYS=1 to override (not recommended)");
                return 1;
            }
            want_pass = 0;
            break;
        case 'h':
            printf("Usage: pqcli genkey NAME [--profile nist|small|paranoid] [--kem ALG] [--sig ALG]\n");
            return 0;
        default: return 1;
        }
    }
    if (profile) {
        const char *pk = NULL, *ps = NULL;
        pq_profile_algs(profile, &pk, &ps);
        if (!kem_set) kem_alg = pk;
        if (!sig_set) sig_alg = ps;
    }
    if (!name && optind < argc) name = argv[optind++];
    if (!name) { pq_error("identity name required (e.g. pqcli genkey alice)"); return 1; }

    char *pass = NULL;
    if (want_pass) {
        if (pass_opt && pass_opt[0]) pass = strdup(pass_opt);
        else if (getenv("PQCLI_PASSPHRASE")) pass = strdup(getenv("PQCLI_PASSPHRASE"));
        else pass = pq_get_passphrase_confirm("New passphrase: ", "Confirm passphrase: ");
        if (!pass) { pq_error("passphrase required — secret keys are encrypted at rest"); return 1; }
    }

    pq_identity_t id;
    memset(&id, 0, sizeof(id));
    id.kem_alg = strdup(kem_alg);
    id.sig_alg = strdup(sig_alg);

    pq_success("Generating KEM keypair (%s)...", kem_alg);
    if (pq_generate_keypair(kem_alg, 0, &id.kem) != 0) {
        pq_error("KEM key generation failed");
        pq_identity_free(&id);
        if (pass) pq_secure_free(pass, strlen(pass));
        return 1;
    }
    pq_success("Generating signature keypair (%s)...", sig_alg);
    if (pq_generate_keypair(sig_alg, 1, &id.sig) != 0) {
        pq_error("Signature key generation failed");
        pq_identity_free(&id);
        if (pass) pq_secure_free(pass, strlen(pass));
        return 1;
    }

    if (pass) pq_info("Protecting secret keys with Argon2id...");
    if (pq_identity_save(&id, name, pass) != 0) {
        pq_error("Failed to save identity");
        pq_identity_free(&id);
        if (pass) pq_secure_free(pass, strlen(pass));
        return 1;
    }
    pq_identity_register(name);
    ensure_default_identity(name);
    if (pass) pq_secure_free(pass, strlen(pass));

    size_t cl = id.kem.public_key_len + id.sig.public_key_len;
    uint8_t *comb = malloc(cl);
    memcpy(comb, id.kem.public_key, id.kem.public_key_len);
    memcpy(comb + id.kem.public_key_len, id.sig.public_key, id.sig.public_key_len);
    char *fp = pq_fingerprint(comb, cl);
    free(comb);

    if (want_pass)
        pq_success("Identity '%s' created (secret keys encrypted at rest)", name);
    else
        pq_success("Identity '%s' created (WARNING: secret keys stored in plaintext)", name);
    printf("  Fingerprint: %s\n", fp ? fp : "-");
    printf("  KEM: %s  SIG: %s\n", kem_alg, sig_alg);
    {
        char *cfg = pq_get_config_dir();
        if (cfg) {
            printf("  Stored in: %s/keys/%s/\n", cfg, name);
            free(cfg);
        }
    }
    free(fp);
    pq_identity_free(&id);
    return 0;
}

int cmd_list_keys(int argc, char **argv) {
    (void)argc; (void)argv;
    return pq_identity_list() == 0 ? 0 : 1;
}

int cmd_export(int argc, char **argv) {
    const char *name = NULL, *out = NULL;
    static struct option long_opts[] = {
        {"name", required_argument, 0, 'n'},
        {"out",  required_argument, 0, 'o'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "n:o:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'n': name = optarg; break;
        case 'o': out = optarg; break;
        case 'h': printf("Usage: pqcli export -n <identity> -o <file.pqpub>\n"); return 0;
        default: return 1;
        }
    }
    if (!name && optind < argc) name = argv[optind++];
    if (!out && optind < argc) out = argv[optind++];
    char *auto_out = NULL;
    if (!out && name) {
        size_t n = strlen(name) + 8;
        auto_out = malloc(n);
        snprintf(auto_out, n, "%s.pqpub", name);
        out = auto_out;
    }
    if (!name || !out) { pq_error("usage: pqcli export <name> [outfile.pqpub]"); free(auto_out); return 1; }
    if (pq_identity_export_public(name, out) != 0) {
        pq_error("export failed"); free(auto_out); return 1;
    }
    pq_success("Exported public key to %s", out);
    free(auto_out);
    return 0;
}

int cmd_import(int argc, char **argv) {
    const char *path = NULL, *name = NULL, *comment = NULL;
    int do_trust = 0;
    static struct option long_opts[] = {
        {"file", required_argument, 0, 'f'},
        {"name", required_argument, 0, 'n'},
        {"comment", required_argument, 0, 'c'},
        {"trust", no_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "f:n:c:th", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'f': path = optarg; break;
        case 'n': name = optarg; break;
        case 'c': comment = optarg; break;
        case 't': do_trust = 1; break;
        case 'h': printf("Usage: pqcli import <file.pqpub> [-n name] [--trust]\n"); return 0;
        default: return 1;
        }
    }
    if (!path && optind < argc) path = argv[optind++];
    if (!path) { pq_error("usage: pqcli import <file.pqpub>"); return 1; }
    if (pq_identity_import_public(path, name, comment) != 0) {
        pq_error("import failed"); return 1;
    }
    pq_success("Imported into keyring");
    if (do_trust) {
        /* resolve name from file if needed */
        char *nm=NULL,*cm=NULL,*ka=NULL,*sa=NULL;
        uint8_t *kpk=NULL,*spk=NULL; size_t kl=0,sl=0;
        if (pq_read_public_key_file(path, &nm, &cm, &ka, &kpk, &kl, &sa, &spk, &sl) == 0) {
            const char *tn = name ? name : nm;
            if (tn) {
                pq_keyring_t kr;
                if (pq_keyring_load(&kr) == 0) {
                    pq_keyring_set_trusted(&kr, tn, true);
                    pq_keyring_save(&kr);
                    pq_keyring_free(&kr);
                    pq_success("Marked '%s' trusted", tn);
                }
            }
            free(nm); free(cm); free(ka); free(sa); free(kpk); free(spk);
        }
    }
    return 0;
}

int cmd_keyring_list(int argc, char **argv) {
    (void)argc; (void)argv;
    pq_keyring_t kr;
    if (pq_keyring_load(&kr) != 0) { pq_error("keyring load failed"); return 1; }
    pq_keyring_list(&kr);
    pq_keyring_free(&kr);
    return 0;
}

int cmd_keyring_add(int argc, char **argv) {
    return cmd_import(argc, argv);
}

int cmd_keyring_remove(int argc, char **argv) {
    const char *name = argc >= 2 ? argv[1] : NULL;
    if (!name) { pq_error("usage: pqcli keyring remove <name>"); return 1; }
    pq_keyring_t kr;
    if (pq_keyring_load(&kr) != 0) return 1;
    if (pq_keyring_remove(&kr, name) != 0) {
        pq_error("not found: %s", name);
        pq_keyring_free(&kr); return 1;
    }
    pq_keyring_save(&kr);
    pq_keyring_free(&kr);
    pq_success("Removed %s", name);
    return 0;
}

int cmd_keyring_trust(int argc, char **argv) {
    const char *name = argc >= 2 ? argv[1] : NULL;
    int trust = 1;
    if (argc >= 1 && argv[0] && strstr(argv[0], "untrust")) trust = 0;
    if (!name) { pq_error("usage: pqcli keyring trust|untrust <name>"); return 1; }
    pq_keyring_t kr;
    if (pq_keyring_load(&kr) != 0) return 1;
    if (pq_keyring_set_trusted(&kr, name, trust != 0) != 0) {
        pq_error("not found: %s", name);
        pq_keyring_free(&kr); return 1;
    }
    pq_keyring_save(&kr);
    pq_keyring_free(&kr);
    pq_success("%s is now %strusted", name, trust ? "" : "un");
    return 0;
}

int cmd_keyring_verify(int argc, char **argv) {
    const char *name = argc >= 2 ? argv[1] : NULL;
    if (!name) { pq_error("usage: pqcli keyring verify <name>"); return 1; }
    pq_keyring_t kr;
    if (pq_keyring_load(&kr) != 0) return 1;
    pq_keyring_entry_t *e = pq_keyring_find(&kr, name);
    if (!e) {
        pq_error("not found: %s", name);
        pq_keyring_free(&kr); return 1;
    }
    printf("Name:         %s\n", e->name);
    printf("Fingerprint:  %s\n", e->fingerprint ? e->fingerprint : "-");
    printf("Trusted:      %s\n", e->trusted ? "yes" : "no");
    printf("KEM:          %s\n", e->kem_alg);
    printf("SIG:          %s\n", e->sig_alg);
    printf("\nVerify fingerprint out-of-band, then: pqcli keyring trust %s\n", name);
    pq_keyring_free(&kr);
    return 0;
}

/* Parse comma-separated recipients into pq_recipient_t list */
static int load_recipients(const char *spec, pq_recipient_t **out, size_t *nout,
                           pq_keyring_t *kr_out, int allow_untrusted) {
    pq_keyring_t kr;
    if (pq_keyring_load(&kr) != 0) memset(&kr, 0, sizeof(kr));
    *kr_out = kr;

    char *dup = strdup(spec);
    if (!dup) return -1;

    size_t cap = 4, n = 0;
    pq_recipient_t *list = calloc(cap, sizeof(pq_recipient_t));
    if (!list) { free(dup); return -1; }

    char *save = NULL;
    for (char *tok = strtok_r(dup, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok);
        while (end > tok && end[-1] == ' ') *--end = 0;
        if (!*tok) continue;

        if (n >= cap) {
            cap *= 2;
            pq_recipient_t *nl = realloc(list, cap * sizeof(*nl));
            if (!nl) { free(dup); free(list); return -1; }
            list = nl;
        }
        memset(&list[n], 0, sizeof(list[n]));

        if (pq_file_exists(tok)) {
            char *nm = NULL, *cm = NULL, *ka = NULL, *sa = NULL;
            uint8_t *kpk = NULL, *spk = NULL;
            size_t kpk_len = 0, spk_len = 0;
            if (pq_read_public_key_file(tok, &nm, &cm, &ka, &kpk, &kpk_len, &sa, &spk, &spk_len) != 0) {
                pq_error("cannot read %s", tok);
                free(dup); free(list); return -1;
            }
            list[n].kem_alg = ka;
            list[n].kem_pk = kpk;
            list[n].kem_pk_len = kpk_len;
            size_t cl = kpk_len + spk_len;
            uint8_t *c = malloc(cl);
            memcpy(c, kpk, kpk_len);
            memcpy(c + kpk_len, spk, spk_len);
            list[n].fingerprint = pq_fingerprint(c, cl);
            free(c); free(nm); free(cm); free(sa); free(spk);
        } else {
            pq_keyring_entry_t *e = pq_keyring_find(&kr, tok);
            if (!e) {
                pq_error("recipient '%s' not in keyring and not a file", tok);
                free(dup); free(list); return -1;
            }
            if (!e->trusted && !allow_untrusted) {
                pq_error("'%s' is not trusted — run: pqcli keyring trust %s  (or --force)", tok, tok);
                free(dup);
                for (size_t j = 0; j < n; j++) {
                    free(list[j].kem_alg); free(list[j].kem_pk); free(list[j].fingerprint);
                }
                free(list);
                return -1;
            } else if (!e->trusted) {
                pq_info("warning: '%s' is not marked trusted (--force)", tok);
            }
            list[n].kem_alg = strdup(e->kem_alg);
            list[n].kem_pk = malloc(e->kem_pk_len);
            memcpy(list[n].kem_pk, e->kem_pk, e->kem_pk_len);
            list[n].kem_pk_len = e->kem_pk_len;
            list[n].fingerprint = e->fingerprint ? strdup(e->fingerprint) : NULL;
        }
        n++;
    }
    free(dup);
    *out = list;
    *nout = n;
    return n > 0 ? 0 : -1;
}

static void free_recipients(pq_recipient_t *list, size_t n) {
    for (size_t i = 0; i < n; i++) {
        free(list[i].kem_alg);
        free(list[i].kem_pk);
        free(list[i].fingerprint);
    }
    free(list);
}

int cmd_encrypt(int argc, char **argv) {
    const char *recipients_spec = NULL;
    const char *identity = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;
    const char *pass_opt = NULL;
    int armor = 0;
    int force = 0;

    static struct option long_opts[] = {
        {"recipient",  required_argument, 0, 'r'},
        {"identity",   required_argument, 0, 'i'},
        {"in",         required_argument, 0, 'f'},
        {"out",        required_argument, 0, 'o'},
        {"armor",      no_argument,       0, 'a'},
        {"force",      no_argument,       0, 'F'},
        {"passphrase", optional_argument, 0, 'p'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "r:i:f:o:aFp::h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'r': recipients_spec = optarg; break;
        case 'i': identity = optarg; break;
        case 'f': infile = optarg; break;
        case 'o': outfile = optarg; break;
        case 'a': armor = 1; break;
        case 'F': force = 1; break;
        case 'p': pass_opt = optarg ? optarg : ""; break;
        case 'h':
            printf("Usage:\n"
                   "  pqcli encrypt <file> <recipient> [recipient2...] [--armor] [-i identity]\n"
                   "  pqcli encrypt -f <file> -r r1,r2 -o <out> [-i id] [--force]\n");
            return 0;
        default: return 1;
        }
    }

    /* Positional: encrypt FILE recip1 recip2... */
    if (!infile && optind < argc) infile = argv[optind++];
    char *rcp_owned = NULL;
    if (!recipients_spec && optind < argc) {
        size_t cap = 256, used = 0;
        char *buf = malloc(cap);
        buf[0] = 0;
        while (optind < argc) {
            const char *tok = argv[optind++];
            size_t need = strlen(tok) + 2;
            if (used + need > cap) {
                cap = (used + need) * 2;
                buf = realloc(buf, cap);
            }
            if (used) buf[used++] = ',';
            memcpy(buf + used, tok, strlen(tok) + 1);
            used += strlen(tok);
        }
        if (used) { recipients_spec = buf; rcp_owned = buf; }
        else free(buf);
    }

    if (!infile || !recipients_spec) {
        pq_error("usage: pqcli encrypt <file> <recipient> [more...]");
        return 1;
    }

    char *auto_out = NULL;
    if (!outfile) {
        auto_out = pq_default_out_path(infile, armor ? ".asc" : ".pqcl");
        outfile = auto_out;
    }

    char *id_resolved = resolve_identity(identity);
    /* signing optional: only if identity resolved */
    const char *use_id = id_resolved;

    pq_recipient_t *rcps = NULL;
    size_t n_rcp = 0;
    pq_keyring_t kr;
    memset(&kr, 0, sizeof(kr));
    if (load_recipients(recipients_spec, &rcps, &n_rcp, &kr, force) != 0) {
        if (recipients_spec && recipients_spec != argv[0]) {
            /* may be our allocated buffer */
        }
        free(auto_out); free(id_resolved);
        pq_keyring_free(&kr);
        return 1;
    }

    pq_identity_t id;
    memset(&id, 0, sizeof(id));
    const uint8_t *sig_sk = NULL;
    size_t sig_sk_len = 0;
    const char *sig_alg = NULL;
    char *sender_fp = NULL;
    char *pass = NULL;

    if (use_id) {
        int prot = pq_identity_is_protected(use_id);
        pass = resolve_passphrase(pass_opt, prot == 1);
        int lr = pq_identity_load(use_id, &id, pass);
        if (pass) pq_secure_free(pass, strlen(pass));
        if (lr == -2) {
            pq_error("passphrase required for identity '%s'", use_id);
            free_recipients(rcps, n_rcp); free(auto_out); free(id_resolved);
            pq_keyring_free(&kr); return 1;
        }
        if (lr != 0) {
            pq_info("note: could not load identity '%s' — encrypting without signature", use_id);
        } else {
            sig_sk = id.sig.secret_key;
            sig_sk_len = id.sig.secret_key_len;
            sig_alg = id.sig_alg;
            size_t cl = id.kem.public_key_len + id.sig.public_key_len;
            uint8_t *c = malloc(cl);
            memcpy(c, id.kem.public_key, id.kem.public_key_len);
            memcpy(c + id.kem.public_key_len, id.sig.public_key, id.sig.public_key_len);
            sender_fp = pq_fingerprint(c, cl);
            free(c);
        }
    }

    if (pq_encrypt_file(infile, outfile, rcps, n_rcp,
                        sig_sk, sig_sk_len, sig_alg, sender_fp, armor != 0) != 0) {
        pq_error("encryption failed");
        free_recipients(rcps, n_rcp);
        free(sender_fp); free(auto_out); free(id_resolved); free(rcp_owned);
        pq_identity_free(&id); pq_keyring_free(&kr);
        return 1;
    }

    pq_success("Encrypted for %zu recipient(s) → %s%s%s",
               n_rcp, outfile, armor ? " (armored)" : "",
               sig_sk ? " [signed]" : "");
    free_recipients(rcps, n_rcp);
    free(sender_fp); free(auto_out); free(id_resolved); free(rcp_owned);
    pq_identity_free(&id);
    pq_keyring_free(&kr);
    return 0;
}

int cmd_decrypt(int argc, char **argv) {
    const char *identity = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;
    const char *sender = NULL;
    const char *pass_opt = NULL;

    static struct option long_opts[] = {
        {"identity",   required_argument, 0, 'i'},
        {"in",         required_argument, 0, 'f'},
        {"out",        required_argument, 0, 'o'},
        {"sender",     required_argument, 0, 's'},
        {"passphrase", optional_argument, 0, 'p'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:f:o:s:p::h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': identity = optarg; break;
        case 'f': infile = optarg; break;
        case 'o': outfile = optarg; break;
        case 's': sender = optarg; break;
        case 'p': pass_opt = optarg ? optarg : ""; break;
        case 'h':
            printf("Usage: pqcli decrypt <file.pqcl> [outfile] [-i identity] [-s sender]\n");
            return 0;
        default: return 1;
        }
    }
    if (!infile && optind < argc) infile = argv[optind++];
    if (!outfile && optind < argc) outfile = argv[optind++];

    if (!infile) { pq_error("usage: pqcli decrypt <ciphertext> [outfile]"); return 1; }

    char *auto_out = NULL;
    if (!outfile) {
        auto_out = pq_default_out_path(infile, "");
        /* if stripping .pqcl/.asc left same name, append .out */
        if (auto_out && strcmp(auto_out, infile) == 0) {
            free(auto_out);
            auto_out = pq_default_out_path(infile, ".out");
        } else if (auto_out && auto_out[0] && !strchr(auto_out, '.')) {
            /* fine */
        }
        outfile = auto_out;
    }

    char *id_resolved = resolve_identity(identity);
    if (!id_resolved) {
        pq_error("no identity — create one with: pqcli genkey <name>");
        free(auto_out); return 1;
    }

    int prot = pq_identity_is_protected(id_resolved);
    char *pass = resolve_passphrase(pass_opt, prot == 1);
    pq_identity_t id;
    int lr = pq_identity_load(id_resolved, &id, pass);
    if (pass) pq_secure_free(pass, strlen(pass));
    if (lr == -2) {
        pq_error("passphrase required for '%s'", id_resolved);
        free(id_resolved); free(auto_out); return 1;
    }
    if (lr != 0) {
        pq_error("cannot load identity '%s'", id_resolved);
        free(id_resolved); free(auto_out); return 1;
    }

    const uint8_t *sender_pk = NULL;
    size_t sender_pk_len = 0;
    const char *sender_sig_alg = NULL;
    pq_keyring_t kr;
    memset(&kr, 0, sizeof(kr));
    int kr_loaded = 0;
    if (sender) {
        if (pq_keyring_load(&kr) == 0) {
            kr_loaded = 1;
            pq_keyring_entry_t *e = pq_keyring_find(&kr, sender);
            if (e) {
                sender_pk = e->sig_pk;
                sender_pk_len = e->sig_pk_len;
                sender_sig_alg = e->sig_alg;
            } else {
                pq_info("note: sender '%s' not in keyring — signature not checked", sender);
            }
        }
    }

    bool sig_ok = false;
    char *sender_fp = NULL;
    if (pq_decrypt_file(infile, outfile,
                        id.kem.secret_key, id.kem.secret_key_len, id.kem_alg,
                        sender_pk, sender_pk_len, sender_sig_alg,
                        &sig_ok, &sender_fp) != 0) {
        pq_error("decryption failed (wrong identity, passphrase, or file?)");
        free(sender_fp); free(id_resolved); free(auto_out);
        if (kr_loaded) pq_keyring_free(&kr);
        pq_identity_free(&id);
        return 1;
    }

    pq_success("Decrypted → %s", outfile);
    if (sender_fp) {
        printf("  Sender fingerprint: %s\n", sender_fp);
        if (kr_loaded) {
            pq_keyring_entry_t *e = pq_keyring_find_by_fp(&kr, sender_fp);
            if (e) printf("  Matched contact: %s (trusted=%s)\n",
                          e->name, e->trusted ? "yes" : "no");
        }
    }
    if (sender_pk)
        printf("  Signature: %s\n", sig_ok ? "OK" : "FAILED");

    free(sender_fp); free(id_resolved); free(auto_out);
    if (kr_loaded) pq_keyring_free(&kr);
    pq_identity_free(&id);
    return 0;
}

int cmd_use(int argc, char **argv) {
    if (argc < 2) {
        char *cur = pq_config_get("default_identity");
        if (cur && cur[0]) {
            printf("Default identity: %s\n", cur);
            free(cur);
        } else {
            printf("No default identity set. Try: pqcli use <name>\n");
        }
        return 0;
    }
    const char *name = argv[1];
    /* check exists */
    char *cfg = pq_get_config_dir();
    if (!cfg) return 1;
    char *kd = pq_path_join(cfg, PQCLI_KEYS_DIR);
    free(cfg);
    char *idir = pq_path_join(kd, name);
    free(kd);
    if (!idir || !pq_file_exists(idir)) {
        pq_error("identity '%s' not found — pqcli list-keys", name);
        free(idir); return 1;
    }
    free(idir);
    if (pq_config_set("default_identity", name) != 0) {
        pq_error("could not write config"); return 1;
    }
    pq_success("Default identity set to '%s'", name);
    return 0;
}

int cmd_doctor(int argc, char **argv) {
    (void)argc; (void)argv;
    int issues = 0;
    printf("pqcli doctor %s\n\n", PQCLI_VERSION);

    /* Config dir */
    char *cfg = pq_get_config_dir();
    if (!cfg) {
        printf("[!] cannot resolve home/config dir\n");
        issues++;
    } else {
        printf("[+] config dir: %s\n", cfg);
        if (!pq_file_exists(cfg))
            printf("    (not created yet — will appear after genkey)\n");
        free(cfg);
    }

    /* RNG */
    uint8_t rb[32];
    if (pq_random_bytes(rb, sizeof(rb)) != 0) {
        printf("[!] OS random source failed\n");
        issues++;
    } else {
        printf("[+] OS CSPRNG OK\n");
    }

    /* liboqs algs */
    printf("[+] default KEM: %s\n", PQCLI_DEFAULT_KEM);
    printf("[+] default SIG: %s\n", PQCLI_DEFAULT_SIG);
    /* probe defaults */
    {
        OQS_KEM *k = OQS_KEM_new(PQCLI_DEFAULT_KEM);
        if (!k) { printf("[!] %s not enabled in liboqs\n", PQCLI_DEFAULT_KEM); issues++; }
        else { printf("[+] %s available (pk=%zu sk=%zu)\n", PQCLI_DEFAULT_KEM,
                      k->length_public_key, k->length_secret_key); OQS_KEM_free(k); }
        OQS_SIG *s = OQS_SIG_new(PQCLI_DEFAULT_SIG);
        if (!s) { printf("[!] %s not enabled in liboqs\n", PQCLI_DEFAULT_SIG); issues++; }
        else { printf("[+] %s available (pk=%zu sk=%zu)\n", PQCLI_DEFAULT_SIG,
                      s->length_public_key, s->length_secret_key); OQS_SIG_free(s); }
    }

    /* Monocypher self-check: encrypt/decrypt roundtrip */
    {
        uint8_t key[32], nonce[24], mac[16], pt[16], ct[16], out[16];
        for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
        for (int i = 0; i < 24; i++) nonce[i] = (uint8_t)(i + 1);
        for (int i = 0; i < 16; i++) pt[i] = (uint8_t)('A' + i);
        crypto_aead_lock(ct, mac, key, nonce, NULL, 0, pt, 16);
        if (crypto_aead_unlock(out, mac, key, nonce, NULL, 0, ct, 16) != 0 ||
            memcmp(pt, out, 16) != 0) {
            printf("[!] Monocypher AEAD roundtrip FAILED\n");
            issues++;
        } else {
            printf("[+] Monocypher XChaCha20-Poly1305 OK\n");
        }
        crypto_wipe(key, sizeof(key));
    }

    /* Identities / keyring summary */
    pq_keyring_t kr;
    if (pq_keyring_load(&kr) == 0) {
        printf("[+] keyring contacts: %zu\n", kr.count);
        size_t trusted = 0;
        for (size_t i = 0; i < kr.count; i++)
            if (kr.entries[i].trusted) trusted++;
        printf("    trusted: %zu\n", trusted);
        pq_keyring_free(&kr);
    }

    
    /* Unprotected secret keys */
    {
        char **names = NULL; size_t n = 0;
        if (pq_identity_names(&names, &n) == 0) {
            for (size_t i = 0; i < n; i++) {
                if (pq_identity_is_protected(names[i]) == 0) {
                    printf("[!] identity '%s' has plaintext secret keys on disk\n", names[i]);
                    printf("    Fix: pqcli passwd %s\n", names[i]);
                    issues++;
                }
                free(names[i]);
            }
            free(names);
        }
    }

printf("\n");
    if (issues == 0)
        pq_success("all checks passed");
    else
        pq_error("%d issue(s) found", issues);
    return issues ? 1 : 0;
}

int cmd_sign(int argc, char **argv) {
    const char *identity = NULL;
    const char *infile = NULL;
    const char *outfile = NULL;
    const char *pass_opt = NULL;

    static struct option long_opts[] = {
        {"identity",   required_argument, 0, 'i'},
        {"in",         required_argument, 0, 'f'},
        {"out",        required_argument, 0, 'o'},
        {"passphrase", optional_argument, 0, 'p'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "i:f:o:p::h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': identity = optarg; break;
        case 'f': infile = optarg; break;
        case 'o': outfile = optarg; break;
        case 'p': pass_opt = optarg ? optarg : ""; break;
        case 'h':
            printf("Usage: pqcli sign <file> [-i identity] [-o file.sig]\n");
            return 0;
        default: return 1;
        }
    }
    if (!infile && optind < argc) infile = argv[optind++];
    if (!outfile && optind < argc) outfile = argv[optind++];
    if (!infile) { pq_error("usage: pqcli sign <file>"); return 1; }

    char *sigpath = outfile ? strdup(outfile) : pq_default_out_path(infile, ".sig");
    char *id_resolved = resolve_identity(identity);
    if (!id_resolved) {
        pq_error("no identity — pqcli genkey <name>  or  pqcli use <name>");
        free(sigpath); return 1;
    }

    int prot = pq_identity_is_protected(id_resolved);
    char *pass = resolve_passphrase(pass_opt, prot == 1);
    pq_identity_t id;
    int lr = pq_identity_load(id_resolved, &id, pass);
    if (pass) pq_secure_free(pass, strlen(pass));
    if (lr != 0) {
        pq_error(lr == -2 ? "passphrase required" : "cannot load identity");
        free(sigpath); free(id_resolved); return 1;
    }

    uint8_t *msg = NULL;
    size_t msg_len = 0;
    if (pq_read_file(infile, &msg, &msg_len) != 0) {
        pq_error("cannot read %s", infile);
        pq_identity_free(&id); free(sigpath); free(id_resolved); return 1;
    }

    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (pq_sign(msg, msg_len, id.sig.secret_key, id.sig.secret_key_len, id.sig_alg,
                &sig, &sig_len) != 0) {
        pq_error("signing failed");
        free(msg); pq_identity_free(&id); free(sigpath); free(id_resolved); return 1;
    }

    size_t cl = id.kem.public_key_len + id.sig.public_key_len;
    uint8_t *comb = malloc(cl);
    memcpy(comb, id.kem.public_key, id.kem.public_key_len);
    memcpy(comb + id.kem.public_key_len, id.sig.public_key, id.sig.public_key_len);
    char *fp = pq_fingerprint(comb, cl);
    free(comb);
    char *b64 = pq_bin_to_b64(sig, sig_len);
    free(sig);

    FILE *f = fopen(sigpath, "w");
    if (!f) {
        pq_error("cannot write %s", sigpath);
        free(msg); free(b64); free(fp); free(sigpath); free(id_resolved);
        pq_identity_free(&id); return 1;
    }
    fprintf(f, "-----BEGIN PQ SIGNATURE-----\n");
    fprintf(f, "Alg: %s\n", id.sig_alg);
    fprintf(f, "Signer: %s\n", fp ? fp : "");
    fprintf(f, "Sig: %s\n", b64);
    fprintf(f, "-----END PQ SIGNATURE-----\n");
    fclose(f);

    pq_success("Signed %s → %s", infile, sigpath);
    free(msg); free(b64); free(fp); free(sigpath); free(id_resolved);
    pq_identity_free(&id);
    return 0;
}

int cmd_verify(int argc, char **argv) {
    const char *infile = NULL;
    const char *sigfile = NULL;
    const char *pubkey = NULL; /* keyring name or .pqpub path */

    static struct option long_opts[] = {
        {"in",     required_argument, 0, 'f'},
        {"sig",    required_argument, 0, 's'},
        {"pubkey", required_argument, 0, 'p'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    optind = 1;
    int opt;
    while ((opt = getopt_long(argc, argv, "f:s:p:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'f': infile = optarg; break;
        case 's': sigfile = optarg; break;
        case 'p': pubkey = optarg; break;
        case 'h':
            printf("Usage: pqcli verify -f FILE -s FILE.sig [-p name|.pqpub]\n");
            return 0;
        default: return 1;
        }
    }
    if (!infile && optind < argc) infile = argv[optind++];
    if (!sigfile && optind < argc) sigfile = argv[optind++];
    if (!pubkey && optind < argc) pubkey = argv[optind++];

    char *auto_sig = NULL;
    if (infile && !sigfile) {
        auto_sig = pq_default_out_path(infile, ".sig");
        if (auto_sig && pq_file_exists(auto_sig))
            sigfile = auto_sig;
        else {
            free(auto_sig); auto_sig = NULL;
        }
    }

    if (!infile || !sigfile) {
        pq_error("usage: pqcli verify <file> [file.sig] [pubkey]");
        free(auto_sig);
        return 1;
    }


    uint8_t *msg = NULL;
    size_t msg_len = 0;
    if (pq_read_file(infile, &msg, &msg_len) != 0) {
        pq_error("cannot read file"); return 1;
    }

    uint8_t *sraw = NULL;
    size_t sraw_len = 0;
    if (pq_read_file(sigfile, &sraw, &sraw_len) != 0) {
        pq_error("cannot read signature"); free(msg); return 1;
    }

    char *alg = NULL;
    char *signer_fp = NULL;
    char *sig_b64 = NULL;
    char *line = (char *)sraw;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t L = strlen(line);
        if (L && line[L-1] == '\r') line[L-1] = 0;
        if (strncmp(line, "Alg: ", 5) == 0) alg = strdup(line + 5);
        else if (strncmp(line, "Signer: ", 8) == 0) signer_fp = strdup(line + 8);
        else if (strncmp(line, "Sig: ", 5) == 0) sig_b64 = strdup(line + 5);
        if (!nl) break;
        line = nl + 1;
    }
    free(sraw);

    if (!alg || !sig_b64) {
        pq_error("invalid signature file");
        free(msg); free(alg); free(signer_fp); free(sig_b64); return 1;
    }
    uint8_t *sig = NULL;
    size_t sig_len = 0;
    if (pq_b64_to_bin(sig_b64, &sig, &sig_len) != 0) {
        pq_error("bad signature encoding");
        free(msg); free(alg); free(signer_fp); free(sig_b64); return 1;
    }
    free(sig_b64);

    /* Resolve public key */
    uint8_t *pk = NULL;
    size_t pk_len = 0;
    char *resolved_name = NULL;

    if (pubkey && pq_file_exists(pubkey)) {
        char *nm=NULL,*cm=NULL,*ka=NULL,*sa=NULL;
        uint8_t *kpk=NULL,*spk=NULL; size_t klen=0,slen=0;
        if (pq_read_public_key_file(pubkey, &nm, &cm, &ka, &kpk, &klen, &sa, &spk, &slen) != 0) {
            pq_error("cannot read public key file");
            free(msg); free(alg); free(signer_fp); free(sig); return 1;
        }
        if (sa && alg && strcmp(sa, alg) != 0)
            pq_info("warning: signature alg %s vs key alg %s", alg, sa);
        pk = spk; pk_len = slen;
        free(nm); free(cm); free(ka); free(sa); free(kpk);
        resolved_name = strdup(pubkey);
    } else {
        pq_keyring_t kr;
        if (pq_keyring_load(&kr) != 0) {
            pq_error("keyring load failed");
            free(msg); free(alg); free(signer_fp); free(sig); return 1;
        }
        pq_keyring_entry_t *e = NULL;
        if (pubkey) e = pq_keyring_find(&kr, pubkey);
        if (!e && signer_fp) e = pq_keyring_find_by_fp(&kr, signer_fp);
        if (!e) {
            pq_error("signer not found — pass -p <name|.pqpub>");
            pq_keyring_free(&kr);
            free(msg); free(alg); free(signer_fp); free(sig); return 1;
        }
        pk = malloc(e->sig_pk_len);
        memcpy(pk, e->sig_pk, e->sig_pk_len);
        pk_len = e->sig_pk_len;
        resolved_name = strdup(e->name);
        if (!alg) alg = strdup(e->sig_alg);
        pq_keyring_free(&kr);
    }

    int ok = (pq_verify(msg, msg_len, sig, sig_len, pk, pk_len, alg) == 0);
    if (ok)
        pq_success("Signature VALID (signer=%s alg=%s)", resolved_name ? resolved_name : "?", alg);
    else
        pq_error("Signature INVALID");

    free(msg); free(alg); free(signer_fp); free(sig); free(pk); free(resolved_name); free(auto_sig);
    return ok ? 0 : 1;
}
