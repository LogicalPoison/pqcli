#define _POSIX_C_SOURCE 200809L
#include "commands.h"
#include "crypto.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*cmd_fn)(int argc, char **argv);
struct cmd_entry { const char *name; cmd_fn fn; };

static int cmd_keyring_dispatch(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: pqcli keyring <list|add|remove|trust|untrust|verify>\n");
        return 1;
    }
    const char *sub = argv[1];
    char **sa = argv + 1;
    const int sc = argc - 1;
    if (strcmp(sub, "list") == 0) return cmd_keyring_list(sc, sa);
    if (strcmp(sub, "add") == 0) return cmd_keyring_add(sc, sa);
    if (strcmp(sub, "remove") == 0 || strcmp(sub, "rm") == 0) return cmd_keyring_remove(sc, sa);
    if (strcmp(sub, "trust") == 0) return cmd_keyring_trust(sc, sa);
    if (strcmp(sub, "untrust") == 0) return cmd_keyring_trust(sc, sa);
    if (strcmp(sub, "verify") == 0) return cmd_keyring_verify(sc, sa);
    pq_error("unknown keyring subcommand: %s", sub);
    return 1;
}

static int cmd_trust_shortcut(int argc, char **argv) {
    char *fake[3] = { "trust", argc >= 2 ? argv[1] : NULL, NULL };
    return cmd_keyring_trust(argc >= 2 ? 2 : 1, fake);
}
static int cmd_untrust_shortcut(int argc, char **argv) {
    char *fake[3] = { "untrust", argc >= 2 ? argv[1] : NULL, NULL };
    return cmd_keyring_trust(argc >= 2 ? 2 : 1, fake);
}

static const struct cmd_entry commands[] = {
    {"help", cmd_help}, {"version", cmd_version},
    {"list-algs", cmd_list_algs}, {"doctor", cmd_doctor},
    {"genkey", cmd_genkey}, {"list-keys", cmd_list_keys}, {"keys", cmd_list_keys},
    {"export", cmd_export}, {"import", cmd_import},
    {"use", cmd_use}, {"info", cmd_info},
    {"rm-key", cmd_rm_key}, {"passwd", cmd_passwd},
    {"config", cmd_config}, {"fingerprint", cmd_fingerprint},
    {"backup", cmd_backup}, {"restore", cmd_restore},
    {"keyring", cmd_keyring_dispatch}, {"contacts", cmd_keyring_list},
    {"trust", cmd_trust_shortcut}, {"untrust", cmd_untrust_shortcut},
    {"encrypt", cmd_encrypt}, {"decrypt", cmd_decrypt},
    {"sign", cmd_sign}, {"verify", cmd_verify},
    {"inspect", cmd_inspect}, {"reencrypt", cmd_reencrypt},
    {"wipe", cmd_wipe},
    {NULL, NULL}
};

int main(int argc, char **argv) {
    if (pq_crypto_init() != 0) {
        fprintf(stderr, "Failed to initialize crypto\n");
        return 1;
    }
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        cmd_help(0, NULL); pq_crypto_cleanup(); return 0;
    }
    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--version") == 0) {
        cmd_version(0, NULL); pq_crypto_cleanup(); return 0;
    }
    for (const struct cmd_entry *e = commands; e->name; e++) {
        if (strcmp(e->name, argv[1]) == 0) {
            int rc = e->fn(argc - 1, argv + 1);
            pq_crypto_cleanup();
            return rc;
        }
    }
    pq_error("unknown command: %s — try 'pqcli help'", argv[1]);
    pq_crypto_cleanup();
    return 1;
}
