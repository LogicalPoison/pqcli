#ifndef PQCLI_KEYRING_H
#define PQCLI_KEYRING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "crypto.h"

typedef struct {
    char   *name;
    char   *comment;
    char   *fingerprint;
    char   *kem_alg;
    char   *sig_alg;
    uint8_t *kem_pk;
    size_t   kem_pk_len;
    uint8_t *sig_pk;
    size_t   sig_pk_len;
    bool     trusted;
} pq_keyring_entry_t;

typedef struct {
    pq_keyring_entry_t *entries;
    size_t count;
    size_t capacity;
} pq_keyring_t;

int  pq_keyring_load(pq_keyring_t *kr);
int  pq_keyring_save(const pq_keyring_t *kr);
void pq_keyring_free(pq_keyring_t *kr);

int  pq_keyring_add(pq_keyring_t *kr, const char *name, const char *comment,
                    const char *kem_alg, const uint8_t *kem_pk, size_t kem_pk_len,
                    const char *sig_alg, const uint8_t *sig_pk, size_t sig_pk_len);
int  pq_keyring_remove(pq_keyring_t *kr, const char *name);
pq_keyring_entry_t *pq_keyring_find(pq_keyring_t *kr, const char *name);
pq_keyring_entry_t *pq_keyring_find_by_fp(pq_keyring_t *kr, const char *fp);
void pq_keyring_list(const pq_keyring_t *kr);
int  pq_keyring_set_trusted(pq_keyring_t *kr, const char *name, bool trusted);

/* passphrase may be NULL => store plaintext (legacy); non-NULL => Argon2 protect */
int  pq_identity_save(const pq_identity_t *id, const char *name, const char *passphrase);
/* passphrase required if keys are protected; may be NULL to try plaintext */
int  pq_identity_load(const char *name, pq_identity_t *id, const char *passphrase);
int  pq_identity_list(void);
int  pq_identity_register(const char *name);
int  pq_identity_export_public(const char *name, const char *out_path);
int  pq_identity_import_public(const char *path, const char *name, const char *comment);
int  pq_identity_is_protected(const char *name); /* 1=yes 0=no -1=error */
int  pq_identity_delete(const char *name);
int  pq_identity_names(char ***names, size_t *count); /* caller frees */

int  pq_write_public_key_file(const char *path,
                              const char *name, const char *comment,
                              const char *kem_alg, const uint8_t *kem_pk, size_t kem_pk_len,
                              const char *sig_alg, const uint8_t *sig_pk, size_t sig_pk_len);
int  pq_read_public_key_file(const char *path,
                             char **name, char **comment,
                             char **kem_alg, uint8_t **kem_pk, size_t *kem_pk_len,
                             char **sig_alg, uint8_t **sig_pk, size_t *sig_pk_len);

#endif /* PQCLI_KEYRING_H */
