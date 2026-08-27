#ifndef PQCLI_CRYPTO_H
#define PQCLI_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char     *alg;
    uint8_t  *public_key;
    size_t    public_key_len;
    uint8_t  *secret_key;
    size_t    secret_key_len;
} pq_keypair_t;

typedef struct {
    char     *kem_alg;
    char     *sig_alg;
    pq_keypair_t kem;
    pq_keypair_t sig;
} pq_identity_t;

/* One recipient for multi-recipient encrypt */
typedef struct {
    char    *kem_alg;
    uint8_t *kem_pk;
    size_t   kem_pk_len;
    char    *fingerprint; /* optional, stored in blob for matching */
} pq_recipient_t;

/*
 * Format version 3:
 *  magic "PQCL" | version=3 | flags
 *  num_recipients (u16)
 *  for each recipient:
 *    fp_len(u8)+fp | kem_alg_len(u16)+alg | kem_ct_len(u32)+ct
 *    cek_nonce[24] | cek_mac[16] | cek_ct[32]
 *  content_nonce[24]
 *  chunk stream: repeated (chunk_len u32 | mac[16] | ct[chunk_len]) until chunk_len=0
 *  if signed: sig_alg_len+alg | sig_len+sig | sender_fp
 *
 * flags: bit0 = signed
 */

#define PQCLI_MAGIC "PQCL"
#define PQCLI_FORMAT_VERSION 3
#define PQCLI_FLAG_SIGNED 0x01
#define PQCLI_NONCE_LEN 24
#define PQCLI_TAG_LEN 16
#define PQCLI_KEY_LEN 32
#define PQCLI_CHUNK_SIZE (1024 * 1024) /* 1 MiB streaming chunks */

int  pq_crypto_init(void);
void pq_crypto_cleanup(void);

void pq_list_kems(void);
void pq_list_sigs(void);

int  pq_generate_keypair(const char *alg, int is_sig, pq_keypair_t *out);
void pq_keypair_free(pq_keypair_t *kp);
void pq_identity_free(pq_identity_t *id);

int  pq_derive_key(const uint8_t *ss, size_t ss_len, uint8_t key[PQCLI_KEY_LEN]);

/* Encrypt file (streaming) to one or more recipients */
int  pq_encrypt_file(
    const char *in_path,
    const char *out_path,
    const pq_recipient_t *recipients, size_t n_recipients,
    const uint8_t *sender_sig_sk, size_t sender_sig_sk_len,
    const char *sig_alg,
    const char *sender_fp,
    bool armor
);

/* Decrypt file (streaming). Tries each identity KEM sk against recipients. */
int  pq_decrypt_file(
    const char *in_path,
    const char *out_path,
    const uint8_t *recipient_kem_sk, size_t recipient_kem_sk_len,
    const char *expected_kem_alg, /* may be NULL */
    const uint8_t *sender_sig_pk, size_t sender_sig_pk_len,
    const char *expected_sig_alg,
    bool *signature_ok,
    char **out_sender_fp
);

int  pq_sign(const uint8_t *msg, size_t msg_len,
             const uint8_t *sk, size_t sk_len, const char *sig_alg,
             uint8_t **sig, size_t *sig_len);
int  pq_verify(const uint8_t *msg, size_t msg_len,
               const uint8_t *sig, size_t sig_len,
               const uint8_t *pk, size_t pk_len, const char *sig_alg);

/* Encrypt/decrypt secret key material with passphrase (Argon2id + XChaCha20) */
int  pq_protect_secret(const uint8_t *plain, size_t plain_len,
                       const char *passphrase,
                       uint8_t **out_blob, size_t *out_blob_len);
int  pq_unprotect_secret(const uint8_t *blob, size_t blob_len,
                         const char *passphrase,
                         uint8_t **out_plain, size_t *out_plain_len);

#endif /* PQCLI_CRYPTO_H */
