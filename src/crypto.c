#define _POSIX_C_SOURCE 200809L
#include "crypto.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "monocypher.h"

/* Argon2id params for key protection (interactive) */
#define PQ_ARGON2_BLOCKS  16384u  /* 16 MiB */
#define PQ_ARGON2_PASSES  3u
#define PQ_ARGON2_LANES   1u
#define PQ_SALT_LEN       16

int pq_crypto_init(void) {
    OQS_init();
    return 0;
}

void pq_crypto_cleanup(void) {
    OQS_destroy();
}

void pq_list_kems(void) {
    int n = OQS_KEM_alg_count();
    printf("Enabled KEMs (%d):\n", n);
    for (int i = 0; i < n; i++) {
        const char *name = OQS_KEM_alg_identifier((size_t)i);
        if (OQS_KEM_alg_is_enabled(name))
            printf("  %s\n", name);
    }
}

void pq_list_sigs(void) {
    int n = OQS_SIG_alg_count();
    printf("Enabled signatures (%d):\n", n);
    for (int i = 0; i < n; i++) {
        const char *name = OQS_SIG_alg_identifier((size_t)i);
        if (OQS_SIG_alg_is_enabled(name))
            printf("  %s\n", name);
    }
}

void pq_keypair_free(pq_keypair_t *kp) {
    if (!kp) return;
    free(kp->alg);
    if (kp->public_key) pq_secure_free(kp->public_key, kp->public_key_len);
    if (kp->secret_key) pq_secure_free(kp->secret_key, kp->secret_key_len);
    memset(kp, 0, sizeof(*kp));
}

void pq_identity_free(pq_identity_t *id) {
    if (!id) return;
    free(id->kem_alg);
    free(id->sig_alg);
    pq_keypair_free(&id->kem);
    pq_keypair_free(&id->sig);
    memset(id, 0, sizeof(*id));
}

int pq_generate_keypair(const char *alg, int is_sig, pq_keypair_t *out) {
    memset(out, 0, sizeof(*out));
    out->alg = strdup(alg);
    if (!out->alg) return -1;
    if (is_sig) {
        OQS_SIG *sig = OQS_SIG_new(alg);
        if (!sig) { free(out->alg); out->alg = NULL; return -1; }
        out->public_key_len = sig->length_public_key;
        out->secret_key_len = sig->length_secret_key;
        out->public_key = pq_secure_malloc(out->public_key_len);
        out->secret_key = pq_secure_malloc(out->secret_key_len);
        if (!out->public_key || !out->secret_key) {
            pq_keypair_free(out); OQS_SIG_free(sig); return -1;
        }
        if (OQS_SIG_keypair(sig, out->public_key, out->secret_key) != OQS_SUCCESS) {
            pq_keypair_free(out); OQS_SIG_free(sig); return -1;
        }
        OQS_SIG_free(sig);
    } else {
        OQS_KEM *kem = OQS_KEM_new(alg);
        if (!kem) { free(out->alg); out->alg = NULL; return -1; }
        out->public_key_len = kem->length_public_key;
        out->secret_key_len = kem->length_secret_key;
        out->public_key = pq_secure_malloc(out->public_key_len);
        out->secret_key = pq_secure_malloc(out->secret_key_len);
        if (!out->public_key || !out->secret_key) {
            pq_keypair_free(out); OQS_KEM_free(kem); return -1;
        }
        if (OQS_KEM_keypair(kem, out->public_key, out->secret_key) != OQS_SUCCESS) {
            pq_keypair_free(out); OQS_KEM_free(kem); return -1;
        }
        OQS_KEM_free(kem);
    }
    return 0;
}

int pq_derive_key(const uint8_t *ss, size_t ss_len, uint8_t key[PQCLI_KEY_LEN]) {
    static const uint8_t info[] = "pqcli-xchacha20";
    crypto_blake2b_keyed(key, PQCLI_KEY_LEN, ss, ss_len, info, sizeof(info) - 1);
    return 0;
}

int pq_sign(const uint8_t *msg, size_t msg_len,
            const uint8_t *sk, size_t sk_len, const char *sig_alg,
            uint8_t **sig, size_t *sig_len) {
    OQS_SIG *s = OQS_SIG_new(sig_alg);
    if (!s) return -1;
    if (sk_len != s->length_secret_key) { OQS_SIG_free(s); return -1; }
    *sig = malloc(s->length_signature);
    if (!*sig) { OQS_SIG_free(s); return -1; }
    size_t slen = s->length_signature;
    if (OQS_SIG_sign(s, *sig, &slen, msg, msg_len, sk) != OQS_SUCCESS) {
        free(*sig); *sig = NULL; OQS_SIG_free(s); return -1;
    }
    *sig_len = slen;
    OQS_SIG_free(s);
    return 0;
}

int pq_verify(const uint8_t *msg, size_t msg_len,
              const uint8_t *sig, size_t sig_len,
              const uint8_t *pk, size_t pk_len, const char *sig_alg) {
    OQS_SIG *s = OQS_SIG_new(sig_alg);
    if (!s) return -1;
    if (pk_len != s->length_public_key) { OQS_SIG_free(s); return -1; }
    OQS_STATUS st = OQS_SIG_verify(s, msg, msg_len, sig, sig_len, pk);
    OQS_SIG_free(s);
    return (st == OQS_SUCCESS) ? 0 : -1;
}

/* ---- passphrase protection (Argon2id + XChaCha20-Poly1305) ---- */
/* blob: salt[16] | nonce[24] | mac[16] | ciphertext */

int pq_protect_secret(const uint8_t *plain, size_t plain_len,
                      const char *passphrase,
                      uint8_t **out_blob, size_t *out_blob_len) {
    uint8_t salt[PQ_SALT_LEN];
    if (pq_random_bytes(salt, sizeof(salt)) != 0) return -1;

    size_t work_sz = (size_t)PQ_ARGON2_BLOCKS * 1024;
    void *work = malloc(work_sz);
    if (!work) return -1;

    uint8_t key[32];
    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = PQ_ARGON2_BLOCKS,
        .nb_passes = PQ_ARGON2_PASSES,
        .nb_lanes  = PQ_ARGON2_LANES
    };
    crypto_argon2_inputs in = {
        .pass = (const uint8_t *)passphrase,
        .salt = salt,
        .pass_size = (uint32_t)strlen(passphrase),
        .salt_size = PQ_SALT_LEN
    };
    crypto_argon2(key, 32, work, cfg, in, crypto_argon2_no_extras);
    free(work);

    uint8_t nonce[PQCLI_NONCE_LEN];
    if (pq_random_bytes(nonce, sizeof(nonce)) != 0) {
        crypto_wipe(key, sizeof(key)); return -1;
    }

    uint8_t *ct = malloc(plain_len);
    if (!ct) { crypto_wipe(key, sizeof(key)); return -1; }
    uint8_t mac[PQCLI_TAG_LEN];
    crypto_aead_lock(ct, mac, key, nonce, NULL, 0, plain, plain_len);
    crypto_wipe(key, sizeof(key));

    size_t blen = PQ_SALT_LEN + PQCLI_NONCE_LEN + PQCLI_TAG_LEN + plain_len;
    uint8_t *blob = malloc(blen);
    if (!blob) { free(ct); return -1; }
    memcpy(blob, salt, PQ_SALT_LEN);
    memcpy(blob + PQ_SALT_LEN, nonce, PQCLI_NONCE_LEN);
    memcpy(blob + PQ_SALT_LEN + PQCLI_NONCE_LEN, mac, PQCLI_TAG_LEN);
    memcpy(blob + PQ_SALT_LEN + PQCLI_NONCE_LEN + PQCLI_TAG_LEN, ct, plain_len);
    free(ct);
    *out_blob = blob;
    *out_blob_len = blen;
    return 0;
}

int pq_unprotect_secret(const uint8_t *blob, size_t blob_len,
                        const char *passphrase,
                        uint8_t **out_plain, size_t *out_plain_len) {
    size_t hdr = PQ_SALT_LEN + PQCLI_NONCE_LEN + PQCLI_TAG_LEN;
    if (blob_len < hdr) return -1;
    const uint8_t *salt = blob;
    const uint8_t *nonce = blob + PQ_SALT_LEN;
    const uint8_t *mac = blob + PQ_SALT_LEN + PQCLI_NONCE_LEN;
    const uint8_t *ct = blob + hdr;
    size_t ct_len = blob_len - hdr;

    size_t work_sz = (size_t)PQ_ARGON2_BLOCKS * 1024;
    void *work = malloc(work_sz);
    if (!work) return -1;
    uint8_t key[32];
    crypto_argon2_config cfg = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = PQ_ARGON2_BLOCKS,
        .nb_passes = PQ_ARGON2_PASSES,
        .nb_lanes  = PQ_ARGON2_LANES
    };
    crypto_argon2_inputs in = {
        .pass = (const uint8_t *)passphrase,
        .salt = salt,
        .pass_size = (uint32_t)strlen(passphrase),
        .salt_size = PQ_SALT_LEN
    };
    crypto_argon2(key, 32, work, cfg, in, crypto_argon2_no_extras);
    free(work);

    uint8_t *pt = pq_secure_malloc(ct_len);
    if (!pt) { crypto_wipe(key, sizeof(key)); return -1; }
    if (crypto_aead_unlock(pt, mac, key, nonce, NULL, 0, ct, ct_len) != 0) {
        crypto_wipe(key, sizeof(key));
        pq_secure_free(pt, ct_len);
        return -1;
    }
    crypto_wipe(key, sizeof(key));
    *out_plain = pt;
    *out_plain_len = ct_len;
    return 0;
}

/* ---- binary helpers ---- */
static void w_u8(FILE *f, uint8_t v)  { fwrite(&v, 1, 1, f); }
static void w_u16(FILE *f, uint16_t v) {
    uint8_t b[2] = { (uint8_t)(v >> 8), (uint8_t)v };
    fwrite(b, 1, 2, f);
}
static void w_u32(FILE *f, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v>>24), (uint8_t)(v>>16), (uint8_t)(v>>8), (uint8_t)v };
    fwrite(b, 1, 4, f);
}
static int r_u8(FILE *f, uint8_t *v)  { return fread(v, 1, 1, f) == 1 ? 0 : -1; }
static int r_u16(FILE *f, uint16_t *v) {
    uint8_t b[2];
    if (fread(b, 1, 2, f) != 2) return -1;
    *v = ((uint16_t)b[0] << 8) | b[1]; return 0;
}
static int r_u32(FILE *f, uint32_t *v) {
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) return -1;
    *v = ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3];
    return 0;
}

/* Wrap CEK for one recipient via KEM */
static int wrap_cek_for_recipient(
    const pq_recipient_t *rcp,
    const uint8_t cek[PQCLI_KEY_LEN],
    uint8_t **kem_ct, size_t *kem_ct_len,
    uint8_t cek_nonce[PQCLI_NONCE_LEN],
    uint8_t cek_mac[PQCLI_TAG_LEN],
    uint8_t cek_ct[PQCLI_KEY_LEN]
) {
    OQS_KEM *kem = OQS_KEM_new(rcp->kem_alg);
    if (!kem) return -1;
    if (rcp->kem_pk_len != kem->length_public_key) { OQS_KEM_free(kem); return -1; }

    *kem_ct = pq_secure_malloc(kem->length_ciphertext);
    uint8_t *ss = pq_secure_malloc(kem->length_shared_secret);
    if (!*kem_ct || !ss) {
        pq_secure_free(*kem_ct, kem->length_ciphertext);
        pq_secure_free(ss, kem->length_shared_secret);
        OQS_KEM_free(kem); return -1;
    }
    if (OQS_KEM_encaps(kem, *kem_ct, ss, rcp->kem_pk) != OQS_SUCCESS) {
        pq_secure_free(*kem_ct, kem->length_ciphertext);
        pq_secure_free(ss, kem->length_shared_secret);
        OQS_KEM_free(kem); return -1;
    }
    *kem_ct_len = kem->length_ciphertext;

    uint8_t kek[PQCLI_KEY_LEN];
    pq_derive_key(ss, kem->length_shared_secret, kek);
    pq_secure_free(ss, kem->length_shared_secret);
    OQS_KEM_free(kem);

    if (pq_random_bytes(cek_nonce, PQCLI_NONCE_LEN) != 0) {
        crypto_wipe(kek, sizeof(kek)); return -1;
    }
    crypto_aead_lock(cek_ct, cek_mac, kek, cek_nonce, NULL, 0, cek, PQCLI_KEY_LEN);
    crypto_wipe(kek, sizeof(kek));
    return 0;
}

static int unwrap_cek(
    const char *kem_alg,
    const uint8_t *kem_ct, size_t kem_ct_len,
    const uint8_t *sk, size_t sk_len,
    const uint8_t cek_nonce[PQCLI_NONCE_LEN],
    const uint8_t cek_mac[PQCLI_TAG_LEN],
    const uint8_t cek_ct[PQCLI_KEY_LEN],
    uint8_t cek_out[PQCLI_KEY_LEN]
) {
    OQS_KEM *kem = OQS_KEM_new(kem_alg);
    if (!kem) return -1;
    if (sk_len != kem->length_secret_key || kem_ct_len != kem->length_ciphertext) {
        OQS_KEM_free(kem); return -1;
    }
    uint8_t *ss = pq_secure_malloc(kem->length_shared_secret);
    if (!ss) { OQS_KEM_free(kem); return -1; }
    if (OQS_KEM_decaps(kem, ss, kem_ct, sk) != OQS_SUCCESS) {
        pq_secure_free(ss, kem->length_shared_secret);
        OQS_KEM_free(kem); return -1;
    }
    uint8_t kek[PQCLI_KEY_LEN];
    pq_derive_key(ss, kem->length_shared_secret, kek);
    pq_secure_free(ss, kem->length_shared_secret);
    OQS_KEM_free(kem);

    int rc = crypto_aead_unlock(cek_out, cek_mac, kek, cek_nonce, NULL, 0, cek_ct, PQCLI_KEY_LEN);
    crypto_wipe(kek, sizeof(kek));
    return rc == 0 ? 0 : -1;
}

int pq_encrypt_file(
    const char *in_path,
    const char *out_path,
    const pq_recipient_t *recipients, size_t n_recipients,
    const uint8_t *sender_sig_sk, size_t sender_sig_sk_len,
    const char *sig_alg,
    const char *sender_fp,
    bool armor
) {
    if (n_recipients == 0 || n_recipients > 65535) return -1;

    uint8_t cek[PQCLI_KEY_LEN];
    uint8_t content_nonce[PQCLI_NONCE_LEN];
    if (pq_random_bytes(cek, sizeof(cek)) != 0) return -1;
    if (pq_random_bytes(content_nonce, sizeof(content_nonce)) != 0) {
        crypto_wipe(cek, sizeof(cek)); return -1;
    }

    /* Build binary blob to a temp path (or memory for armor) */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", out_path);
    FILE *out = fopen(tmp_path, "wb");
    if (!out) { crypto_wipe(cek, sizeof(cek)); return -1; }

    uint8_t flags = 0;
    if (sender_sig_sk && sig_alg) flags |= PQCLI_FLAG_SIGNED;

    fwrite(PQCLI_MAGIC, 1, 4, out);
    w_u8(out, PQCLI_FORMAT_VERSION);
    w_u8(out, flags);
    w_u16(out, (uint16_t)n_recipients);

    /* Per-recipient packages */
    for (size_t i = 0; i < n_recipients; i++) {
        const pq_recipient_t *r = &recipients[i];
        uint8_t *kem_ct = NULL;
        size_t kem_ct_len = 0;
        uint8_t cek_nonce[PQCLI_NONCE_LEN], cek_mac[PQCLI_TAG_LEN], cek_ct[PQCLI_KEY_LEN];
        if (wrap_cek_for_recipient(r, cek, &kem_ct, &kem_ct_len, cek_nonce, cek_mac, cek_ct) != 0) {
            fclose(out); remove(tmp_path);
            crypto_wipe(cek, sizeof(cek)); return -1;
        }
        uint8_t fp_len = 0;
        if (r->fingerprint) {
            size_t fl = strlen(r->fingerprint);
            if (fl > 255) fl = 255;
            fp_len = (uint8_t)fl;
        }
        w_u8(out, fp_len);
        if (fp_len) fwrite(r->fingerprint, 1, fp_len, out);
        uint16_t al = (uint16_t)strlen(r->kem_alg);
        w_u16(out, al);
        fwrite(r->kem_alg, 1, al, out);
        w_u32(out, (uint32_t)kem_ct_len);
        fwrite(kem_ct, 1, kem_ct_len, out);
        fwrite(cek_nonce, 1, PQCLI_NONCE_LEN, out);
        fwrite(cek_mac, 1, PQCLI_TAG_LEN, out);
        fwrite(cek_ct, 1, PQCLI_KEY_LEN, out);
        pq_secure_free(kem_ct, kem_ct_len);
    }

    fwrite(content_nonce, 1, PQCLI_NONCE_LEN, out);

    /* Stream encrypt input */
    FILE *in = fopen(in_path, "rb");
    if (!in) {
        fclose(out); remove(tmp_path);
        crypto_wipe(cek, sizeof(cek)); return -1;
    }

    crypto_aead_ctx aead;
    crypto_aead_init_x(&aead, cek, content_nonce);
    crypto_wipe(cek, sizeof(cek));

    uint8_t *pt_buf = malloc(PQCLI_CHUNK_SIZE);
    uint8_t *ct_buf = malloc(PQCLI_CHUNK_SIZE);
    if (!pt_buf || !ct_buf) {
        free(pt_buf); free(ct_buf);
        fclose(in); fclose(out); remove(tmp_path);
        crypto_wipe(&aead, sizeof(aead)); return -1;
    }

    /* Hash of all chunk macs for optional signature */
    crypto_blake2b_ctx hash_ctx;
    crypto_blake2b_init(&hash_ctx, 32);
    crypto_blake2b_update(&hash_ctx, content_nonce, PQCLI_NONCE_LEN);

    for (;;) {
        size_t n = fread(pt_buf, 1, PQCLI_CHUNK_SIZE, in);
        if (n == 0) break;
        uint8_t mac[PQCLI_TAG_LEN];
        crypto_aead_write(&aead, ct_buf, mac, NULL, 0, pt_buf, n);
        w_u32(out, (uint32_t)n);
        fwrite(mac, 1, PQCLI_TAG_LEN, out);
        fwrite(ct_buf, 1, n, out);
        crypto_blake2b_update(&hash_ctx, mac, PQCLI_TAG_LEN);
        crypto_blake2b_update(&hash_ctx, ct_buf, n);
    }
    w_u32(out, 0); /* end of chunks */
    fclose(in);
    crypto_wipe(&aead, sizeof(aead));
    free(pt_buf); free(ct_buf);

    uint8_t content_hash[32];
    crypto_blake2b_final(&hash_ctx, content_hash);

    if (flags & PQCLI_FLAG_SIGNED) {
        uint8_t *signature = NULL;
        size_t sig_len = 0;
        if (pq_sign(content_hash, 32, sender_sig_sk, sender_sig_sk_len, sig_alg,
                    &signature, &sig_len) != 0) {
            fclose(out); remove(tmp_path); return -1;
        }
        uint16_t al = (uint16_t)strlen(sig_alg);
        w_u16(out, al);
        fwrite(sig_alg, 1, al, out);
        w_u32(out, (uint32_t)sig_len);
        fwrite(signature, 1, sig_len, out);
        free(signature);
        uint8_t fp_len = 0;
        if (sender_fp) {
            size_t fl = strlen(sender_fp);
            if (fl > 255) fl = 255;
            fp_len = (uint8_t)fl;
        }
        w_u8(out, fp_len);
        if (fp_len) fwrite(sender_fp, 1, fp_len, out);
    }
    fclose(out);

    if (armor) {
        uint8_t *raw = NULL;
        size_t raw_len = 0;
        if (pq_read_file(tmp_path, &raw, &raw_len) != 0) {
            remove(tmp_path); return -1;
        }
        remove(tmp_path);
        char *text = NULL;
        if (pq_armor_encode(raw, raw_len, &text) != 0) {
            free(raw); return -1;
        }
        free(raw);
        FILE *af = fopen(out_path, "w");
        if (!af) { free(text); return -1; }
        fputs(text, af);
        fclose(af);
        free(text);
    } else {
        if (rename(tmp_path, out_path) != 0) {
            /* cross-device fallback */
            uint8_t *raw = NULL; size_t raw_len = 0;
            if (pq_read_file(tmp_path, &raw, &raw_len) != 0) {
                remove(tmp_path); return -1;
            }
            remove(tmp_path);
            if (pq_write_file(out_path, raw, raw_len, 0644) != 0) {
                free(raw); return -1;
            }
            free(raw);
        }
    }
    return 0;
}

int pq_decrypt_file(
    const char *in_path,
    const char *out_path,
    const uint8_t *recipient_kem_sk, size_t recipient_kem_sk_len,
    const char *expected_kem_alg,
    const uint8_t *sender_sig_pk, size_t sender_sig_pk_len,
    const char *expected_sig_alg,
    bool *signature_ok,
    char **out_sender_fp
) {
    if (signature_ok) *signature_ok = false;
    if (out_sender_fp) *out_sender_fp = NULL;

    uint8_t *raw = NULL;
    size_t raw_len = 0;
    if (pq_read_file(in_path, &raw, &raw_len) != 0) return -1;

    /* Detect armor */
    if (raw_len > 20 && memcmp(raw, "-----BEGIN", 10) == 0) {
        uint8_t *bin = NULL;
        size_t bin_len = 0;
        if (pq_armor_decode((char *)raw, raw_len, &bin, &bin_len) != 0) {
            free(raw); return -1;
        }
        free(raw);
        raw = bin;
        raw_len = bin_len;
    }

    /* Write to temp for FILE* parsing */
    char tmp_in[512];
    snprintf(tmp_in, sizeof(tmp_in), "%s.din", out_path);
    if (pq_write_file(tmp_in, raw, raw_len, 0600) != 0) {
        free(raw); return -1;
    }
    free(raw);

    FILE *in = fopen(tmp_in, "rb");
    if (!in) { remove(tmp_in); return -1; }

    char magic[4];
    if (fread(magic, 1, 4, in) != 4 || memcmp(magic, PQCLI_MAGIC, 4) != 0) {
        fclose(in); remove(tmp_in); return -1;
    }
    uint8_t version, flags;
    if (r_u8(in, &version) || r_u8(in, &flags)) {
        fclose(in); remove(tmp_in); return -1;
    }
    if (version != PQCLI_FORMAT_VERSION) {
        fclose(in); remove(tmp_in); return -1;
    }

    uint16_t n_rcp;
    if (r_u16(in, &n_rcp) || n_rcp == 0) {
        fclose(in); remove(tmp_in); return -1;
    }

    uint8_t cek[PQCLI_KEY_LEN];
    int got_cek = 0;

    for (uint16_t i = 0; i < n_rcp; i++) {
        uint8_t fp_len;
        if (r_u8(in, &fp_len)) { fclose(in); remove(tmp_in); return -1; }
        if (fp_len) fseek(in, fp_len, SEEK_CUR);

        uint16_t al;
        if (r_u16(in, &al)) { fclose(in); remove(tmp_in); return -1; }
        char *kem_alg = malloc(al + 1);
        if (!kem_alg || fread(kem_alg, 1, al, in) != al) {
            free(kem_alg); fclose(in); remove(tmp_in); return -1;
        }
        kem_alg[al] = 0;

        uint32_t kem_ct_len;
        if (r_u32(in, &kem_ct_len)) {
            free(kem_alg); fclose(in); remove(tmp_in); return -1;
        }
        uint8_t *kem_ct = malloc(kem_ct_len);
        if (!kem_ct || fread(kem_ct, 1, kem_ct_len, in) != kem_ct_len) {
            free(kem_alg); free(kem_ct); fclose(in); remove(tmp_in); return -1;
        }
        uint8_t cek_nonce[PQCLI_NONCE_LEN], cek_mac[PQCLI_TAG_LEN], cek_ct[PQCLI_KEY_LEN];
        if (fread(cek_nonce, 1, PQCLI_NONCE_LEN, in) != PQCLI_NONCE_LEN ||
            fread(cek_mac, 1, PQCLI_TAG_LEN, in) != PQCLI_TAG_LEN ||
            fread(cek_ct, 1, PQCLI_KEY_LEN, in) != PQCLI_KEY_LEN) {
            free(kem_alg); free(kem_ct); fclose(in); remove(tmp_in); return -1;
        }

        if (!got_cek) {
            if (!expected_kem_alg || strcmp(expected_kem_alg, kem_alg) == 0) {
                if (unwrap_cek(kem_alg, kem_ct, kem_ct_len,
                               recipient_kem_sk, recipient_kem_sk_len,
                               cek_nonce, cek_mac, cek_ct, cek) == 0) {
                    got_cek = 1;
                }
            }
        }
        free(kem_alg);
        free(kem_ct);
    }

    if (!got_cek) {
        fclose(in); remove(tmp_in); return -1;
    }

    uint8_t content_nonce[PQCLI_NONCE_LEN];
    if (fread(content_nonce, 1, PQCLI_NONCE_LEN, in) != PQCLI_NONCE_LEN) {
        crypto_wipe(cek, sizeof(cek));
        fclose(in); remove(tmp_in); return -1;
    }

    FILE *out = fopen(out_path, "wb");
    if (!out) {
        crypto_wipe(cek, sizeof(cek));
        fclose(in); remove(tmp_in); return -1;
    }

    crypto_aead_ctx aead;
    crypto_aead_init_x(&aead, cek, content_nonce);
    crypto_wipe(cek, sizeof(cek));

    crypto_blake2b_ctx hash_ctx;
    crypto_blake2b_init(&hash_ctx, 32);
    crypto_blake2b_update(&hash_ctx, content_nonce, PQCLI_NONCE_LEN);

    int ok = 1;
    for (;;) {
        uint32_t clen;
        if (r_u32(in, &clen)) { ok = 0; break; }
        if (clen == 0) break;
        if (clen > PQCLI_CHUNK_SIZE) { ok = 0; break; }
        uint8_t mac[PQCLI_TAG_LEN];
        if (fread(mac, 1, PQCLI_TAG_LEN, in) != PQCLI_TAG_LEN) { ok = 0; break; }
        uint8_t *ct = malloc(clen);
        uint8_t *pt = malloc(clen);
        if (!ct || !pt) { free(ct); free(pt); ok = 0; break; }
        if (fread(ct, 1, clen, in) != clen) {
            free(ct); free(pt); ok = 0; break;
        }
        if (crypto_aead_read(&aead, pt, mac, NULL, 0, ct, clen) != 0) {
            free(ct); free(pt); ok = 0; break;
        }
        fwrite(pt, 1, clen, out);
        crypto_blake2b_update(&hash_ctx, mac, PQCLI_TAG_LEN);
        crypto_blake2b_update(&hash_ctx, ct, clen);
        free(ct); free(pt);
    }
    crypto_wipe(&aead, sizeof(aead));
    fclose(out);

    uint8_t content_hash[32];
    crypto_blake2b_final(&hash_ctx, content_hash);

    if (ok && (flags & PQCLI_FLAG_SIGNED)) {
        uint16_t al;
        if (r_u16(in, &al) == 0) {
            char *sig_alg = malloc(al + 1);
            if (sig_alg && fread(sig_alg, 1, al, in) == al) {
                sig_alg[al] = 0;
                uint32_t slen;
                if (r_u32(in, &slen) == 0) {
                    uint8_t *sig = malloc(slen);
                    if (sig && fread(sig, 1, slen, in) == slen) {
                        if (sender_sig_pk &&
                            (!expected_sig_alg || strcmp(expected_sig_alg, sig_alg) == 0)) {
                            int v = pq_verify(content_hash, 32, sig, slen,
                                              sender_sig_pk, sender_sig_pk_len, sig_alg);
                            if (signature_ok) *signature_ok = (v == 0);
                        }
                    }
                    free(sig);
                }
            }
            free(sig_alg);
        }
        uint8_t fp_len = 0;
        if (r_u8(in, &fp_len) == 0 && fp_len > 0 && out_sender_fp) {
            *out_sender_fp = malloc(fp_len + 1);
            if (*out_sender_fp && fread(*out_sender_fp, 1, fp_len, in) == fp_len)
                (*out_sender_fp)[fp_len] = 0;
            else { free(*out_sender_fp); *out_sender_fp = NULL; }
        }
    }

    fclose(in);
    remove(tmp_in);
    if (!ok) {
        remove(out_path);
        return -1;
    }
    return 0;
}
