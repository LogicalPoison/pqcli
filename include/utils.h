#ifndef PQCLI_UTILS_H
#define PQCLI_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/types.h>

#define PQCLI_VERSION "1.4.0"
#define PQCLI_DEFAULT_KEM "ML-KEM-768"
#define PQCLI_DEFAULT_SIG "ML-DSA-65"
#define PQCLI_HOME_DIR ".pqcli"
#define PQCLI_KEYS_DIR "keys"
#define PQCLI_KEYRING_DIR "keyring"
#define PQCLI_CONFIG_FILE "config"

void *pq_secure_malloc(size_t len);
void  pq_secure_free(void *ptr, size_t len);
void  pq_memzero(void *ptr, size_t len);

int   pq_read_file(const char *path, uint8_t **out, size_t *out_len);
int   pq_write_file(const char *path, const uint8_t *data, size_t len, mode_t mode);
int   pq_file_exists(const char *path);

char *pq_get_home_dir(void);
char *pq_get_config_dir(void);
char *pq_path_join(const char *a, const char *b);
int   pq_ensure_dir(const char *path);

char *pq_bin_to_hex(const uint8_t *bin, size_t len);
int   pq_hex_to_bin(const char *hex, uint8_t **out, size_t *out_len);
char *pq_bin_to_b64(const uint8_t *bin, size_t len);
int   pq_b64_to_bin(const char *b64, uint8_t **out, size_t *out_len);

char *pq_fingerprint(const uint8_t *pk, size_t pk_len);

void  pq_die(const char *fmt, ...);
void  pq_error(const char *fmt, ...);
void  pq_info(const char *fmt, ...);
void  pq_success(const char *fmt, ...);

int   pq_random_bytes(uint8_t *buf, size_t len);

/* Passphrase prompt (no echo). Caller must pq_secure_free the result. */
char *pq_get_passphrase(const char *prompt);
char *pq_get_passphrase_confirm(const char *prompt, const char *confirm_prompt);

/* ASCII armor */
int   pq_armor_encode(const uint8_t *bin, size_t len, char **out_text);
int   pq_armor_decode(const char *text, size_t text_len, uint8_t **out, size_t *out_len);

/* Simple key=value config in ~/.pqcli/config */
char *pq_config_get(const char *key);          /* malloc'd value or NULL */
int   pq_config_set(const char *key, const char *value);

/* Derive output path: replace or append suffix */
char *pq_default_out_path(const char *in, const char *new_suffix);

#endif /* PQCLI_UTILS_H */
