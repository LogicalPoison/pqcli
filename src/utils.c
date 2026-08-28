#define _POSIX_C_SOURCE 200809L
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#ifndef _WIN32
#include <termios.h>
#endif

#include "monocypher.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#include <direct.h>
#include <io.h>
/* use _mkdir(path) on Windows; do not redefine mkdir macro */
/* MSVC links bcrypt via pragma; MinGW needs -lbcrypt in CMake */
#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif
#else
#include <unistd.h>
#include <pwd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

void *pq_secure_malloc(size_t len) {
    void *p = calloc(1, len);
    return p;
}

void pq_secure_free(void *ptr, size_t len) {
    if (!ptr) return;
    crypto_wipe(ptr, len);
    free(ptr);
}

void pq_memzero(void *ptr, size_t len) {
    if (ptr) crypto_wipe(ptr, len);
}

int pq_read_file(const char *path, uint8_t **out, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return -1;
    }
    buf[sz] = 0;
    fclose(f);
    *out = buf;
    *out_len = (size_t)sz;
    return 0;
}

int pq_write_file(const char *path, const uint8_t *data, size_t len, mode_t mode) {
#ifdef _WIN32
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(data, 1, len, f) != len) { fclose(f); return -1; }
    fclose(f);
    (void)mode;
    return 0;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    size_t written = 0;
    while (written < len) {
        ssize_t n = write(fd, data + written, len - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }
    close(fd);
    chmod(path, mode);
    return 0;
#endif
}

int pq_file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

char *pq_get_home_dir(void) {
#ifdef _WIN32
    const char *h = getenv("USERPROFILE");
    if (!h) h = getenv("HOME");
#else
    const char *h = getenv("HOME");
    if (!h) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) h = pw->pw_dir;
    }
#endif
    if (!h) return NULL;
    return strdup(h);
}

char *pq_get_config_dir(void) {
    char *home = pq_get_home_dir();
    if (!home) return NULL;
    char *cfg = pq_path_join(home, PQCLI_HOME_DIR);
    free(home);
    return cfg;
}

char *pq_path_join(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    int need_sep = (la > 0 && a[la-1] != '/' && a[la-1] != '\\');
    char *p = malloc(la + lb + 2);
    if (!p) return NULL;
    memcpy(p, a, la);
    if (need_sep) p[la++] = '/';
    memcpy(p + la, b, lb + 1);
    return p;
}

int pq_ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        return -1;
    }
#ifdef _WIN32
    return _mkdir(path) == 0 ? 0 : -1;
#else
    return mkdir(path, 0700) == 0 ? 0 : -1;
#endif
}

char *pq_bin_to_hex(const uint8_t *bin, size_t len) {
    static const char hex[] = "0123456789abcdef";
    char *out = malloc(len * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = hex[(bin[i] >> 4) & 0xf];
        out[i*2+1] = hex[bin[i] & 0xf];
    }
    out[len*2] = 0;
    return out;
}

int pq_hex_to_bin(const char *hex, uint8_t **out, size_t *out_len) {
    size_t n = strlen(hex);
    if (n % 2) return -1;
    size_t len = n / 2;
    uint8_t *buf = malloc(len);
    if (!buf) return -1;
    for (size_t i = 0; i < len; i++) {
        unsigned int v;
        if (sscanf(hex + i*2, "%2x", &v) != 1) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)v;
    }
    *out = buf;
    *out_len = len;
    return 0;
}

/* Minimal base64 (RFC 4648) — no OpenSSL */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *pq_bin_to_b64(const uint8_t *bin, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;
    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? bin[i++] : 0;
        uint32_t b = i < len ? bin[i++] : 0;
        uint32_t c = i < len ? bin[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(triple >> 18) & 0x3f];
        out[j++] = b64_table[(triple >> 12) & 0x3f];
        out[j++] = b64_table[(triple >> 6) & 0x3f];
        out[j++] = b64_table[triple & 0x3f];
    }
    size_t mod = len % 3;
    if (mod == 1) { out[out_len - 1] = '='; out[out_len - 2] = '='; }
    else if (mod == 2) { out[out_len - 1] = '='; }
    out[out_len] = 0;
    return out;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int pq_b64_to_bin(const char *b64, uint8_t **out, size_t *out_len) {
    size_t in_len = strlen(b64);
    while (in_len > 0 && (b64[in_len-1] == '=' || b64[in_len-1] == '\n' ||
                          b64[in_len-1] == '\r' || b64[in_len-1] == ' '))
        in_len--;
    /* filter whitespace roughly by counting valid chars */
    size_t valid = 0;
    for (size_t i = 0; b64[i]; i++)
        if (b64_val(b64[i]) >= 0) valid++;
    size_t max_out = (valid / 4) * 3 + 3;
    uint8_t *buf = malloc(max_out);
    if (!buf) return -1;

    int val = 0, valb = -8;
    size_t o = 0;
    for (size_t i = 0; b64[i]; i++) {
        int d = b64_val(b64[i]);
        if (d < 0) continue;
        val = (val << 6) | d;
        valb += 6;
        if (valb >= 0) {
            buf[o++] = (uint8_t)((val >> valb) & 0xff);
            valb -= 8;
        }
    }
    *out = buf;
    *out_len = o;
    return 0;
}

char *pq_fingerprint(const uint8_t *pk, size_t pk_len) {
    uint8_t hash[32];
    crypto_blake2b(hash, 32, pk, pk_len);
    /* first 16 bytes as hex (32 chars) */
    return pq_bin_to_hex(hash, 16);
}

void pq_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

void pq_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

void pq_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

void pq_success(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[+] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

int pq_random_bytes(uint8_t *buf, size_t len) {
#ifdef _WIN32
    NTSTATUS st = BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;
#elif defined(__linux__)
    size_t got = 0;
    while (got < len) {
        ssize_t n = getrandom(buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            /* fallback to /dev/urandom */
            break;
        }
        got += (size_t)n;
    }
    if (got == len) return 0;
#endif
#ifndef _WIN32
    {
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) return -1;
        size_t got = 0;
        while (got < len) {
            ssize_t n = read(fd, buf + got, len - got);
            if (n < 0) {
                if (errno == EINTR) continue;
                close(fd);
                return -1;
            }
            if (n == 0) { close(fd); return -1; }
            got += (size_t)n;
        }
        close(fd);
        return 0;
    }
#endif
}

/* ---- passphrase (no echo) ---- */
char *pq_get_passphrase(const char *prompt)
{
    fprintf(stderr, "%s", prompt ? prompt : "Passphrase: ");
    fflush(stderr);

#ifdef _WIN32

    HANDLE hstdin = GetStdHandle(STD_INPUT_HANDLE);
    if (hstdin == INVALID_HANDLE_VALUE || hstdin == NULL)
        return NULL;

    DWORD old_mode;
    if (!GetConsoleMode(hstdin, &old_mode))
        return NULL;

    DWORD new_mode = old_mode;
    new_mode &= ~ENABLE_ECHO_INPUT;
    new_mode |= ENABLE_LINE_INPUT;

    if (!SetConsoleMode(hstdin, new_mode))
        return NULL;

    char buf[512];
    DWORD chars_read = 0;

    BOOL ok = ReadConsoleA(
        hstdin,
        buf,
        sizeof(buf) - 1,
        &chars_read,
        NULL
    );

    /* Always restore console state */
    SetConsoleMode(hstdin, old_mode);

    fprintf(stderr, "\n");

    if (!ok)
        return NULL;

    buf[chars_read] = '\0';

    /* Remove CR/LF */
    size_t n = strlen(buf);
    while (n > 0 &&
           (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }

    char *out = pq_secure_malloc(n + 1);
    if (!out) {
        pq_memzero(buf, sizeof(buf));
        return NULL;
    }

    memcpy(out, buf, n + 1);

    pq_memzero(buf, sizeof(buf));

    return out;

#else

    struct termios oldt, newt;
    int fd = STDIN_FILENO;

    int have_tio = (tcgetattr(fd, &oldt) == 0);

    if (have_tio) {
        newt = oldt;
        newt.c_lflag &= ~(ECHO);

        if (tcsetattr(fd, TCSAFLUSH, &newt) != 0)
            have_tio = 0;
    }

    char *line = NULL;
    size_t cap = 0;

    ssize_t n = getline(&line, &cap, stdin);

    /* Restore terminal even if getline() failed */
    if (have_tio)
        tcsetattr(fd, TCSAFLUSH, &oldt);

    fprintf(stderr, "\n");

    if (n < 0) {
        if (line) {
            pq_memzero(line, cap);
            free(line);
        }
        return NULL;
    }

    while (n > 0 &&
           (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[--n] = '\0';
    }

    char *out = pq_secure_malloc((size_t)n + 1);

    if (!out) {
        pq_memzero(line, cap);
        free(line);
        return NULL;
    }

    memcpy(out, line, (size_t)n + 1);

    pq_memzero(line, cap);
    free(line);

    return out;

#endif
}

char *pq_get_passphrase_confirm(const char *prompt, const char *confirm_prompt) {
    char *a = pq_get_passphrase(prompt);
    if (!a) return NULL;
    char *b = pq_get_passphrase(confirm_prompt ? confirm_prompt : "Confirm passphrase: ");
    if (!b) { pq_secure_free(a, strlen(a)); return NULL; }
    if (strcmp(a, b) != 0) {
        pq_error("passphrases do not match");
        pq_secure_free(a, strlen(a));
        pq_secure_free(b, strlen(b));
        return NULL;
    }
    pq_secure_free(b, strlen(b));
    return a;
}

/* ---- ASCII armor ---- */
int pq_armor_encode(const uint8_t *bin, size_t len, char **out_text) {
    char *b64 = pq_bin_to_b64(bin, len);
    if (!b64) return -1;
    size_t b64len = strlen(b64);
    /* wrap at 64 cols */
    size_t lines = (b64len + 63) / 64;
    size_t out_cap = 64 + b64len + lines + 64;
    char *out = malloc(out_cap);
    if (!out) { free(b64); return -1; }
    char *p = out;
    p += sprintf(p, "-----BEGIN PQ MESSAGE-----\n");
    for (size_t i = 0; i < b64len; i += 64) {
        size_t n = b64len - i;
        if (n > 64) n = 64;
        memcpy(p, b64 + i, n);
        p += n;
        *p++ = '\n';
    }
    p += sprintf(p, "-----END PQ MESSAGE-----\n");
    *p = 0;
    free(b64);
    *out_text = out;
    return 0;
}

int pq_armor_decode(const char *text, size_t text_len, uint8_t **out, size_t *out_len) {
    (void)text_len;
    const char *begin = strstr(text, "-----BEGIN PQ MESSAGE-----");
    const char *end = strstr(text, "-----END PQ MESSAGE-----");
    if (!begin || !end || end <= begin) return -1;
    begin = strchr(begin, '\n');
    if (!begin || begin >= end) return -1;
    begin++;
    /* collect base64 chars */
    size_t cap = (size_t)(end - begin) + 1;
    char *b64 = malloc(cap);
    if (!b64) return -1;
    size_t j = 0;
    for (const char *q = begin; q < end; q++) {
        if (*q == '\n' || *q == '\r' || *q == ' ' || *q == '\t') continue;
        b64[j++] = *q;
    }
    b64[j] = 0;
    int r = pq_b64_to_bin(b64, out, out_len);
    free(b64);
    return r;
}


char *pq_config_get(const char *key) {
    char *cfgdir = pq_get_config_dir();
    if (!cfgdir) return NULL;
    char *path = pq_path_join(cfgdir, PQCLI_CONFIG_FILE);
    free(cfgdir);
    if (!path) return NULL;
    uint8_t *raw = NULL; size_t len = 0;
    if (pq_read_file(path, &raw, &len) != 0) { free(path); return NULL; }
    free(path);
    char *result = NULL;
    size_t klen = strlen(key);
    char *line = (char *)raw;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        size_t L = strlen(line);
        if (L && line[L-1] == '\r') line[L-1] = 0;
        if (strncmp(line, key, klen) == 0 && line[klen] == '=') {
            result = strdup(line + klen + 1);
            break;
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(raw);
    return result;
}

int pq_config_set(const char *key, const char *value) {
    char *cfgdir = pq_get_config_dir();
    if (!cfgdir) return -1;
    if (pq_ensure_dir(cfgdir) != 0) { free(cfgdir); return -1; }
    char *path = pq_path_join(cfgdir, PQCLI_CONFIG_FILE);
    free(cfgdir);
    if (!path) return -1;

    /* load existing lines, replace or append key */
    char *content = NULL;
    size_t cap = 0, used = 0;
    uint8_t *raw = NULL; size_t len = 0;
    int found = 0;
    if (pq_read_file(path, &raw, &len) == 0) {
        char *line = (char *)raw;
        while (line && *line) {
            char *nl = strchr(line, '\n');
            if (nl) *nl = 0;
            size_t L = strlen(line);
            if (L && line[L-1] == '\r') line[L-1] = 0;
            size_t klen = strlen(key);
            int is_key = (strncmp(line, key, klen) == 0 && line[klen] == '=');
            const char *out_line;
            char buf[1024];
            if (is_key) {
                snprintf(buf, sizeof(buf), "%s=%s", key, value);
                out_line = buf;
                found = 1;
            } else {
                out_line = line;
            }
            size_t need = strlen(out_line) + 2;
            if (used + need > cap) {
                cap = (cap ? cap * 2 : 256) + need;
                char *n = realloc(content, cap);
                if (!n) { free(content); free(raw); free(path); return -1; }
                content = n;
            }
            used += (size_t)sprintf(content + used, "%s\n", out_line);
            if (!nl) break;
            line = nl + 1;
        }
        free(raw);
    }
    if (!found) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s=%s\n", key, value);
        size_t need = strlen(buf) + 1;
        if (used + need > cap) {
            cap = used + need + 64;
            char *n = realloc(content, cap);
            if (!n) { free(content); free(path); return -1; }
            content = n;
        }
        memcpy(content + used, buf, need);
        used += strlen(buf);
    }
    int r = pq_write_file(path, (uint8_t *)(content ? content : ""), used, 0600);
    free(content);
    free(path);
    return r;
}

char *pq_default_out_path(const char *in, const char *new_suffix) {
    /* If in ends with a known ciphertext suffix, strip it for decrypt-style outs */
    const char *known[] = { ".pqcl", ".asc", ".sig", NULL };
    size_t inlen = strlen(in);
    char *base = NULL;
    for (int i = 0; known[i]; i++) {
        size_t sl = strlen(known[i]);
        if (inlen > sl && strcmp(in + inlen - sl, known[i]) == 0) {
            base = malloc(inlen - sl + 1);
            memcpy(base, in, inlen - sl);
            base[inlen - sl] = 0;
            break;
        }
    }
    if (!base) base = strdup(in);
    if (!base) return NULL;
    if (!new_suffix || !new_suffix[0]) return base;
    size_t n = strlen(base) + strlen(new_suffix) + 1;
    char *out = malloc(n);
    if (!out) { free(base); return NULL; }
    snprintf(out, n, "%s%s", base, new_suffix);
    free(base);
    return out;
}
