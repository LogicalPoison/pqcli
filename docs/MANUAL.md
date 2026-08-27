# pqcli Instruction Manual

**Version 1.4.0**  
Post-quantum CLI for encryption, decryption, signing, and public-key management.

Built on **liboqs** (NIST ML-KEM / ML-DSA) and **Monocypher** (XChaCha20-Poly1305, BLAKE2b, Argon2id).

---

## Table of contents

1. [Overview](#1-overview)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Concepts](#4-concepts)
5. [Quick start](#5-quick-start)
6. [Smart defaults (UX)](#6-smart-defaults-ux)
7. [Command reference](#7-command-reference)
8. [File formats](#8-file-formats)
9. [Storage layout](#9-storage-layout)
10. [Passphrases and environment](#10-passphrases-and-environment)
11. [Security practices](#11-security-practices)
12. [Troubleshooting](#12-troubleshooting)
13. [Examples](#13-examples)
14. [Bash completion](#14-bash-completion)

---

## 1. Overview

`pqcli` is a command-line tool for post-quantum cryptography:

| Capability | Mechanism |
|------------|-----------|
| Key encapsulation | ML-KEM (and other liboqs KEMs) |
| Digital signatures | ML-DSA (and other liboqs SIGs) |
| Bulk encryption | XChaCha20-Poly1305 (streaming, Monocypher) |
| Key derivation | Keyed BLAKE2b |
| Secret-key protection | Argon2id + XChaCha20-Poly1305 |
| Fingerprints | BLAKE2b-256 (first 16 bytes, hex) |

**Good for:** encrypting files to one or many recipients, signing files, managing identities and a contact keyring.

**Not:** a full OpenPGP/age ecosystem replacement, a network protocol, or a production audit-certified product. Treat it as a serious, usable prototype.

---

## 2. Requirements

- CMake ≥ 3.16  
- C11 compiler (GCC, Clang, or MSVC)  
- Git (liboqs submodule)  
- **No OpenSSL** required for pqcli itself  

```bash
# Debian/Ubuntu
sudo apt install cmake ninja-build pkg-config git build-essential

# macOS
brew install cmake ninja pkg-config git
```

---

## 3. Installation

```bash
git clone --recurse-submodules <repository-url> pqcli
cd pqcli
# or: git submodule update --init --recursive
# or: ./scripts/init-submodules.sh

mkdir build && cd build
cmake ..
cmake --build .
./pqcli doctor
```

| CMake option | Default | Meaning |
|--------------|---------|---------|
| `PQCLI_BUILD_LIBOQS` | `ON` | Build liboqs from `third_party/liboqs` |
| `PQCLI_USE_SYSTEM_LIBOQS` | `OFF` | Use system liboqs |

Monocypher is vendored under `third_party/monocypher/`.

---

## 4. Concepts

### Identity
Your local key set: one **KEM** keypair (receive encrypted data) + one **signature** keypair (sign). Stored under `~/.pqcli/keys/<name>/`. Secrets may be **passphrase-protected**.

### Keyring
Other people’s **public** keys. Import `.pqpub` files, check **fingerprints** out-of-band, then **trust**. Encrypt refuses untrusted contacts unless `--force`.

### Fingerprint
Hex string from `BLAKE2b-256(kem_pk || sig_pk)` (first 16 bytes). Verify before trusting.

### Hybrid encryption
1. Random content key (CEK)  
2. Stream-encrypt file with XChaCha20-Poly1305 (1 MiB chunks)  
3. For each recipient: KEM-encapsulate and wrap the CEK  
4. Optionally sign a content hash with ML-DSA  

### Profiles

| Profile | KEM | Signature |
|---------|-----|-----------|
| `nist` (default) | ML-KEM-768 | ML-DSA-65 |
| `small` | ML-KEM-512 | ML-DSA-44 |
| `paranoid` | ML-KEM-1024 | ML-DSA-87 |

---

## 5. Quick start

```bash
pqcli genkey alice                 # passphrase prompted; becomes default if first
pqcli export alice                 # → alice.pqpub

# On Bob’s machine
pqcli import alice.pqpub
pqcli keyring verify alice         # compare fingerprint out-of-band
pqcli trust alice

pqcli genkey bob
pqcli encrypt secret.txt alice     # → secret.txt.pqcl
pqcli decrypt secret.txt.pqcl      # → secret.txt (default identity)
```

Multi-recipient + armor:

```bash
pqcli encrypt data.bin alice bob --armor   # → data.bin.asc
```

---

## 6. Smart defaults (UX)

You usually do **not** need every flag:

| Situation | What pqcli does |
|-----------|-----------------|
| No `-o` | Infers output: `.pqcl`, `.asc` (armor), `.sig`; on decrypt strips suffix |
| No `-i` | Uses `default_identity` (`pqcli use <name>`) or the only local identity |
| `encrypt file alice bob` | Positional file + recipients (comma form still works: `-r a,b`) |
| `verify file` | Looks for `file.sig` beside it |
| First `genkey` | Sets that identity as default |
| Untrusted recipient | Encrypt blocked unless `trust` or `--force` |

Flags remain fully supported for scripts.

---

## 7. Command reference

```text
pqcli <command> [options] [args]
```

### 7.1 General

| Command | Description |
|---------|-------------|
| `help` | Help overview |
| `version` | Print version |
| `list-algs` | List enabled KEMs and signatures |
| `doctor` | Health check (RNG, algs, Monocypher, keyring) |

### 7.2 Identities

| Command | Description |
|---------|-------------|
| `genkey <name>` | Create identity (`--profile`, `--kem`, `--sig`, `--no-passphrase`) |
| `list-keys` / `keys` | List local identities |
| `export <name> [file]` | Export public key (default: `<name>.pqpub`) |
| `import <file.pqpub>` | Import into keyring (`--trust` to mark trusted) |
| `use <name>` | Set default identity (or show current) |
| `info <name>` | Details for identity or contact |
| `rm-key <name>` | Delete identity (type name to confirm; `--force` skips) |
| `passwd [name]` | Change passphrase |
| `fingerprint <target>` | Print fingerprint (identity, contact, or `.pqpub`) |
| `backup [name] [-o file]` | Encrypted identity backup → `*.pqbackup` |
| `restore <file> [-n name]` | Restore identity from backup |

```bash
pqcli genkey alice --profile paranoid
pqcli export alice
pqcli use alice
pqcli info alice
pqcli passwd alice
pqcli backup alice
pqcli restore alice.pqbackup
```

### 7.3 Keyring

| Command | Description |
|---------|-------------|
| `keyring list` / `contacts` | List contacts |
| `keyring add` / `import` | Import public key |
| `keyring remove <name>` | Remove contact |
| `keyring trust <name>` / `trust <name>` | Mark trusted |
| `keyring untrust <name>` / `untrust <name>` | Clear trust |
| `keyring verify <name>` | Show fingerprint and metadata |

```bash
pqcli import bob.pqpub --trust
pqcli trust carol
pqcli contacts
```

### 7.4 Encrypt / decrypt

```bash
pqcli encrypt <file> <recipient> [recipient2...] [--armor] [-i id] [--force]
pqcli encrypt -f IN -r r1,r2 -o OUT [-i id] [--armor] [--force]

pqcli decrypt <ciphertext> [outfile] [-i id] [-s sender]
```

| Option | Meaning |
|--------|---------|
| `-r` | Recipients: keyring names and/or `.pqpub` paths |
| `-i` | Sign with this identity (encrypt) or decrypt as this identity |
| `-a` / `--armor` | ASCII armor |
| `-F` / `--force` | Allow untrusted recipients |
| `-s` | Sender name for signature check on decrypt |

```bash
pqcli encrypt secret.txt alice bob
pqcli encrypt secret.txt alice --armor
pqcli decrypt secret.txt.pqcl
pqcli decrypt secret.txt.pqcl -s bob
```

### 7.5 Sign / verify

```bash
pqcli sign <file> [-i identity] [-o file.sig]
pqcli verify <file> [file.sig] [pubkey-name-or-.pqpub]
```

```bash
pqcli sign release.tar.gz
pqcli verify release.tar.gz
pqcli verify release.tar.gz release.tar.gz.sig alice.pqpub
```

### 7.6 Ciphertext utilities

| Command | Description |
|---------|-------------|
| `inspect <file>` | Version, signed?, recipients, encoding (no decrypt) |
| `reencrypt <in> -r new1,new2 [-o out]` | Decrypt then encrypt for new recipients |
| `wipe <file>` | Overwrite with random data, then delete |

```bash
pqcli inspect secret.txt.pqcl
pqcli reencrypt secret.txt.pqcl -r carol -o for-carol.pqcl
pqcli wipe secret.txt
```

### 7.7 Config

```bash
pqcli config                     # show default_identity
pqcli config get default_identity
pqcli config set default_identity alice
pqcli config default_identity=alice
```

---

## 8. File formats

### Public key (`.pqpub`)
Text block with name, algorithms, fingerprint, base64 public keys. **No secrets.** Safe to share.

### Ciphertext (binary, **format version 3**)
```text
PQCL | version=3 | flags
num_recipients
  per recipient: fingerprint, kem_alg, kem_ct, wrapped CEK
content_nonce
chunk stream: (len | mac | ct)* until len=0
[optional signature + sender fingerprint]
```

### Armored ciphertext
```text
-----BEGIN PQ MESSAGE-----
...base64...
-----END PQ MESSAGE-----
```

### Detached signature (`.sig`)
```text
-----BEGIN PQ SIGNATURE-----
Alg: ML-DSA-65
Signer: <fingerprint>
Sig: <base64>
-----END PQ SIGNATURE-----
```

### Identity backup (`.pqbackup`)
Armored, passphrase-protected blob of public + secret key material.

**Note:** Format v3 is not compatible with older pqcli ciphertext versions.

---

## 9. Storage layout

```text
~/.pqcli/
├── config                 # default_identity=...
├── keys/
│   ├── identities
│   └── <name>/
│       ├── meta           # kem_alg, sig_alg, protected=yes|no
│       ├── kem.sk         # secret (often Argon2-wrapped)
│       ├── sig.sk
│       ├── kem.pk
│       └── sig.pk
└── keyring/
    ├── index
    └── <name>.pqpub
```

Secret files use mode `0600` on Unix.

---

## 10. Passphrases and environment

Resolution order:

1. `--passphrase` (if given with a value)  
2. **`PQCLI_PASSPHRASE`** environment variable  
3. Interactive prompt (echo disabled when possible)  

Argon2id for key protection: **16 MiB**, **3** passes, **1** lane.

Prefer env or prompt over putting secrets on the command line (shell history / process list).

---

## 11. Security practices

1. Verify fingerprints before `trust`.  
2. Prefer passphrase-protected identities (default).  
3. Avoid `--force` unless you accept the risk.  
4. Protect `~/.pqcli` (permissions, disk encryption, backups).  
5. Use `nist` or `paranoid` for serious data.  
6. Use `wipe` for local plaintext you must discard.  
7. Keep backups (`pqcli backup`) offline and passphrase-strong.  
8. This is not a substitute for a formal security audit.

---

## 12. Troubleshooting

| Symptom | Try |
|---------|-----|
| liboqs missing at configure | `git submodule update --init --recursive` |
| Default alg missing in `doctor` | Rebuild liboqs with ML-KEM / ML-DSA enabled |
| `passphrase required` | Prompt, `--passphrase`, or `PQCLI_PASSPHRASE` |
| `not trusted` on encrypt | `pqcli trust <name>` or `--force` |
| Decryption failed | Wrong identity/passphrase, or not a recipient |
| Signature INVALID | Wrong public key or modified file |
| Permission denied | Own `~/.pqcli`; secrets should be `0600` |

---

## 13. Examples

**Team multi-recipient**
```bash
pqcli encrypt build.zip alice bob carol -i release-bot
```

**Email-friendly armor**
```bash
pqcli encrypt letter.txt alice --armor
pqcli decrypt letter.txt.asc
```

**Signed release**
```bash
pqcli sign app.tar.gz
pqcli export vendor
# ship app.tar.gz, app.tar.gz.sig, vendor.pqpub
pqcli verify app.tar.gz app.tar.gz.sig vendor.pqpub
```

**Rotate recipients**
```bash
pqcli reencrypt old.pqcl -r newperson -o new.pqcl
```

**Cold-storage identity**
```bash
pqcli genkey vault --profile paranoid
pqcli backup vault -o vault.pqbackup
# store vault.pqbackup offline; wipe working copies carefully
```

---

## 14. Bash completion

```bash
source scripts/pqcli-completion.bash
```

---

## License

MIT (see `LICENSE`). liboqs and Monocypher keep their upstream licenses.

---

*End of manual — version 1.4.0*
