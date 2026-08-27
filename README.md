# pqcli — Post-Quantum CLI Tool

**Full instruction manual:** [docs/MANUAL.md](docs/MANUAL.md)


Cross-platform C CLI for post-quantum encryption, decryption, signing, and public-key management using [liboqs](https://github.com/open-quantum-safe/liboqs) (NIST ML-KEM / ML-DSA) and [Monocypher](https://monocypher.org/) (XChaCha20-Poly1305 + BLAKE2b).

## Features

- **Hybrid encryption**: PQ KEM (default ML-KEM-768) → shared secret → HKDF-SHA256 → AES-256-GCM
- **Optional signatures** on ciphertext (default ML-DSA-65)
- **Identity management**: generate/store KEM + signature keypairs
- **Keyring**: store contacts’ public keys, fingerprints, and trust flags
- **Fingerprint verification**: out-of-band check before trusting a contact
- **Passphrase-protected keys**: Argon2id + XChaCha20 at rest
- **Multi-recipient encrypt**: one file, many keyring contacts
- **Streaming**: 1 MiB chunks for large files
- **ASCII armor**: `--armor` for email-safe ciphertext
- **Detached sign/verify**: ML-DSA signatures on arbitrary files
- **Trust policy**: encrypt refuses untrusted recipients unless `--force`
- **Profiles**: `nist` / `small` / `paranoid` algorithm sets
- **doctor**: installation and crypto self-check
- **Cross-platform**: Linux, macOS, Windows (CMake + C11)
- **Secure memory**: sensitive buffers wiped via Monocypher `crypto_wipe`

## Dependencies

- CMake ≥ 3.16
- C compiler (GCC, Clang, or MSVC)
- **Monocypher** — vendored at `third_party/monocypher` (no system install needed)
- **liboqs** — git submodule at `third_party/liboqs`

On Ubuntu/Debian: `sudo apt install cmake ninja-build pkg-config git`

No OpenSSL dependency.

## Get the source (with liboqs submodule)

```bash
git clone --recurse-submodules <repo-url> pqcli
# or if already cloned:
cd pqcli && git submodule update --init --recursive
```

`third_party/liboqs` tracks [open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs) (see `.gitmodules`).

## Build

CMake builds liboqs from the submodule by default and links it:

```bash
cd pqcli
mkdir build && cd build
cmake ..
cmake --build .
```

| CMake option | Default | Meaning |
|--------------|---------|---------|
| `PQCLI_BUILD_LIBOQS` | ON | Build from `third_party/liboqs` |
| `PQCLI_USE_SYSTEM_LIBOQS` | OFF | Use system liboqs instead |

```bash
cmake -DPQCLI_USE_SYSTEM_LIBOQS=ON -DPQCLI_BUILD_LIBOQS=OFF ..
```

## Quick start

```bash
# Generate passphrase-protected identity
./pqcli genkey -n alice
# (prompts for passphrase; or PQCLI_PASSPHRASE=... / --no-passphrase)

./pqcli export -n alice -o alice.pqpub

# Bob imports Alice
./pqcli import -f alice.pqpub
./pqcli keyring verify alice && ./pqcli keyring trust alice

./pqcli genkey -n bob
# Encrypt for one or many recipients; optional sign + armor
./pqcli encrypt -r alice -i bob -f secret.txt -o secret.pqcl
./pqcli encrypt -r alice,carol -f big.bin -o big.pqcl --armor

./pqcli decrypt -i alice -f secret.pqcl -o secret.out -s bob
```

## Commands

| Command | Description |
|---------|-------------|
| `genkey -n NAME [--kem ALG] [--sig ALG]` | Create identity |
| `list-keys` | List local identities |
| `export -n NAME -o FILE` | Write `.pqpub` public key file |
| `import -f FILE [-n NAME]` | Add public key to keyring |
| `keyring list` | List contacts |
| `keyring remove NAME` | Remove contact |
| `keyring trust / untrust NAME` | Set trust flag |
| `keyring verify NAME` | Show fingerprint for verification |
| `encrypt -r RECIPIENT -f IN -o OUT [-i IDENTITY]` | Encrypt (optionally sign) |
| `decrypt -i IDENTITY -f IN -o OUT [-s SENDER]` | Decrypt (optionally verify) |
| `list-algs` | List enabled KEMs / signatures |
| `version` / `help` | Version / help |

Recipient can be a keyring name or a path to a `.pqpub` file.

## File formats

### Public key (`.pqpub`)

Text, PEM-style:

```
-----BEGIN PQ PUBLIC KEY-----
Name: alice
Comment: ...
KEM: ML-KEM-768
SIG: ML-DSA-65
Fingerprint: <32 hex chars>
Trusted: yes|no
KEM-PK: <base64>
SIG-PK: <base64>
-----END PQ PUBLIC KEY-----
```

### Ciphertext blob

Binary:

```
magic "PQCL" | version(1) | flags
kem_alg | [sig_alg if signed]
kem_ciphertext | nonce(24) | tag(16) | ciphertext   # XChaCha20-Poly1305
[signature if signed]
[sender fingerprint]
```

## Storage layout

```
~/.pqcli/
  keys/<name>/          # own identities
    meta, kem.sk, sig.sk, kem.pk, sig.pk
  keys/identities       # list of identity names
  keyring/
    index
    <name>.pqpub        # contacts
```

## Security notes

- Prefer NIST-standardized algorithms: **ML-KEM-*** and **ML-DSA-***.
- Always verify fingerprints out-of-band before `keyring trust`.
- Secret keys are stored with mode `0600`; keep the config directory private.
- This is a reference/educational tool. For production systems, consider audited libraries, hardware key storage, and formal threat models.

## License

MIT (same spirit as liboqs examples).
