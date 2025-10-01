# AES-CTR with Hash-Chain Key Derivation (Alice/Bob)

This project implements AES-256 CTR encryption/decryption using a SHA-256 hash chain to derive a fresh 256-bit key per 64-byte message block. Alice encrypts messages using keys derived from a shared seed; Bob derives the same keys to decrypt.

## What this demonstrates
- Deterministic key derivation from a single shared seed using a SHA-256 hash chain.
- One-time-per-block keying: each 64-byte block is encrypted with a different AES-256-CTR key.
- Symmetric encryption workflow between Alice (encryption) and Bob (decryption) without distributing multiple keys.

## How the algorithm works
- Input block size: 64 bytes (512 bits)
- Key size: 32 bytes (256 bits)
- Key derivation (hash chain):
  - `key_0 = SHA256(shared_seed)`
  - `key_{i+1} = SHA256(key_i)`
- Encryption (Alice):
  1) Read `SharedSeedX.txt`, `MessagesX.txt` (4 lines, each 64 bytes)
  2) Compute `key_0`, encrypt line 0 with `key_0` using AES-256-CTR
  3) Compute `key_1`, encrypt line 1 with `key_1`, etc.
  4) Save all keys as hex to `Keys.txt` and ciphertexts as hex to `Ciphertexts.txt`
- Decryption (Bob):
  1) Read `SharedSeedX.txt`, `Ciphertexts.txt`
  2) Compute `key_0`… and decrypt each line with the matching key
  3) Write plaintext lines to `Plaintexts.txt`

### Tiny example
Suppose the seed is `hello` and there are 2 lines: `AAAA...` and `BBBB...` (64 chars each).
- `key_0 = SHA256("hello")`
- Encrypt line 0 with `key_0` → `ct_0`
- `key_1 = SHA256(key_0)`
- Encrypt line 1 with `key_1` → `ct_1`
Alice outputs:
- `Keys.txt` with two 64-hex-char lines (key_0, key_1)
- `Ciphertexts.txt` with two 128-hex-char lines (ct_0, ct_1)
Bob computes the same keys and decrypts `ct_0`, `ct_1` back to the original lines.

## Repository structure
```
HW3/
  README.md
  alice.c                         (encryption; no external helper includes)
  bob.c                           (decryption; no external helper includes)
  tests/
    VerifyingChainCrypt.sh        (Linux verification script)
    TESTING.md                    (Linux setup & test guide)
    SharedSeed1.txt
    SharedSeed2.txt
    SharedSeed3.txt
    Messages1.txt
    Messages2.txt
    Messages3.txt
    CorrectKeys1.txt
    CorrectKeys2.txt
    CorrectKeys3.txt
    CorrectCiphertexts1.txt
    CorrectCiphertexts2.txt
    CorrectCiphertexts3.txt
    CorrectPlaintexts1.txt
    CorrectPlaintexts2.txt
    CorrectPlaintexts3.txt
```

## How to test (Linux)
- Prerequisites:
  - Debian/Ubuntu: `sudo apt update && sudo apt install -y build-essential libssl-dev`
  - Fedora/RHEL: `sudo dnf install -y gcc openssl-devel`
- Run the verification script:
```bash
cd tests
bash VerifyingChainCrypt.sh
```
You should see, for cases 1..3: `KeysX is valid.`, `CiphertextsX is valid.`, `PlaintextsX is valid.`

### Manual test of case 1
```bash
cd tests
gcc ../alice.c -lssl -lcrypto -o alice
gcc ../bob.c -lssl -lcrypto -o bob
./alice SharedSeed1.txt Messages1.txt
./bob SharedSeed1.txt Ciphertexts.txt
cmp -s Keys.txt CorrectKeys1.txt && echo "Keys1 ok" || echo "Keys1 FAIL"
cmp -s Ciphertexts.txt CorrectCiphertexts1.txt && echo "Ciphertexts1 ok" || echo "Ciphertexts1 FAIL"
cmp -s Plaintexts.txt CorrectPlaintexts1.txt && echo "Plaintexts1 ok" || echo "Plaintexts1 FAIL"
```

## Notes
- `alice.c` and `bob.c` each inline the minimal helpers required; no external helper C file is needed.
- AES-256-CTR IV is a fixed deterministic constant (`"1234567890uvwxyz"`) to match the course-provided reference logic and test vectors.
- Each message line must be exactly 64 bytes; newlines are trimmed on read.
