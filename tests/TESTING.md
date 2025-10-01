## AES-CTR Hash-Chain Testing Guide (Linux)

This guide shows how to compile and test `alice.c` and `bob.c` on Linux using the provided verification script and test vectors.

### 1) Requirements
- GCC toolchain
- OpenSSL development libraries (libssl, libcrypto)

On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y build-essential libssl-dev
```

On Fedora/RHEL/CentOS:
```bash
sudo dnf install -y gcc openssl-devel
```

### 2) Directory Layout
Ensure the following files are in place with the new structure:
- Project root: `alice.c`, `bob.c`
- This folder (`tests/`): `VerifyingChainCrypt.sh`, and all test vectors: `SharedSeed1.txt..3`, `Messages1.txt..3`, `CorrectKeys1.txt..3`, `CorrectCiphertexts1.txt..3`, `CorrectPlaintexts1.txt..3`

### 3) Run the full verification
From inside `tests/`:
```bash
bash VerifyingChainCrypt.sh
```

What it does:
- Compiles `alice` and `bob` with `-lssl -lcrypto`
- For i in 1..3:
  - Runs `./alice SharedSeed$i.txt Messages$i.txt` → writes `Keys.txt`, `Ciphertexts.txt`
  - Runs `./bob SharedSeed$i.txt Ciphertexts.txt` → writes `Plaintexts.txt`
  - Compares outputs to `Correct*.txt`

Expected output example:
```
Testing case 1...
Verifying outputs for test case 1...
Keys1 is valid.
Ciphertexts1 is valid.
Plaintexts1 is valid.
...
```

### 4) Manual one-off test (optional)
Compile manually (from inside `tests/`):
```bash
gcc ../alice.c -lssl -lcrypto -o alice
gcc ../bob.c -lssl -lcrypto -o bob
```

Run case 1 only:
```bash
./alice SharedSeed1.txt Messages1.txt
./bob SharedSeed1.txt Ciphertexts.txt

cmp -s Keys.txt CorrectKeys1.txt && echo "Keys1 ok" || echo "Keys1 FAIL"
cmp -s Ciphertexts.txt CorrectCiphertexts1.txt && echo "Ciphertexts1 ok" || echo "Ciphertexts1 FAIL"
cmp -s Plaintexts.txt CorrectPlaintexts1.txt && echo "Plaintexts1 ok" || echo "Plaintexts1 FAIL"
```

### 5) Troubleshooting
- Missing OpenSSL headers/libraries:
  - Install `libssl-dev` (Debian/Ubuntu) or `openssl-devel` (Fedora/RHEL).
- Permission denied when running scripts:
```bash
chmod +x VerifyingChainCrypt.sh
```
- Clean old outputs before re-running:
```bash
rm -f Keys.txt Ciphertexts.txt Plaintexts.txt alice bob
```

### 6) Notes
- `alice.c` writes `Keys.txt` and `Ciphertexts.txt` in hex per spec.
- `bob.c` parses hex safely and writes `Plaintexts.txt` as ASCII text.
- Both programs use SHA-256 hash chaining and AES-256-CTR with OpenSSL.


