# Secure Python labs

Six labs from MCSC-6002 (Cybersecurity Architecture, Design & Secure Software Development), all in pure Python standard library — no third-party packages needed.

| Lab | File | What it does |
| --- | --- | --- |
| 1 — Secure storage | `lab1-secure-storage/secure_storage.py` | Stores user records with encrypted passwords and a SHA-256 integrity hash per record; verify mode reports OK or TAMPERED for every record, and a tamper-check mode compares two user files. |
| 2 — Authentication | `lab2-authentication/auth_system.py` | Salted password login with lockout and logging, a file-based 6-digit OTP (30–60 s expiry, max 3 attempts, single-use), and HMAC-signed JWT-style tokens. |
| 3 — Access control | `lab3-access-control/secure_file_system.py` | RBAC file system (Admin > Doctor > Nurse > Guest), Unix-style permissions, SHA-256 integrity checked on every read, audit logging, lockout after 3 failed attempts. |
| 4 — Input validation | `lab4-input-validation/secure_input.py` | Input validation engine, vulnerable vs parameterized SQL (SQL injection demo on a throwaway local database), XSS escaping, format-string demo, and `random` vs `secrets` comparison. |
| 5 — Hashing & anti-tampering | `lab5-hashing-anti-tampering/hash_tamper.py` | SHA-256 hashing, HMAC generation/verification, nonce replay protection, and file tampering detection. |
| 6 — Secure communication | `lab6-secure-communication/secure_comms.py` | RSA key setup, message encryption, and digital signatures (with a tamper demo), RSA session-key exchange, and Diffie-Hellman — implemented from scratch so the pieces are visible. |

## Run them

```bash
python3 secure_storage.py add --username frank --email frank@example.com --password 'Frank123!'
python3 hash_tamper.py demo
python3 secure_comms.py demo3
```

Each file has usage instructions in its header.

## Honest limits

- **Demo crypto, not production crypto.** Lab 1 and the patient app encrypt with a SHA-256 keystream XOR. That shows the idea of encrypting at rest; it is not real encryption. In production, use a vetted library (e.g. `cryptography`/Fernet) and store passwords as salted hashes, never as reversible ciphertext.
- **Stdlib stand-ins.** Where the brief asked for bcrypt or PyJWT, these labs use PBKDF2-HMAC-SHA256 (200,000 iterations, unique salt per user) and an HMAC-SHA256 JWT-style token instead. Same properties, one swappable function each — the headers say exactly where to swap in the real libraries.
- **Teaching implementations.** Lab 6 implements RSA and Diffie-Hellman from scratch (Miller-Rabin primes, PKCS#1 v1.5 padding). The key sizes are real (2048-bit), but the code has not been audited and must not be used for real data.
- **Demo data files.** Some modes expect sample data files from the lab handout (e.g. `users.json` / `users_tampered.json` in Lab 1). Those files are not in this repo; the scripts create their own working files when you run them.
