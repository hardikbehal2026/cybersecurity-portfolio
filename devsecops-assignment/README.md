# DevSecOps assignment

MCSC-6002 mini assignment: security remediation and a secure Python application. Two parts.

## Part A — Fix the vulnerable code (`testCode_fixed.py`)

The original `testCode.py` had three Bandit findings:

| Finding | Severity | Fix |
| --- | --- | --- |
| B605 shell injection — `os.system(f"cat {file_path}")` | High | `os.system` removed entirely; files are read with `open()` after the ID is validated, so user input can never reach a shell. |
| B324 weak crypto — `hashlib.md5` | High | Replaced with SHA-256. |
| B105 hard-coded secret — `SECRET_KEY = "12345"` | Low | Secret key and admin password hash now come from the environment (`APP_ADMIN_PASSWORD_SHA256`), nothing hard-coded. |

After the fixes, Bandit reports **0 issues**.

## Part B — Secure patient-registration app (`patient_app.py`, `test_patient_app.py`)

A console app that registers patients (numeric ID + name) and looks them up by ID:

- **Confidentiality:** names are stored encrypted and only decrypted when shown on screen.
- **Integrity:** a SHA-256 hash is stored with every record and checked on every read. A record whose hash changed is reported, never shown.
- **Input validation:** patient IDs must be numbers only; anything else is rejected with a clear message and the program keeps running.
- **Availability:** bad input, a missing data file, or a damaged data file never crashes the program.

Tests: 5 pytest cases in `test_patient_app.py`, all passing (`pytest test_patient_app.py -v`). Bandit reports 0 issues on both files.

## Honest limits

The encryption in `patient_app.py` is the same teaching demo as the labs (SHA-256 keystream XOR). It shows encrypting at rest, but it is not production cryptography — a real clinic system would use a vetted library, proper key management, and access control. The admin password in Part A is checked as plain SHA-256 from an environment variable; in production it would live in a credential store and use a slow hash like bcrypt or Argon2.
