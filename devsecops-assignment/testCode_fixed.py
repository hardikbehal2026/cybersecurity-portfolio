"""Remediated version of testCode.py (MCSC-6002 Assignment 5%, Part A).

What changed, mapped to the original Bandit findings:
- B105 hard-coded secret: the secret key and the admin password are no
  longer written in the source. The admin password hash comes from the
  environment variable APP_ADMIN_PASSWORD_SHA256.
- B605 shell injection: os.system is gone completely. Patient files are
  read with open() after the ID is checked, so user input can never
  reach a shell.
- B324 weak MD5: replaced with SHA-256.

This is a teaching demo, not production code. In a real system the admin
password would live in a proper credential store, and logins would use a
slow password hash such as bcrypt or Argon2 instead of plain SHA-256.
"""

import hashlib
import hmac
import os
from pathlib import Path

DATA_DIR = Path("data")


def _expected_password_hash():
    """SHA-256 hash of the admin password, read from the environment."""
    return os.environ.get("APP_ADMIN_PASSWORD_SHA256", "")


def login(username, password):
    """Check the login. Only the user 'admin' exists in this demo.

    The entered password is hashed and compared in constant time, so
    the comparison does not leak how much of the password matched.
    """
    expected = _expected_password_hash()
    entered = hashlib.sha256(password.encode()).hexdigest()
    if username == "admin" and expected and hmac.compare_digest(entered, expected):
        print("Login successful")
        return True
    print("Login failed")
    return False


def get_patient_data(patient_id):
    """Read one patient file.

    The ID must be digits only, so nobody can slip in "../" or shell
    characters. The resolved path is also checked to make sure it stays
    inside the data folder.
    """
    if not patient_id.isdigit():
        print("Invalid patient ID: only numbers are allowed.")
        return None
    file_path = (DATA_DIR / (patient_id + ".txt")).resolve()
    if file_path.parent != DATA_DIR.resolve():
        print("Invalid patient ID.")
        return None
    try:
        with open(file_path, encoding="utf-8") as handle:
            content = handle.read()
    except FileNotFoundError:
        print("No record found for that patient ID.")
        return None
    except OSError:
        print("Could not read the patient file.")
        return None
    print(content)
    return content


def generate_hash(data):
    """SHA-256 hex digest of the given text."""
    return hashlib.sha256(data.encode()).hexdigest()


if __name__ == "__main__":
    user = input("Enter username: ")
    entered_password = input("Enter password: ")
    login(user, entered_password)

    pid = input("Enter patient ID: ")
    get_patient_data(pid)
