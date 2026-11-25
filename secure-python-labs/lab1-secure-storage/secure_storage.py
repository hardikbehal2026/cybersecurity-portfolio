"""
Lab 1 - Secure Data Storage and Data Integrity Verification
MCSC-6002, Cybersecurity Architecture, Design and Secure Software Development

Standard-library only (Python 3.x), so it runs without extra packages.

What it does
------------
Task 2a: takes user input (interactive, or --username/--email/--password)
         and stores the new user in users_secure.json.
Task 2b: encrypts the password before storage. The demonstration cipher is a
         keystream XOR: a SHA-256 keystream is generated from a key held in
         the LAB_KEY environment variable (default: a lab-only demo key) and
         the result is base64-encoded. This is a lab demonstration, NOT
         production encryption - in production use a vetted library such as
         cryptography (Fernet) and store passwords as a salted hash instead
         of a reversible ciphertext.
Task 2c: computes a SHA-256 integrity hash for every record:
         SHA256(username | email | password_encrypted)
         and stores it as "integrity_hash" in the same record.
Task 2d: verify mode recomputes the hash for every record on read and
         reports OK or TAMPERED for each user.
Task 4a-c: check_tamper mode computes the same SHA-256 hash for every record
         in users.json and in users_tampered.json and reports any user whose
         hash changed. The tampered record in the supplied files is bob.

Usage
-----
    python secure_storage.py add
    python secure_storage.py add --username frank --email frank@example.com --password 'Frank123!'
    python secure_storage.py migrate
    python secure_storage.py verify
    python secure_storage.py verify users_secure.json
    python secure_storage.py check_tamper
    python secure_storage.py check_tamper users.json users_tampered.json
"""

import argparse
import base64
import hashlib
import json
import os
import sys

SECURE_FILE = "users_secure.json"
DEMO_KEY = os.environ.get("LAB_KEY", "lab-demo-key-change-me")


def _keystream(length, key=DEMO_KEY):
    """Generate a SHA-256 keystream of at least `length` bytes."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(f"{key}:{counter}".encode()).digest()
        counter += 1
    return out[:length]


def encrypt_password(password):
    """Task 2b: reversible demonstration encryption, base64 output."""
    data = password.encode()
    stream = _keystream(len(data))
    encrypted = bytes(b ^ s for b, s in zip(data, stream))
    return base64.b64encode(encrypted).decode()


def decrypt_password(ciphertext):
    """Reverse of encrypt_password, used only to prove round-trip works."""
    data = base64.b64decode(ciphertext.encode())
    stream = _keystream(len(data))
    return bytes(b ^ s for b, s in zip(data, stream)).decode()


def integrity_hash(username, email, password_encrypted):
    """Task 2c: SHA-256 integrity value for one record."""
    canonical = f"{username}|{email}|{password_encrypted}"
    return hashlib.sha256(canonical.encode()).hexdigest()


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path, records):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=4)
    print(f"Saved {len(records)} record(s) to {path}")


def secure_record(username, email, password):
    """Build one securely stored record (Tasks 2a, 2b, 2c)."""
    encrypted = encrypt_password(password)
    return {
        "username": username,
        "email": email,
        "password_encrypted": encrypted,
        "integrity_hash": integrity_hash(username, email, encrypted),
    }


def cmd_add(args):
    username = args.username or input("Username: ").strip()
    email = args.email or input("Email: ").strip()
    password = args.password or input("Password: ").strip()
    if not username or not email or not password:
        print("Error: username, email and password are all required.")
        sys.exit(1)
    records = load_json(SECURE_FILE) if os.path.exists(SECURE_FILE) else []
    if any(r["username"] == username for r in records):
        print(f"Error: user '{username}' already exists.")
        sys.exit(1)
    record = secure_record(username, email, password)
    records.append(record)
    save_json(SECURE_FILE, records)
    print(f"Added user '{username}' (Task 2a).")
    print(f"  password_encrypted: {record['password_encrypted']} (Task 2b)")
    print(f"  integrity_hash:     {record['integrity_hash']} (Task 2c)")


def cmd_migrate(args):
    """Convert the original plaintext users.json into users_secure.json."""
    records = load_json("users.json")
    secure = [secure_record(r["username"], r["email"], r["password"])
              for r in records]
    save_json(SECURE_FILE, secure)
    print("Migrated original users.json to users_secure.json:")
    print("  - plaintext passwords are NOT stored in the secure file")
    print("  - every record now has password_encrypted + integrity_hash")


def cmd_verify(args):
    """Task 2d: verify integrity when reading a secure file."""
    path = args.file
    records = load_json(path)
    print(f"Verifying {len(records)} record(s) in {path} ...")
    tampered = []
    for r in records:
        expected = integrity_hash(r["username"], r["email"],
                                  r["password_encrypted"])
        ok = expected == r.get("integrity_hash")
        print(f"  {r['username']:<10} {'OK' if ok else 'TAMPERED'}")
        if not ok:
            tampered.append(r["username"])
    if tampered:
        print(f"Result: TAMPERING DETECTED for: {', '.join(tampered)}")
    else:
        print("Result: all records passed integrity verification.")


def cmd_check_tamper(args):
    """Task 4: compare original vs tampered dataset record by record."""
    original = {r["username"]: r for r in load_json(args.original)}
    tampered_file = load_json(args.tampered)
    print(f"Comparing {args.original} with {args.tampered} ...")
    changed = []
    for r in tampered_file:
        name = r["username"]
        orig = original.get(name)
        if orig is None:
            print(f"  {name:<10} NEW RECORD (not in original)")
            changed.append(name)
            continue
        h_orig = hashlib.sha256(
            f"{orig['username']}|{orig['password']}|{orig['email']}".encode()
        ).hexdigest()
        h_new = hashlib.sha256(
            f"{r['username']}|{r['password']}|{r['email']}".encode()
        ).hexdigest()
        ok = h_orig == h_new
        print(f"  {name:<10} {'OK' if ok else 'TAMPERED - hash changed'}")
        if not ok:
            changed.append(name)
    if changed:
        print(f"Result: tampered record(s) detected: {', '.join(changed)}")
    else:
        print("Result: no tampering detected.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_add = sub.add_parser("add", help="Task 2a: add a user securely")
    p_add.add_argument("--username")
    p_add.add_argument("--email")
    p_add.add_argument("--password")
    sub.add_parser("migrate", help="Convert users.json to users_secure.json")
    p_ver = sub.add_parser("verify", help="Task 2d: verify a secure file")
    p_ver.add_argument("file", nargs="?", default=SECURE_FILE)
    p_chk = sub.add_parser("check_tamper", help="Task 4: detect tampering")
    p_chk.add_argument("original", nargs="?", default="users.json")
    p_chk.add_argument("tampered", nargs="?", default="users_tampered.json")
    args = parser.parse_args()
    if args.command == "add":
        cmd_add(args)
    elif args.command == "migrate":
        cmd_migrate(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "check_tamper":
        cmd_check_tamper(args)


if __name__ == "__main__":
    main()
