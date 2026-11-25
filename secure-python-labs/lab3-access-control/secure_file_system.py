#!/usr/bin/env python3
"""
Secure File System Simulator — MCSC-6002 Lab 3
Access Control & Secure File Operations (healthcare analytics platform).

Implements, using only the Python standard library:
  4.1  Role-based access control (RBAC) with hierarchy
       Admin > Doctor > Nurse > Guest, plus password authentication.
  4.2  Unix-style file permission model (owner / role / other, rwx).
  4.3  Secure file operations: create / read / write / delete.
       Every operation validates RBAC + file permissions, logs the
       activity, and raises an alert when unauthorised.
  4.4  File integrity: SHA-256 hash on create/modify, stored in a
       metadata file, verified on every read; mismatch raises an alert.
  4.5  Audit logging: timestamp, user, action, file, SUCCESS/FAILURE.
  4.6  Unauthorised-access detection: incident logged, alert printed,
       user locked after 3 failed attempts (failed logins and denied
       operations both count). An Admin unlocks the account.

Honest implementation notes (also stated in the completed lab file):
  * Passwords are hashed with PBKDF2-HMAC-SHA256, 200,000 iterations,
    a unique 16-byte salt per user (hashlib). No plaintext password is
    stored. This is the stdlib equivalent of bcrypt, which is not
    installed in this environment; swap hash_password()/verify_password()
    for bcrypt to use it.
  * The audit log and metadata are plain files in the working directory,
    exactly as the brief suggests ("metadata file or dictionary"). They
    are NOT tamper-proof on their own — see the research report,
    Section B, for that vulnerability and Section C for the fix.
  * Permission rule (documented, deterministic): the "role" triplet
    applies to a user whose role is the same as, or higher than, the
    file owner's role in the hierarchy; a lower role falls through to
    the "other" triplet. Admin bypasses file permissions (hierarchy
    top) and every such access is still written to the audit log.
  * Default permissions on a new file: owner "rw-", role "r--",
    other "---" (owner can read/write, same-or-higher roles can read,
    everyone else nothing). Use `chmod` to change them.
  * Lockout is until an Admin runs `unlock <user>`; a successful login
    or a successful authorised operation resets the failure counter.
    An integrity failure (tampered file) does NOT count against the
    reader — the file is at fault, not the user — it is logged and
    alerted instead.

Usage (run from the lab working directory):
  python3 secure_file_system.py register <username> <role>
  python3 secure_file_system.py login <username>
  python3 secure_file_system.py logout
  python3 secure_file_system.py whoami
  python3 secure_file_system.py create <file> <content...>
  python3 secure_file_system.py read <file>
  python3 secure_file_system.py write <file> <content...>
  python3 secure_file_system.py delete <file>
  python3 secure_file_system.py list
  python3 secure_file_system.py perms <file>
  python3 secure_file_system.py chmod <file> <rwxrwxrwx>
  python3 secure_file_system.py verify <file>
  python3 secure_file_system.py metadata
  python3 secure_file_system.py log
  python3 secure_file_system.py users
  python3 secure_file_system.py roles
  python3 secure_file_system.py unlock <username>
  python3 secure_file_system.py help

Passwords are read with getpass (never echoed, never printed). Demo
passwords in the lab screenshots are shown redacted as ********.
"""

import getpass
import hashlib
import hmac
import json
import os
import secrets
import sys
from datetime import datetime

# ---------------------------------------------------------------- files
USERS_DB = "users_db.json"
METADATA_DB = "files_metadata.json"
AUDIT_LOG = "audit.log"
SESSION_FILE = ".session.json"
VAULT_DIR = "vault"

# ---------------------------------------------------------------- roles
ROLE_RANK = {"Guest": 1, "Nurse": 2, "Doctor": 3, "Admin": 4}
ROLES = ["Admin", "Doctor", "Nurse", "Guest"]

# Which roles may attempt each operation at all (before file checks).
ROLE_CAN = {
    "create": {"Admin", "Doctor", "Nurse"},
    "read": {"Admin", "Doctor", "Nurse", "Guest"},
    "write": {"Admin", "Doctor", "Nurse"},
    "delete": {"Admin", "Doctor"},
}

PBKDF2_ITERATIONS = 200_000
MAX_FAILED_ATTEMPTS = 3


# ---------------------------------------------------------------- helpers
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_json(path, default):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def hash_password(password, salt=None):
    """PBKDF2-HMAC-SHA256 with a unique 16-byte salt (stdlib bcrypt stand-in)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    salt = bytes.fromhex(salt_hex)
    _, digest = hash_password(password, salt)
    return hmac.compare_digest(digest, hash_hex)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- audit
def audit(user, action, filename, result, note=""):
    line = (
        f"[{now_str()}] User: {user} | Action: {action} | "
        f"File: {filename} | Result: {result}"
    )
    if note:
        line += f" | {note}"
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line


def alert(message):
    print(f"*** ALERT: {message} ***")


# ---------------------------------------------------------------- session
def current_user():
    data = load_json(SESSION_FILE, {})
    username = data.get("username")
    if not username:
        return None
    users = load_json(USERS_DB, {})
    user = users.get(username)
    if not user:
        return None
    return username, user


def require_login():
    session = current_user()
    if not session:
        print("Access denied: you must log in first (see: login <username>).")
        return None
    username, user = session
    if user.get("locked"):
        print(f"Access denied: account '{username}' is locked. Ask an Admin to unlock it.")
        return None
    return session


def record_failure(username):
    """Count a failed login / denied operation; lock at 3 (brief 4.6)."""
    users = load_json(USERS_DB, {})
    user = users.get(username)
    if not user:
        return
    user["failed_attempts"] = user.get("failed_attempts", 0) + 1
    if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        user["locked"] = True
        save_json(USERS_DB, users)
        alert(
            f"User '{username}' LOCKED after {MAX_FAILED_ATTEMPTS} failed attempts."
        )
    else:
        save_json(USERS_DB, users)
        print(
            f"Failed attempt {user['failed_attempts']}/{MAX_FAILED_ATTEMPTS} "
            f"for user '{username}'."
        )


def reset_failures(username):
    users = load_json(USERS_DB, {})
    user = users.get(username)
    if user and user.get("failed_attempts"):
        user["failed_attempts"] = 0
        save_json(USERS_DB, users)


# ---------------------------------------------------------------- permissions
def check_permission(username, user, filename, operation):
    """Return (allowed, reason). Enforces RBAC first, then file perms.

    operation: 'read' | 'write' | 'delete' | 'create' (create has no file yet).
    Permission letters: read -> 'r', write -> 'w', delete -> 'w'
    (deleting needs write permission on the file, as in Unix).
    """
    role = user["role"]
    if role not in ROLE_CAN.get(operation, set()):
        return False, f"role '{role}' may not {operation} files"
    if operation == "create":
        return True, "role allowed"
    meta = load_json(METADATA_DB, {})
    entry = meta.get(filename)
    if not entry:
        return False, f"file '{filename}' does not exist"
    if role == "Admin":
        return True, "Admin (top of role hierarchy)"
    owner = entry["owner"]
    perms = entry["permissions"]  # {"owner": "rw-", "role": "r--", "other": "---"}
    if username == owner:
        triplet = perms["owner"]
        who = "owner"
    elif ROLE_RANK[role] >= ROLE_RANK[entry["owner_role"]]:
        triplet = perms["role"]
        who = "role (same or higher than owner)"
    else:
        triplet = perms["other"]
        who = "other (lower role than owner)"
    needed = {"read": "r", "write": "w", "delete": "w"}[operation]
    if needed in triplet:
        return True, f"{who} permissions '{triplet}' allow '{needed}'"
    return False, f"{who} permissions '{triplet}' do not allow '{needed}'"


def deny(username, action, filename, reason):
    audit(username, action, filename, "DENIED", reason)
    alert(f"Unauthorized access: user '{username}' tried to {action} "
          f"'{filename}' — {reason}.")
    print(f"Access DENIED: {reason}.")
    record_failure(username)


# ---------------------------------------------------------------- commands
def cmd_register(args):
    if len(args) != 2:
        print("Usage: register <username> <role>   (roles: Admin, Doctor, Nurse, Guest)")
        return
    username, role = args
    if role not in ROLES:
        print(f"Invalid role '{role}'. Roles: {', '.join(ROLES)}.")
        return
    users = load_json(USERS_DB, {})
    session = current_user()
    if users and not (session and session[1]["role"] == "Admin"):
        print("Only an Admin can register new users (an Admin must log in first).")
        return
    if username in users:
        print(f"User '{username}' already exists.")
        return
    password = getpass.getpass(f"Set a password for {username} ({role}): ")
    if len(password) < 8 or not any(c.isdigit() for c in password) \
            or not any(c.isalpha() for c in password):
        print("Password must be at least 8 characters with a letter and a digit.")
        return
    salt, digest = hash_password(password)
    users[username] = {
        "role": role,
        "salt": salt,
        "password_hash": digest,
        "failed_attempts": 0,
        "locked": False,
    }
    save_json(USERS_DB, users)
    audit("system", "REGISTER", "-", "SUCCESS", f"new user {username} ({role})")
    print(f"User '{username}' registered with role '{role}'.")
    print("Password stored as salted PBKDF2-HMAC-SHA256 hash (no plaintext stored).")


def cmd_login(args):
    if len(args) != 1:
        print("Usage: login <username>")
        return
    username = args[0]
    users = load_json(USERS_DB, {})
    user = users.get(username)
    if not user:
        print(f"Login failed: no such user '{username}'.")
        return
    if user.get("locked"):
        print(f"Login failed: account '{username}' is LOCKED. Ask an Admin to unlock it.")
        audit(username, "LOGIN", "-", "DENIED", "account locked")
        return
    password = getpass.getpass(f"Password for {username}: ")
    if not verify_password(password, user["salt"], user["password_hash"]):
        print("Login failed: incorrect password.")
        audit(username, "LOGIN", "-", "DENIED", "incorrect password")
        record_failure(username)
        return
    reset_failures(username)
    save_json(SESSION_FILE, {"username": username})
    audit(username, "LOGIN", "-", "SUCCESS")
    print(f"Login successful. Welcome, {username} ({user['role']}).")


def cmd_logout(_args):
    session = current_user()
    if session:
        audit(session[0], "LOGOUT", "-", "SUCCESS")
        print(f"User '{session[0]}' logged out.")
    if os.path.exists(SESSION_FILE):
        os.remove(SESSION_FILE)


def cmd_whoami(_args):
    session = require_login()
    if session:
        print(f"Logged in as {session[0]} (role: {session[1]['role']}).")


def cmd_roles(_args):
    print("Role hierarchy (highest to lowest): Admin > Doctor > Nurse > Guest")
    print("Higher roles inherit the access of lower roles; Admin may access any file.")
    print()
    print(f"{'Role':<8}{'create':<9}{'read':<7}{'write':<8}{'delete':<8}")
    for role in ROLES:
        print(f"{role:<8}"
              f"{'yes' if role in ROLE_CAN['create'] else 'no':<9}"
              f"{'yes' if role in ROLE_CAN['read'] else 'no':<7}"
              f"{'yes' if role in ROLE_CAN['write'] else 'no':<8}"
              f"{'yes' if role in ROLE_CAN['delete'] else 'no':<8}")
    print("\nFile permissions are checked as well: owner / role / other (rwx).")


def cmd_users(_args):
    session = require_login()
    if not session:
        return
    users = load_json(USERS_DB, {})
    print(f"{'User':<12}{'Role':<9}{'Locked':<9}{'Failed':<8}")
    for name in sorted(users):
        u = users[name]
        print(f"{name:<12}{u['role']:<9}{str(u.get('locked', False)):<9}"
              f"{u.get('failed_attempts', 0):<8}")


def vault_path(filename):
    if os.path.sep in filename or filename in (".", ".."):
        return None
    return os.path.join(VAULT_DIR, filename)


def cmd_create(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if len(args) < 1:
        print("Usage: create <file> <content...>")
        return
    filename = args[0]
    content = " ".join(args[1:]) if len(args) > 1 else ""
    allowed, reason = check_permission(username, user, filename, "create")
    if not allowed:
        deny(username, "CREATE", filename, reason)
        return
    path = vault_path(filename)
    if path is None or os.path.exists(path):
        print(f"Cannot create '{filename}': invalid name or file already exists.")
        audit(username, "CREATE", filename, "DENIED", "invalid name or already exists")
        return
    os.makedirs(VAULT_DIR, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    file_hash = sha256_file(path)
    meta = load_json(METADATA_DB, {})
    meta[filename] = {
        "owner": username,
        "owner_role": user["role"],
        "permissions": {"owner": "rw-", "role": "r--", "other": "---"},
        "sha256": file_hash,
    }
    save_json(METADATA_DB, meta)
    reset_failures(username)
    audit(username, "CREATE", filename, "SUCCESS", f"SHA-256 {file_hash[:16]}...")
    print(f"File '{filename}' created by {username} ({user['role']}).")
    print(f"Owner: {username} | Permissions: rw- r-- --- (owner/role/other)")
    print(f"SHA-256: {file_hash}")
    print("Hash stored in files_metadata.json.")


def cmd_read(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if len(args) != 1:
        print("Usage: read <file>")
        return
    filename = args[0]
    allowed, reason = check_permission(username, user, filename, "read")
    if not allowed:
        deny(username, "READ", filename, reason)
        return
    path = vault_path(filename)
    meta = load_json(METADATA_DB, {}).get(filename)
    if path is None or not os.path.exists(path) or not meta:
        print(f"File '{filename}' not found.")
        audit(username, "READ", filename, "DENIED", "file not found")
        return
    # 4.4 — verify integrity on EVERY read, before returning content.
    current_hash = sha256_file(path)
    if not hmac.compare_digest(current_hash, meta["sha256"]):
        audit(username, "READ", filename, "DENIED",
              "INTEGRITY FAIL: SHA-256 mismatch")
        alert(f"INTEGRITY BREACH in '{filename}': stored hash "
              f"{meta['sha256'][:16]}... != current hash {current_hash[:16]}... "
              f"Content NOT returned.")
        print("Access DENIED: file integrity check failed (hash mismatch).")
        return
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    reset_failures(username)
    audit(username, "READ", filename, "SUCCESS", "SHA-256 verified")
    print(f"--- {filename} (integrity verified, SHA-256 matches) ---")
    print(content)
    print("--- end of file ---")


def cmd_write(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if len(args) < 1:
        print("Usage: write <file> <content...>")
        return
    filename = args[0]
    content = " ".join(args[1:]) if len(args) > 1 else ""
    allowed, reason = check_permission(username, user, filename, "write")
    if not allowed:
        deny(username, "WRITE", filename, reason)
        return
    path = vault_path(filename)
    if path is None or not os.path.exists(path):
        print(f"File '{filename}' not found.")
        audit(username, "WRITE", filename, "DENIED", "file not found")
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    new_hash = sha256_file(path)
    meta = load_json(METADATA_DB, {})
    meta[filename]["sha256"] = new_hash
    save_json(METADATA_DB, meta)
    reset_failures(username)
    audit(username, "WRITE", filename, "SUCCESS", f"new SHA-256 {new_hash[:16]}...")
    print(f"File '{filename}' updated by {username}.")
    print(f"New SHA-256: {new_hash} (stored in files_metadata.json).")


def cmd_delete(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if len(args) != 1:
        print("Usage: delete <file>")
        return
    filename = args[0]
    allowed, reason = check_permission(username, user, filename, "delete")
    if not allowed:
        deny(username, "DELETE", filename, reason)
        return
    path = vault_path(filename)
    if path is None or not os.path.exists(path):
        print(f"File '{filename}' not found.")
        audit(username, "DELETE", filename, "DENIED", "file not found")
        return
    os.remove(path)
    meta = load_json(METADATA_DB, {})
    meta.pop(filename, None)
    save_json(METADATA_DB, meta)
    reset_failures(username)
    audit(username, "DELETE", filename, "SUCCESS")
    print(f"File '{filename}' deleted by {username}.")


def cmd_list(_args):
    session = require_login()
    if not session:
        return
    meta = load_json(METADATA_DB, {})
    if not meta:
        print("No files stored yet.")
        return
    print(f"{'File':<24}{'Owner':<11}{'Role':<8}{'Perms (o/r/oth)':<16}")
    for name in sorted(meta):
        e = meta[name]
        p = e["permissions"]
        print(f"{name:<24}{e['owner']:<11}{e['owner_role']:<8}"
              f"{p['owner']} {p['role']} {p['other']}")


def cmd_perms(args):
    session = require_login()
    if not session:
        return
    if len(args) != 1:
        print("Usage: perms <file>")
        return
    meta = load_json(METADATA_DB, {}).get(args[0])
    if not meta:
        print(f"File '{args[0]}' not found.")
        return
    p = meta["permissions"]
    print(f"File: {args[0]}")
    print(f"Owner: {meta['owner']} ({meta['owner_role']})")
    print(f"Permissions: owner {p['owner']} | role {p['role']} | other {p['other']}")
    print(f"SHA-256: {meta['sha256']}")


def cmd_chmod(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if len(args) != 2:
        print("Usage: chmod <file> <rwxrwxrwx>   e.g. chmod patient_record.txt rw-r--r--")
        return
    filename, perms = args
    if len(perms) != 9 or any(c not in "rwx-" for c in perms):
        print("Permissions must be 9 characters of r, w, x and -, e.g. rw-r--r--.")
        return
    meta = load_json(METADATA_DB, {})
    entry = meta.get(filename)
    if not entry:
        print(f"File '{filename}' not found.")
        return
    if username != entry["owner"] and user["role"] != "Admin":
        deny(username, "CHMOD", filename, "only the owner or an Admin may change permissions")
        return
    entry["permissions"] = {
        "owner": perms[0:3], "role": perms[3:6], "other": perms[6:9],
    }
    save_json(METADATA_DB, meta)
    audit(username, "CHMOD", filename, "SUCCESS", f"perms now {perms}")
    print(f"Permissions for '{filename}' set to {perms} "
          f"(owner {perms[0:3]} | role {perms[3:6]} | other {perms[6:9]}).")


def cmd_verify(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if len(args) != 1:
        print("Usage: verify <file>")
        return
    filename = args[0]
    meta = load_json(METADATA_DB, {}).get(filename)
    path = vault_path(filename)
    if not meta or path is None or not os.path.exists(path):
        print(f"File '{filename}' not found.")
        return
    current = sha256_file(path)
    if hmac.compare_digest(current, meta["sha256"]):
        audit(username, "VERIFY", filename, "SUCCESS", "SHA-256 matches")
        print(f"INTEGRITY OK: '{filename}' hash matches the stored SHA-256.")
        print(f"SHA-256: {current}")
    else:
        audit(username, "VERIFY", filename, "DENIED", "INTEGRITY FAIL: SHA-256 mismatch")
        alert(f"INTEGRITY BREACH in '{filename}': stored {meta['sha256'][:16]}... "
              f"!= current {current[:16]}...")
        print("INTEGRITY FAIL: hash mismatch — file has been tampered with.")


def cmd_metadata(_args):
    session = require_login()
    if not session:
        return
    print("--- files_metadata.json (hashes stored here, separate from file data) ---")
    if os.path.exists(METADATA_DB):
        with open(METADATA_DB, "r", encoding="utf-8") as f:
            print(f.read())
    else:
        print("(no metadata stored yet)")


def cmd_log(_args):
    session = require_login()
    if not session:
        return
    print("--- audit.log ---")
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            print(f.read(), end="")
    else:
        print("(audit log is empty)")


def cmd_unlock(args):
    session = require_login()
    if not session:
        return
    username, user = session
    if user["role"] != "Admin":
        print("Only an Admin can unlock accounts.")
        return
    if len(args) != 1:
        print("Usage: unlock <username>")
        return
    users = load_json(USERS_DB, {})
    target = users.get(args[0])
    if not target:
        print(f"No such user '{args[0]}'.")
        return
    target["locked"] = False
    target["failed_attempts"] = 0
    save_json(USERS_DB, users)
    audit(username, "UNLOCK", "-", "SUCCESS", f"unlocked {args[0]}")
    print(f"User '{args[0]}' unlocked.")


def cmd_help(_args):
    print(__doc__)


COMMANDS = {
    "register": cmd_register, "login": cmd_login, "logout": cmd_logout,
    "whoami": cmd_whoami, "roles": cmd_roles, "users": cmd_users,
    "create": cmd_create, "read": cmd_read, "write": cmd_write,
    "delete": cmd_delete, "list": cmd_list, "perms": cmd_perms,
    "chmod": cmd_chmod, "verify": cmd_verify, "metadata": cmd_metadata,
    "log": cmd_log, "unlock": cmd_unlock, "help": cmd_help,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print("Secure File System Simulator — MCSC-6002 Lab 3")
        print("Run: python3 secure_file_system.py help")
        return 1
    COMMANDS[argv[1]](argv[2:])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
