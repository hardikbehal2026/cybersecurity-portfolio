"""
Lab 2 - Authentication: Passwords, File-Based OTP and Tokens
MCSC-6002, Cybersecurity Architecture, Design and Secure Software
Development (3.5%). Due Sat Nov 14, 2026, 11:59 PM EST.

Standard-library only (Python 3.x), so it runs without extra packages.

IMPORTANT - stdlib equivalents, stated honestly
------------------------------------------------
The brief's Pre-Lab Preparation says "pip install bcrypt pyjwt".
bcrypt and PyJWT are NOT installed in this VM, so this lab uses
stdlib equivalents that provide the same properties, in one
swappable function each:
  * Salted hashing: hashlib.pbkdf2_hmac, SHA-256, 200,000 iterations,
    a unique 16-byte salt per user (see hash_password()). This is a
    bcrypt-equivalent key-stretching construction; in production use
    bcrypt (or Argon2) by replacing hash_password()/verify_password().
  * Token: an HMAC-SHA256 signed JWT-style token
    (header.payload.signature, base64url, see issue_token()) verified
    with a secret key in token_secret.key. This is NOT an unsigned
    bearer token: a forged or altered token fails signature checks.
    In production use PyJWT by replacing issue_token()/validate_token().
  * OTP: secrets module (cryptographically secure), 6 digits.

Files (all created in the folder this script lives in)
-----------------------------------------------------
  users_db.json   - username -> salt (hex) + password hash (hex) only.
                    NO plaintext password is ever stored.
  otp_store.txt   - one line per OTP: username|otp|expiry_epoch|
                    attempts|used   (username, OTP value and expiry
                    timestamp are the fields the brief requires).
  tokens.txt      - one line per token: token|username|expiry_epoch|
                    revoked
  token_secret.key - HMAC signing key, generated once (32 random bytes).
  auth_log.txt    - audit log: every login attempt (success / failure /
                    lock), OTP event, token issue / revoke, and every
                    protected-resource access attempt, with timestamp.

Demo / timing overrides (defaults are the lab values)
----------------------------------------------------
  LAB2_LOCK_SECONDS   default 600  (10 min lock after 5 failed logins)
  LAB2_OTP_SECONDS    default 60   (OTP expires in 60 s, inside 30-60 s)
  LAB2_TOKEN_SECONDS  default 900  (token expires in 15 min)
Set an override only to demonstrate expiry/lockout in a reasonable
time while testing; the screenshots in Lab2_completed.docx say
where an override was used.

Password policy (per the brief: "alphanumeric password")
-------------------------------------------------------
Minimum 8 characters, letters and digits only, at least one letter
and at least one digit.

Usage
-----
    python auth_system.py register --username alice --password Alice1234
    python auth_system.py login    --username alice --password Alice1234
    python auth_system.py otp-verify --username alice --otp 123456
    python auth_system.py access   --token <token>
    python auth_system.py access                (no token -> refused)
    python auth_system.py revoke   --token <token>
    python auth_system.py logout   --token <token>
    python auth_system.py status   --username alice
    python auth_system.py show-db
    python auth_system.py show-log
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
USERS_FILE = BASE / "users_db.json"
OTP_FILE = BASE / "otp_store.txt"
TOKENS_FILE = BASE / "tokens.txt"
SECRET_FILE = BASE / "token_secret.key"
LOG_FILE = BASE / "auth_log.txt"

MAX_FAILED_LOGINS = 5
MAX_OTP_ATTEMPTS = 3
LOCK_SECONDS = int(os.environ.get("LAB2_LOCK_SECONDS", "600"))
OTP_SECONDS = int(os.environ.get("LAB2_OTP_SECONDS", "60"))
TOKEN_SECONDS = int(os.environ.get("LAB2_TOKEN_SECONDS", "900"))
HASH_ITERATIONS = 200_000


def now_ts():
    return time.time()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def log(event):
    """Task 1f: log all login attempts (and OTP / token events)."""
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now_iso()}] {event}\n")


# ---------------------------------------------------------------- hashing
def hash_password(password, salt=None):
    """Task 1a: salted hashing (PBKDF2-HMAC-SHA256, bcrypt-equivalent).

    Returns (salt_hex, hash_hex). A fresh 16-byte salt is generated
    for every user, so two users with the same password get
    different hashes.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, HASH_ITERATIONS)
    return salt.hex(), digest.hex()


def verify_password(password, salt_hex, hash_hex):
    """Task 1c: validate a password against the stored hash.

    Recomputes the hash with the stored salt and compares it in
    constant time, so the stored hash is never reversed and no
    plaintext password is ever compared or stored.
    """
    salt = bytes.fromhex(salt_hex)
    _, candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, hash_hex)


def valid_password_policy(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not password.isalnum():
        return False, "Password must be alphanumeric (letters and digits only)."
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one digit."
    return True, ""


# ---------------------------------------------------------------- users
def load_users():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=4), encoding="utf-8")


# ---------------------------------------------------------------- OTP
def read_otp_lines():
    if not OTP_FILE.exists():
        return []
    return [ln.rstrip("\n") for ln in OTP_FILE.read_text(
        encoding="utf-8").splitlines() if ln.strip()]


def write_otp_lines(lines):
    OTP_FILE.write_text("\n".join(lines) + ("\n" if lines else ""),
                        encoding="utf-8")


def generate_otp(username):
    """Task 2: 6-digit OTP from the cryptographically secure
    secrets module, stored in otp_store.txt with username, OTP
    value and expiration timestamp."""
    otp = f"{secrets.randbelow(900000) + 100000:06d}"
    expiry = int(now_ts()) + OTP_SECONDS
    lines = [ln for ln in read_otp_lines()
             if not ln.startswith(username + "|")]
    lines.append(f"{username}|{otp}|{expiry}|0|no")
    write_otp_lines(lines)
    return otp, expiry


def find_otp(username):
    for ln in read_otp_lines():
        parts = ln.split("|")
        if len(parts) == 5 and parts[0] == username:
            return parts
    return None


def remove_otp(username):
    write_otp_lines([ln for ln in read_otp_lines()
                     if not ln.startswith(username + "|")])


def update_otp(username, otp, expiry, attempts, used):
    lines = []
    for ln in read_otp_lines():
        if ln.startswith(username + "|"):
            lines.append(f"{username}|{otp}|{expiry}|{attempts}|{used}")
        else:
            lines.append(ln)
    write_otp_lines(lines)


# ---------------------------------------------------------------- tokens
def get_secret():
    if not SECRET_FILE.exists():
        SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
    return SECRET_FILE.read_text(encoding="utf-8").strip().encode()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def issue_token(username):
    """Task 3: HMAC-SHA256 signed JWT-style token, issued only
    after successful OTP verification. Stored in tokens.txt."""
    header = _b64url(json.dumps(
        {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(
        {"sub": username, "iat": int(now_ts()),
         "exp": int(now_ts()) + TOKEN_SECONDS},
        separators=(",", ":")).encode())
    signature = _b64url(hmac.new(
        get_secret(), f"{header}.{payload}".encode(),
        hashlib.sha256).digest())
    token = f"{header}.{payload}.{signature}"
    expiry = int(now_ts()) + TOKEN_SECONDS
    with open(TOKENS_FILE, "a", encoding="utf-8") as f:
        f.write(f"{token}|{username}|{expiry}|no\n")
    return token, expiry


def read_token_lines():
    if not TOKENS_FILE.exists():
        return []
    return [ln.rstrip("\n") for ln in TOKENS_FILE.read_text(
        encoding="utf-8").splitlines() if ln.strip()]


def validate_token(token):
    """Task 3: token validation - signature, expiry and revocation.

    Returns (username, error). A token is valid only if its
    signature verifies with the server secret, it has not expired,
    and it has not been revoked in tokens.txt.
    """
    if not token:
        return None, "Invalid Token. Login Required."
    parts = token.split(".")
    if len(parts) != 3:
        return None, "Invalid Token. Login Required."
    header, payload, signature = parts
    expected = _b64url(hmac.new(
        get_secret(), f"{header}.{payload}".encode(),
        hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None, "Invalid Token. Login Required."
    try:
        claims = json.loads(_b64url_decode(payload))
    except Exception:
        return None, "Invalid Token. Login Required."
    if claims.get("exp", 0) <= int(now_ts()):
        return None, "Invalid Token. Login Required."
    for ln in read_token_lines():
        fields = ln.split("|")
        if len(fields) == 4 and fields[0] == token:
            if fields[3] == "yes":
                return None, "Invalid Token. Login Required."
            return claims.get("sub"), None
    return None, "Invalid Token. Login Required."


def revoke_token(token):
    lines = []
    changed = False
    for ln in read_token_lines():
        fields = ln.split("|")
        if len(fields) == 4 and fields[0] == token and fields[3] == "no":
            lines.append(f"{fields[0]}|{fields[1]}|{fields[2]}|yes")
            changed = True
        else:
            lines.append(ln)
    if lines:
        TOKENS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed


# ---------------------------------------------------------------- commands
def cmd_register(args):
    ok, msg = valid_password_policy(args.password)
    if not ok:
        print(f"Registration failed: {msg}")
        sys.exit(1)
    users = load_users()
    if args.username in users:
        print(f"Error: user '{args.username}' already exists.")
        sys.exit(1)
    salt_hex, hash_hex = hash_password(args.password)
    users[args.username] = {
        "salt": salt_hex,
        "password_hash": hash_hex,
        "iterations": HASH_ITERATIONS,
        "failed_attempts": 0,
        "locked_until": 0,
    }
    save_users(users)
    log(f"REGISTER {args.username} (salted hash stored, no plaintext)")
    print(f"User '{args.username}' registered.")
    print("  Password stored as salted hash only - no plaintext password stored.")
    print(f"  salt: {salt_hex}")
    print(f"  password_hash: {hash_hex[:32]}... (SHA-256 PBKDF2, "
          f"{HASH_ITERATIONS} iterations)")


def cmd_login(args):
    users = load_users()
    user = users.get(args.username)
    if user is None:
        log(f"LOGIN_FAIL {args.username} (unknown user)")
        print("Login Failed. Invalid Username or Password. Please try again.")
        sys.exit(1)
    if user.get("locked_until", 0) > now_ts():
        until = datetime.fromtimestamp(
            user["locked_until"], tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC")
        log(f"LOGIN_BLOCKED {args.username} (account locked until {until})")
        print(f"Account Temporarily Locked. Try again after {until}.")
        sys.exit(1)
    if not verify_password(args.password, user["salt"], user["password_hash"]):
        user["failed_attempts"] = user.get("failed_attempts", 0) + 1
        if user["failed_attempts"] >= MAX_FAILED_LOGINS:
            user["locked_until"] = now_ts() + LOCK_SECONDS
            save_users(users)
            log(f"LOGIN_LOCK {args.username} (locked after "
                f"{MAX_FAILED_LOGINS} failed attempts)")
            print("Login Failed. Invalid Username or Password. Please try again.")
            print(f"Account Temporarily Locked after {MAX_FAILED_LOGINS} "
                  f"failed attempts.")
        else:
            save_users(users)
            log(f"LOGIN_FAIL {args.username} "
                f"(failed attempt {user['failed_attempts']}/{MAX_FAILED_LOGINS})")
            print("Login Failed. Invalid Username or Password. Please try again.")
            print(f"Failed attempts: {user['failed_attempts']}/{MAX_FAILED_LOGINS}")
        sys.exit(1)
    user["failed_attempts"] = 0
    user["locked_until"] = 0
    save_users(users)
    log(f"LOGIN_SUCCESS {args.username} (password verified, OTP issued)")
    otp, expiry = generate_otp(args.username)
    exp_str = datetime.fromtimestamp(expiry, tz=timezone.utc).strftime(
        "%H:%M:%S UTC")
    print("Login Successful")
    print("Password verified. OTP generated as a second factor.")
    print(f"Your OTP is: {otp}  (6 digits, expires at {exp_str}, "
          f"in {OTP_SECONDS} seconds)")
    print("In a real system this OTP is sent by SMS/email, not printed here;")
    print("this lab stores it in otp_store.txt (see Task 2).")


def cmd_otp_verify(args):
    entry = find_otp(args.username)
    if entry is None:
        log(f"OTP_FAIL {args.username} (no active OTP - log in again)")
        print("No active OTP. Please log in again to get a new OTP.")
        sys.exit(1)
    _, otp_value, expiry_s, attempts_s, used = entry
    expiry, attempts = int(expiry_s), int(attempts_s)
    if used == "yes":
        log(f"OTP_REUSE {args.username} (OTP already used)")
        print("OTP already used. Request a new OTP.")
        sys.exit(1)
    if now_ts() > expiry:
        remove_otp(args.username)
        log(f"OTP_EXPIRED {args.username} (OTP removed after expiry)")
        print("OTP expired. Request a new OTP.")
        sys.exit(1)
    if attempts >= MAX_OTP_ATTEMPTS:
        remove_otp(args.username)
        log(f"OTP_LOCKED {args.username} (max OTP attempts reached)")
        print("Maximum OTP attempts reached. Please log in again.")
        sys.exit(1)
    if args.otp != otp_value:
        attempts += 1
        if attempts >= MAX_OTP_ATTEMPTS:
            remove_otp(args.username)
            log(f"OTP_FAIL {args.username} "
                f"(incorrect OTP, attempt {attempts}/{MAX_OTP_ATTEMPTS} - OTP invalidated)")
            print("Login failed. Invalid OTP. Please try again.")
            print("Maximum OTP attempts reached. Please log in again.")
        else:
            update_otp(args.username, otp_value, expiry, attempts, "no")
            log(f"OTP_FAIL {args.username} "
                f"(incorrect OTP, attempt {attempts}/{MAX_OTP_ATTEMPTS})")
            print("Login failed. Invalid OTP. Please try again.")
            print(f"Incorrect OTP attempts: {attempts}/{MAX_OTP_ATTEMPTS}")
        sys.exit(1)
    # Correct OTP: invalidate it immediately (mark used=yes in
    # otp_store.txt) so it cannot be reused; the next login
    # replaces it with a fresh OTP.
    update_otp(args.username, otp_value, expiry, attempts, "yes")
    log(f"OTP_SUCCESS {args.username} (OTP verified, OTP invalidated after use)")
    token, token_expiry = issue_token(args.username)
    log(f"TOKEN_ISSUED {args.username} (expires "
        f"{datetime.fromtimestamp(token_expiry, tz=timezone.utc).strftime('%H:%M:%S UTC')})")
    print("OTP verified. Login Successful")
    print("Token issued (stored in tokens.txt):")
    print(f"  {token}")
    print("Use it with: python auth_system.py access --token <token>")


def cmd_access(args):
    username, error = validate_token(args.token)
    if error:
        log(f"ACCESS_DENIED (invalid/expired/revoked token or no token)")
        print("Invalid Token. Login Required.")
        sys.exit(1)
    log(f"ACCESS_GRANTED {username} (protected resource accessed)")
    print(f"Access granted to protected resource for user '{username}'.")
    print("  Protected resource: user dashboard (requires a valid token).")


def cmd_revoke(args):
    if revoke_token(args.token):
        log("TOKEN_REVOKED (token revoked by user)")
        print("Token revoked.")
    else:
        print("Token not found or already revoked.")
        sys.exit(1)


def cmd_logout(args):
    cmd_revoke(args)
    print("Logged out.")


def cmd_status(args):
    users = load_users()
    user = users.get(args.username)
    if user is None:
        print(f"User '{args.username}' not found.")
        sys.exit(1)
    locked = user.get("locked_until", 0) > now_ts()
    print(f"User: {args.username}")
    print(f"  failed_attempts: {user.get('failed_attempts', 0)}/{MAX_FAILED_LOGINS}")
    print(f"  locked: {'yes' if locked else 'no'}")
    if locked:
        print("  locked_until: " + datetime.fromtimestamp(
            user["locked_until"], tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"))
    otp = find_otp(args.username)
    active_otp = otp if otp and otp[4] != "yes" else None
    print(f"  active OTP: {'yes' if active_otp else 'no'}")
    if active_otp:
        print("  OTP expires: " + datetime.fromtimestamp(
            int(active_otp[2]), tz=timezone.utc).strftime("%H:%M:%S UTC"))


def cmd_show_db(args):
    print("users_db.json (salt + hash only - no plaintext passwords):")
    print(USERS_FILE.read_text(encoding="utf-8") if USERS_FILE.exists()
          else "  (no users registered yet)")


def cmd_show_log(args):
    print("auth_log.txt:")
    print(LOG_FILE.read_text(encoding="utf-8") if LOG_FILE.exists()
          else "  (no log entries yet)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("register", help="Task 1: register a user")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p = sub.add_parser("login", help="Task 1: password login (issues OTP)")
    p.add_argument("--username", required=True)
    p.add_argument("--password", required=True)
    p = sub.add_parser("otp-verify", help="Task 2: verify the OTP")
    p.add_argument("--username", required=True)
    p.add_argument("--otp", required=True)
    p = sub.add_parser("access", help="Task 3: access protected resource")
    p.add_argument("--token")
    p = sub.add_parser("revoke", help="Task 3: revoke a token")
    p.add_argument("--token", required=True)
    p = sub.add_parser("logout", help="Task 3: log out (revoke token)")
    p.add_argument("--token", required=True)
    p = sub.add_parser("status", help="Show a user's lock/OTP status")
    p.add_argument("--username", required=True)
    sub.add_parser("show-db", help="Show users_db.json")
    sub.add_parser("show-log", help="Show auth_log.txt")
    args = parser.parse_args()
    {"register": cmd_register, "login": cmd_login,
     "otp-verify": cmd_otp_verify, "access": cmd_access,
     "revoke": cmd_revoke, "logout": cmd_logout,
     "status": cmd_status, "show-db": cmd_show_db,
     "show-log": cmd_show_log}[args.command](args)


if __name__ == "__main__":
    main()
