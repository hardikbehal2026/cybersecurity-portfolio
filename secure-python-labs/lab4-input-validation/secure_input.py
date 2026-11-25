#!/usr/bin/env python3
"""Lab 4: Input Validation, Secure Randomness & Injection Attack Prevention.
MCSC-6002. Due Sat Nov 21, 2026, 11:59 PM EST. Max 4 points.

A secure input processing module for a web-based healthcare data portal.
Standard library only: re, sqlite3, secrets, html, time, math, os.
random is imported just for the insecure comparison, never for tokens.

A few things to be clear about:
- No bcrypt or PyJWT here. They aren't installed, and this lab doesn't need
  them — the brief's own list is re / sqlite3 / secrets / html.
- Nothing here stores a password. That was Lab 2.
- The vulnerable SQL query and the unsafe format function are only there so
  the attack can be shown in a throwaway local database. Don't use them
  anywhere real. They're labelled VULNERABLE / UNSAFE everywhere.
- The format-string demo is Python's version of C's printf(user_input).
  Python's % operator doesn't do %n (it just errors), so the %n
  arbitrary-write part is explained in the docx instead of shown live.
  What the demo does show is the real problem: the attacker's %x
  specifiers get interpreted instead of printed.
- Tokens are 32 hex chars from secrets.token_hex(16) — 16 bytes, 128 bits,
  straight from the OS random source.
"""

import argparse
import collections
import html
import math
import os
import random  # INSECURE comparison only — never for tokens
import re
import secrets
import sqlite3
import time

# Email: must look like username@domain.tld. Anything with markup in it
# gets rejected up front, before the regex even runs.
_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$"
)
_FORBIDDEN_IN_EMAIL = ("<", ">", "script", "javascript:", "(", ")", " ",
                       "'", '"', ";", "\\")


def validate_email(email):
    """Return (is_valid, reason)."""
    if not isinstance(email, str) or not email:
        return False, "empty / not a string"
    if len(email) > 254:
        return False, "too long (> 254 characters)"
    lowered = email.lower()
    for bad in _FORBIDDEN_IN_EMAIL:
        if bad in lowered:
            return False, f"rejected: contains {bad!r} (possible script injection)"
    if email.count("@") != 1:
        return False, "rejected: must contain exactly one '@'"
    local, domain = email.split("@")
    if not local or not domain:
        return False, "rejected: empty local part or domain"
    if ".." in email or local.startswith(".") or local.endswith("."):
        return False, "rejected: consecutive / leading / trailing dots"
    if not _EMAIL_RE.match(email):
        return False, "rejected: does not match username@domain.tld"
    if domain.startswith("-") or domain.endswith("-"):
        return False, "rejected: invalid domain"
    return True, "valid"


# Filenames: letters, digits, _ and . only. No "..", no slashes,
# no leading dot (that would hide the file, like .env).
_FILENAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


def validate_filename(name):
    """Return (is_valid, reason)."""
    if not isinstance(name, str) or not name:
        return False, "empty / not a string"
    if ".." in name:
        return False, "rejected: '..' (path traversal)"
    if "/" in name or "\\" in name:
        return False, "rejected: path separator in filename"
    if name.startswith("."):
        return False, "rejected: hidden file (leading '.')"
    if "\x00" in name:
        return False, "rejected: NUL byte"
    if name.endswith("."):
        return False, "rejected: trailing dot"
    if not _FILENAME_RE.match(name):
        return False, "rejected: only letters, digits, '_' and '.' allowed"
    return True, "valid"


# File paths: everything has to stay under BASE_DIR. The path gets
# normalised first (so a/../b collapses), then checked with commonpath —
# a plain startswith check would be fooled by a sibling folder like
# /portal_data-evil. realpath also catches a symlink inside the base
# that points outside it.
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "portal_data"))


def validate_path(user_path, base_dir=BASE_DIR):
    """Return (is_valid, resolved_path_or_reason).

    Accepts a path relative to base_dir. Absolute paths are rejected
    unless they already lie inside base_dir.
    """
    if not isinstance(user_path, str) or not user_path:
        return False, "empty / not a string"
    if "\x00" in user_path:
        return False, "rejected: NUL byte"
    base = os.path.realpath(base_dir)
    if os.path.isabs(user_path):
        candidate = os.path.normpath(user_path)
    else:
        candidate = os.path.normpath(os.path.join(base, user_path))
    resolved = os.path.realpath(candidate)
    try:
        common = os.path.commonpath([base, resolved])
    except ValueError:
        return False, "rejected: path is on a different drive"
    if common != base:
        return False, f"rejected: escapes base directory ({resolved})"
    return True, resolved


# SQL injection demo. Throwaway local database, 3 users. The vulnerable
# version is only here to show the attack — never use it for real.
DEMO_USERS = [
    ("alice", "alice@humber.ca", "patient"),
    ("bob", "bob@humber.ca", "doctor"),
    ("carol", "carol@humber.ca", "nurse"),
]


def build_demo_db(path=":memory:"):
    """Create a throwaway SQLite database with 3 demo users."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)"
    )
    conn.execute("DELETE FROM users")
    conn.executemany(
        "INSERT INTO users (username, email, role) VALUES (?, ?, ?)", DEMO_USERS
    )
    conn.commit()
    return conn


def vulnerable_query(conn, user_input):
    """VULNERABLE — demo only. Builds the query by gluing strings together."""
    query = "SELECT * FROM users WHERE username = '" + user_input + "'"
    return conn.execute(query).fetchall()


def secure_query(conn, user_input):
    """SECURE — parameterized. The input is data, never part of the SQL."""
    query = "SELECT * FROM users WHERE username = ?"
    return conn.execute(query, (user_input,)).fetchall()


# XSS: escape on output. < > & " ' turn into entities, so the browser
# shows the text instead of running it.
def render_comment_raw(user_input):
    """VULNERABLE — demo only. Input goes in unescaped."""
    return f"<div class='comment'>{user_input}</div>"


def render_comment_safe(user_input):
    """SECURE — html.escape does the work."""
    return f"<div class='comment'>{html.escape(user_input, quote=True)}</div>"


def sanitize_comment(user_input):
    """Same escaping, kept as a separate helper for input-side use."""
    return html.escape(user_input, quote=True)


# Format strings: the Python version of C's printf(user_input).
# In the unsafe one the input IS the format string, so %x and friends
# get interpreted. In the safe one the format is a fixed "%s" and the
# input is only ever data.
def unsafe_format(user_input):
    """UNSAFE — demo only. See the docx for why %n is worse in C."""
    return user_input % (12345, 67890, 11111)


def safe_format(user_input):
    """SAFE — same idea as printf("%s", user_input) in C."""
    return "%s" % user_input


# Secure randomness: secrets, straight from the OS. 32 hex chars = 128 bits.
def secure_token():
    """Session / password-reset token."""
    return secrets.token_hex(16)


def insecure_token_sequence(seed=1234, n=5):
    """INSECURE — demo only. Same seed, same numbers, every single run."""
    rng = random.Random(seed)
    return [rng.randint(1, 100) for _ in range(n)]


def token_uniqueness(n=1000):
    """Generate n secure tokens; return (n, unique_count, duplicates)."""
    tokens = [secure_token() for _ in range(n)]
    return n, len(set(tokens)), n - len(set(tokens))


def distribution_over_100(samples=10000):
    """Draw `samples` values with secrets.randbelow(100) and count how
    often each value 0-99 occurs. Returns a collections.Counter."""
    counts = collections.Counter(secrets.randbelow(100) for _ in range(samples))
    return counts


def chi_square(counts, samples):
    """Chi-square against a uniform spread over 100 buckets. Near 99
    (the degrees of freedom) means it looks uniform; way above means not."""
    expected = samples / 100.0
    return sum((counts.get(i, 0) - expected) ** 2 / expected for i in range(100))


# Entropy: just log2 of how many possibilities there are.
def entropy_bits(possibilities):
    """Entropy in bits for a uniformly random choice among N possibilities."""
    return math.log2(possibilities)


# ---------------------------------------------------------------------------
# Demo — prints every section, used to produce the screenshots
# ---------------------------------------------------------------------------
def demo_validation():
    print("=== 4.1 (A) Email validation ===")
    for email in [
        "alice@humber.ca",
        "bob.smith+lab@health-portal.org",
        "alice@humber",
        "alice@@humber.ca",
        "alice@.ca",
        "<script>alert(1)</script>@humber.ca",
        "alice@humber.ca<script>",
        "alice humber.ca",
    ]:
        ok, reason = validate_email(email)
        print(f"  {email!r:45} -> {'ACCEPT' if ok else 'REJECT'}  ({reason})")
    print()
    print("=== 4.1 (B) Filename validation ===")
    for name in [
        "patient_record.txt",
        "lab_results_2026-11.csv",
        "../etc/passwd",
        "../../.env",
        ".env",
        "report.pdf ",
        "my file.txt",
        "notes.txt\x00.jpg",
        "data..txt",
    ]:
        ok, reason = validate_filename(name)
        print(f"  {name!r:30} -> {'ACCEPT' if ok else 'REJECT'}  ({reason})")
    print()
    print("=== 4.1 (C) File-path validation (base: portal_data/) ===")
    for path in [
        "records/patient_101.txt",
        "records/../records/patient_101.txt",
        "records/../../etc/passwd",
        "../secret.txt",
        "/etc/passwd",
        "records//lab_2026.csv",
    ]:
        ok, result = validate_path(path)
        print(f"  {path!r:35} -> {'ACCEPT' if ok else 'REJECT'}  ({result})")


def demo_sql():
    print("=== 4.2 SQL injection: vulnerable vs parameterized ===")
    conn = build_demo_db()
    attack = "' OR '1'='1"
    print(f"  Attacker input: {attack!r}")
    print("  Vulnerable query (string concatenation):")
    print("    SELECT * FROM users WHERE username = '' OR '1'='1'")
    rows = vulnerable_query(conn, attack)
    print(f"    -> returned {len(rows)} rows (ALL users — login bypass): {rows}")
    print("  Secure query (parameterized, '?'):")
    print("    SELECT * FROM users WHERE username = ?")
    rows = secure_query(conn, attack)
    print(f"    -> returned {len(rows)} rows (no user literally named that)")
    print("  Legitimate lookup still works (secure):")
    print(f"    secure_query('alice') -> {secure_query(conn, 'alice')}")
    print("  Second payload \"' OR 1=1 --\":")
    print(f"    vulnerable -> {len(vulnerable_query(conn, chr(39) + ' OR 1=1 --'))} rows")
    print(f"    secure     -> {len(secure_query(conn, chr(39) + ' OR 1=1 --'))} rows")
    conn.close()


def demo_xss():
    print("=== 4.3 XSS: raw vs html.escape ===")
    payload = "<script>alert('Hacked')</script>"
    print(f"  User comment: {payload!r}")
    print(f"  RAW (vulnerable):  {render_comment_raw(payload)}")
    print(f"  ESCAPED (safe):    {render_comment_safe(payload)}")
    print("  -> escaped output is displayed as text; no script executes.")
    print(f"  Second payload: {render_comment_safe(chr(60) + 'img src=x onerror=alert(1)' + chr(62))}")


def demo_format():
    print("=== 4.4 Format string: printf(user_input) vs printf(\"%s\", user_input) ===")
    payload = "%x %x %x"
    print(f"  Attacker input: {payload!r}")
    try:
        print(f"  UNSAFE printf(user_input): {unsafe_format(payload)!r}")
        print("    -> format specifiers were INTERPRETED (hex values printed),")
        print("       not shown literally. In C, %x leaks stack data and %n writes to memory.")
    except Exception as exc:  # noqa: BLE001 - demo must show the crash
        print(f"  UNSAFE printf(user_input): CRASH — {type(exc).__name__}: {exc}")
    print(f"  SAFE   printf(\"%s\", user_input): {safe_format(payload)!r}")
    print("    -> input printed literally, nothing interpreted.")
    print(f"  SAFE with normal text: {safe_format('Hello, Alice')!r}")


def demo_random():
    print("=== 4.5 Secure randomness (secrets) ===")
    print(f"  Sample session token: {secure_token()}  (32 hex chars, 128 bits)")
    print(f"  Sample reset token:   {secure_token()}")
    n, unique, dupes = token_uniqueness(1000)
    print(f"  Uniqueness: generated {n} tokens, {unique} unique, {dupes} duplicates")
    print("  Insecure comparison — random.Random(1234), randint(1,100) x5:")
    print(f"    run 1: {insecure_token_sequence()}")
    print(f"    run 2: {insecure_token_sequence()}   <- identical: predictable")
    print("  Distribution: 10,000 draws of secrets.randbelow(100):")
    counts = distribution_over_100(10000)
    vals = [counts.get(i, 0) for i in range(100)]
    print(f"    expected per value: 100.0 | min: {min(vals)} | max: {max(vals)} "
          f"| mean: {sum(vals) / 100:.1f}")
    print(f"    chi-square (99 df, ~99 expected): {chi_square(counts, 10000):.1f}")
    print("    first 10 buckets (0-9):", vals[:10])
    print("  Entropy: 32-char hex token = 16 bytes = "
          f"{entropy_bits(16 ** 32):.0f} bits (32 hex chars x 4 bits each); "
          f"6-digit OTP = {entropy_bits(10 ** 6):.1f} bits")


def main():
    parser = argparse.ArgumentParser(description="Lab 4 Secure Input Processing Module")
    parser.add_argument("section", nargs="?", default="all",
                        choices=["all", "validation", "sql", "xss", "format", "random"])
    args = parser.parse_args()
    if args.section in ("all", "validation"):
        demo_validation()
        print()
    if args.section in ("all", "sql"):
        demo_sql()
        print()
    if args.section in ("all", "xss"):
        demo_xss()
        print()
    if args.section in ("all", "format"):
        demo_format()
        print()
    if args.section in ("all", "random"):
        demo_random()


if __name__ == "__main__":
    main()
