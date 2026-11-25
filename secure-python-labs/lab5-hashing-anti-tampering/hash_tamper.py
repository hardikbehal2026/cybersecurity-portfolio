#!/usr/bin/env python3
"""
Lab 5: Hashes & Anti-Tampering Mechanisms (MCSC-6002, 2%)
Simple Integrity & Anti-Tampering System — standard library only.

Modules used: hashlib (SHA-256), hmac (HMAC-SHA256), time, secrets.
No third-party packages. No network access. Demo data is fictional.

Usage:
    python3 hash_tamper.py demo            # run all four tasks in order
    python3 hash_tamper.py hash <string>   # Task 4.1: SHA-256 of a string
    python3 hash_tamper.py hmac-demo       # Task 4.2: HMAC generate / verify
    python3 hash_tamper.py nonce-demo      # Task 4.3: nonce replay protection
    python3 hash_tamper.py file-demo       # Task 4.4: file tampering detection
    python3 hash_tamper.py verify <file>   # verify a file against its stored hash

Honest limits (also analysed in section 4.5 of the report):
  * A plain hash proves nothing about who created the data — anyone can
    recompute a hash after tampering. Only the HMAC (with a secret key)
    adds authenticity, and only while the key stays secret.
  * The nonce store and the file-hash baseline live in plain local files
    in this demo. An attacker who can rewrite those files can defeat the
    checks. In production they must be protected / kept separately.
  * Hashing detects tampering after the fact; it does not prevent it.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone

NONCE_MAX_AGE_SECONDS = 60          # brief: nonce expires within 60 seconds
NONCE_STORE_FILE = "nonce_store.json"
FILE_HASHES_FILE = "file_hashes.json"
TAMPER_LOG_FILE = "tamper_log.txt"


# ---------------------------------------------------------------- 4.1 Hashing
def sha256_string(text: str) -> str:
    """Return the SHA-256 hex digest of a string (UTF-8 encoded)."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_string_hash(text: str, expected_hex: str) -> bool:
    """True if the string still hashes to the expected digest (constant-time)."""
    return hmac.compare_digest(sha256_string(text), expected_hex)


def demo_hashing() -> None:
    print("=== 4.1 Task 1: Hashing of Strings (SHA-256) ===")
    original = "Patient123"
    digest = sha256_string(original)
    print(f"Input:  {original}")
    print(f"SHA-256: {digest}")
    print(f"Verify original:  {verify_string_hash(original, digest)}")
    # Tamper detection: one character changed -> completely different hash
    tampered = "Patient124"
    tampered_digest = sha256_string(tampered)
    print(f"Input:  {tampered}   (one character changed)")
    print(f"SHA-256: {tampered_digest}")
    print(f"Verify tampered against original hash: "
          f"{verify_string_hash(tampered, digest)}")
    if not verify_string_hash(tampered, digest):
        print("-> TAMPER DETECTED: hash does not match the stored hash.")
    print()


# ------------------------------------------------------------------- 4.2 MAC
def generate_hmac(key: bytes, message: str) -> str:
    """HMAC-SHA256 of a message under a secret key, as a hex digest."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_hmac(key: bytes, message: str, expected_hex: str) -> bool:
    """True if the message authenticates under the key (constant-time)."""
    return hmac.compare_digest(generate_hmac(key, message), expected_hex)


def demo_hmac() -> None:
    print("=== 4.2 Task 2: Message Authentication Code (HMAC-SHA256) ===")
    # In a real deployment the key comes from a secret manager / env var,
    # never from source code. Here it is generated fresh for the demo.
    key = secrets.token_bytes(32)
    message = "Patient123: dosage 10mg, Dr. Smith"
    mac = generate_hmac(key, message)
    print(f"Message: {message}")
    print(f"HMAC-SHA256: {mac}")
    print(f"Valid message   -> MAC Verified: {verify_hmac(key, message, mac)}")
    modified = "Patient123: dosage 50mg, Dr. Smith"
    print(f"Modified message: {modified}")
    print(f"Modified message -> MAC Verified: "
          f"{verify_hmac(key, modified, mac)}")
    if not verify_hmac(key, modified, mac):
        print("-> TAMPER DETECTED: MAC verification failed.")
    print()


# ------------------------------------------------------- 4.3 Nonce / replay
class ReplayProtector:
    """One nonce per request, accepted once and only while fresh.

    A nonce is accepted only if (a) it has never been seen before and
    (b) its timestamp is at most NONCE_MAX_AGE_SECONDS (60 s) old.
    Reused nonces are rejected (replay), stale nonces are rejected
    (expired). Used nonces are recorded so a replay is caught even
    after the original request succeeded.
    """

    def __init__(self, store_file: str = NONCE_STORE_FILE):
        self.store_file = store_file
        self.used: dict[str, float] = {}
        if os.path.exists(store_file):
            try:
                with open(store_file, encoding="utf-8") as f:
                    self.used = {k: float(v) for k, v in json.load(f).items()}
            except (ValueError, OSError):
                self.used = {}

    def _save(self) -> None:
        with open(self.store_file, "w", encoding="utf-8") as f:
            json.dump(self.used, f, indent=2)

    @staticmethod
    def generate_nonce() -> str:
        """A fresh, unpredictable nonce (16 hex chars from secrets)."""
        return secrets.token_hex(8)

    def check_request(self, nonce: str, timestamp: float | None = None):
        """Return (accepted: bool, reason: str) for one request."""
        now = time.time()
        ts = now if timestamp is None else timestamp
        if nonce in self.used:
            return False, "REJECTED (Duplicate NONCE)"
        if now - ts > NONCE_MAX_AGE_SECONDS:
            return False, "REJECTED (Expired NONCE - older than 60s)"
        if ts - now > 5:  # small clock-skew allowance, not a replay window
            return False, "REJECTED (Nonce timestamp is in the future)"
        self.used[nonce] = ts
        self._save()
        return True, "ACCEPTED"


def demo_nonce() -> None:
    print("=== 4.3 Task 3: NONCE for Replay Protection ===")
    protector = ReplayProtector()
    nonce = protector.generate_nonce()
    print(f"Generated NONCE: {nonce}")
    ok, reason = protector.check_request(nonce)
    print(f"Request 1 (nonce {nonce}) -> {reason}")
    # Replay: same nonce sent a second time
    ok, reason = protector.check_request(nonce)
    print(f"Request 1 again (nonce {nonce}) -> {reason}")
    # Expired: a fresh nonce whose timestamp is 120 seconds old
    old_nonce = protector.generate_nonce()
    ok, reason = protector.check_request(old_nonce, time.time() - 120)
    print(f"Request with expired nonce {old_nonce} (120s old) -> {reason}")
    # Fresh request with a new nonce is accepted
    fresh = protector.generate_nonce()
    ok, reason = protector.check_request(fresh)
    print(f"Request 2 (new nonce {fresh}) -> {reason}")
    print()


# ------------------------------------------------- 4.4 File tamper detection
def hash_file(path: str) -> str:
    """SHA-256 hex digest of a file, read in chunks (works for large files)."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_baselines() -> dict:
    if os.path.exists(FILE_HASHES_FILE):
        try:
            with open(FILE_HASHES_FILE, encoding="utf-8") as f:
                return json.load(f)
        except (ValueError, OSError):
            return {}
    return {}


def _save_baselines(baselines: dict) -> None:
    with open(FILE_HASHES_FILE, "w", encoding="utf-8") as f:
        json.dump(baselines, f, indent=2)


def record_file_hash(path: str) -> str:
    """Hash a file and store the hash as its trusted baseline."""
    digest = hash_file(path)
    baselines = _load_baselines()
    baselines[os.path.abspath(path)] = digest
    _save_baselines(baselines)
    return digest


def verify_file(path: str):
    """Compare a file against its stored baseline.

    Returns (status, stored_hash, current_hash) where status is
    'OK', 'TAMPERED', or 'NO BASELINE'. A tamper is also written to
    tamper_log.txt with a UTC timestamp.
    """
    current = hash_file(path)
    baselines = _load_baselines()
    stored = baselines.get(os.path.abspath(path))
    if stored is None:
        return "NO BASELINE", None, current
    if hmac.compare_digest(stored, current):
        return "OK", stored, current
    ts = datetime.now(timezone.utc).isoformat()
    with open(TAMPER_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{ts} TAMPERED {os.path.abspath(path)} "
                f"stored={stored} current={current}\n")
    return "TAMPERED", stored, current


def demo_file_tampering() -> None:
    print("=== 4.4 Task 4: File / Software Tampering Detection ===")
    filename = "data.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("Patient: Patient123\nDosage: 10mg\nDoctor: Dr. Smith\n")
    print(f"Selected file: {filename}")
    original = record_file_hash(filename)
    print(f"Original Hash: {original}")
    status, _, current = verify_file(filename)
    print(f"Integrity check before modification: {status}")
    # Simulate an attacker modifying the file outside the application
    with open(filename, "a", encoding="utf-8") as f:
        f.write("Dosage: 50mg   (changed by attacker)\n")
    print("File modified manually (dosage changed to 50mg).")
    status, stored, current = verify_file(filename)
    print(f"Original Hash: {stored}")
    print(f"New Hash:      {current}")
    if status == "TAMPERED":
        print("-> ALERT: File has been tampered!")
        print(f"   Tamper event logged to {TAMPER_LOG_FILE} with timestamp.")
    print()


# --------------------------------------------------------------------- demo
def demo_all() -> None:
    print("Lab 5: Hashes & Anti-Tampering Mechanisms — full demonstration")
    print("=" * 70)
    demo_hashing()
    demo_hmac()
    demo_nonce()
    demo_file_tampering()
    print("=== 5. Sample Execution Output (summary) ===")
    print("Input: Patient123")
    print(f"Hash: {sha256_string('Patient123')[:12]}... (full hash shown in 4.1)")
    print("MAC Verified: True  |  Modified Message -> MAC Verified: False")
    print("Nonce: <generated> -> ACCEPTED  |  same Nonce -> REJECTED")
    print("File Integrity Check: Original Hash != New Hash")
    print("-> ALERT: File tampered!")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Lab 5: Hashes & Anti-Tampering Mechanisms")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="run all four tasks in order")
    p_hash = sub.add_parser("hash", help="SHA-256 of a string")
    p_hash.add_argument("text")
    sub.add_parser("hmac-demo", help="HMAC generate / verify demo")
    sub.add_parser("nonce-demo", help="nonce replay-protection demo")
    sub.add_parser("file-demo", help="file tampering detection demo")
    p_verify = sub.add_parser("verify", help="verify a file against its baseline")
    p_verify.add_argument("path")
    args = parser.parse_args(argv)

    if args.command == "demo":
        demo_all()
    elif args.command == "hash":
        print(f"Input:  {args.text}")
        print(f"SHA-256: {sha256_string(args.text)}")
    elif args.command == "hmac-demo":
        demo_hmac()
    elif args.command == "nonce-demo":
        demo_nonce()
    elif args.command == "file-demo":
        demo_file_tampering()
    elif args.command == "verify":
        status, stored, current = verify_file(args.path)
        print(f"File: {args.path}")
        print(f"Stored Hash:  {stored}")
        print(f"Current Hash: {current}")
        print(f"Status: {status}")
        if status == "TAMPERED":
            print("-> ALERT: File has been tampered!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
