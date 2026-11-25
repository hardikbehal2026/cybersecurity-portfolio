#!/usr/bin/env python3
"""
secure_comms.py — Lab 6: Secure Communication System Using Public Key Cryptography
MCSC-6002, Task 2-6. Hospital A (Central Hospital, Brampton) and
Hospital B (Satellite Clinic, Mississauga) exchange patient data over an
insecure network.

Pure Python standard library only. RSA and Diffie-Hellman are implemented
here from scratch (Miller-Rabin prime generation, pow() modular
exponentiation, SHA-256 hashing before signing) so the lab shows how the
pieces work instead of hiding them inside a library call.

HONEST LIMIT — this is a teaching prototype, NOT production cryptography:
  * The RSA code below uses PKCS#1 v1.5 padding and a small, simple key
    file format (JSON). A real hospital system would use a vetted library
    (for example Python's `cryptography` package), OAEP padding, proper
    certificates, and hardware-backed key storage.
  * Key sizes used here are real (2048-bit RSA, 2048-bit Diffie-Hellman
    group), so the demo numbers are genuine, but the code itself has not
    been audited and must not be used for real patient data.
  * Demo private keys are stored as local files with permissions 0600.
    That keeps other users on the same machine out, but it is not the same
    as a key vault or an HSM.

Usage:
  python3 secure_comms.py demo2   Task 2: RSA key pairs for both hospitals
  python3 secure_comms.py demo3   Task 3: encrypt / decrypt the cardiac message
  python3 secure_comms.py demo4   Task 4: sign / verify, plus tamper demo
  python3 secure_comms.py demo5   Task 5: RSA session-key exchange
  python3 secure_comms.py demo6   Task 6: Diffie-Hellman shared secret
  python3 secure_comms.py demo    run all five demos in order
"""

import hashlib
import json
import os
import secrets
import sys

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# ---------------------------------------------------------------------------
# Primes (Miller-Rabin)
# ---------------------------------------------------------------------------

def is_probable_prime(n, rounds=20):
    """Miller-Rabin primality test. 20 rounds makes a false positive
    vanishingly unlikely, and that is good enough for a classroom demo."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a, m):
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse exists")
    return x % m


# ---------------------------------------------------------------------------
# RSA
# ---------------------------------------------------------------------------

def rsa_keypair(bits=2048):
    """Generate an RSA key pair. Returns dicts (public, private).
    Regenerates until the modulus is exactly `bits` long, so a
    '2048-bit key' really has a 2048-bit modulus."""
    e = 65537
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if _egcd(e, phi)[0] != 1:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        break
    d = mod_inverse(e, phi)
    public = {"n": n, "e": e}
    private = {"n": n, "e": e, "d": d}
    return public, private


def _pkcs1_v15_pad(message, key_len):
    """EME-PKCS1-v1_5 encryption padding: 00 02 || random non-zero bytes || 00 || M."""
    if len(message) > key_len - 11:
        raise ValueError("message too long for this RSA key")
    padding_len = key_len - len(message) - 3
    padding = b""
    while len(padding) < padding_len:
        b = secrets.token_bytes(1)
        if b != b"\x00":
            padding += b
    return b"\x00\x02" + padding + b"\x00" + message


def rsa_encrypt(message_bytes, public):
    n, e = public["n"], public["e"]
    key_len = (n.bit_length() + 7) // 8
    block = _pkcs1_v15_pad(message_bytes, key_len)
    m = int.from_bytes(block, "big")
    c = pow(m, e, n)
    return c.to_bytes(key_len, "big")


def rsa_decrypt(ciphertext, private):
    n, d = private["n"], private["d"]
    key_len = (n.bit_length() + 7) // 8
    if len(ciphertext) != key_len:
        raise ValueError("ciphertext has the wrong length")
    m = pow(int.from_bytes(ciphertext, "big"), d, n)
    block = m.to_bytes(key_len, "big")
    if block[0:2] != b"\x00\x02":
        raise ValueError("decryption failed: bad padding")
    sep = block.find(b"\x00", 2)
    if sep < 0:
        raise ValueError("decryption failed: bad padding")
    return block[sep + 1:]


# PKCS#1 v1.5 DigestInfo prefix for SHA-256 (EMSA-PKCS1-v1_5).
_SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_sign(message_bytes, private):
    """Sign the SHA-256 hash of the message with the private key."""
    digest = hashlib.sha256(message_bytes).digest()
    t = _SHA256_PREFIX + digest
    n, d = private["n"], private["d"]
    key_len = (n.bit_length() + 7) // 8
    if len(t) > key_len - 11:
        raise ValueError("hash too long for this RSA key")
    block = b"\x00\x01" + b"\xff" * (key_len - len(t) - 3) + b"\x00" + t
    s = pow(int.from_bytes(block, "big"), d, n)
    return s.to_bytes(key_len, "big")


def rsa_verify(message_bytes, signature, public):
    """Return True only if the signature matches this exact message."""
    n, e = public["n"], public["e"]
    key_len = (n.bit_length() + 7) // 8
    if len(signature) != key_len:
        return False
    m = pow(int.from_bytes(signature, "big"), e, n)
    block = m.to_bytes(key_len, "big")
    digest = hashlib.sha256(message_bytes).digest()
    expected = b"\x00\x01" + b"\xff" * (key_len - len(_SHA256_PREFIX) - len(digest) - 3) \
        + b"\x00" + _SHA256_PREFIX + digest
    return block == expected


# ---------------------------------------------------------------------------
# Key storage
# ---------------------------------------------------------------------------

def _key_fingerprint(public):
    data = ("%d:%d" % (public["n"], public["e"])).encode()
    return hashlib.sha256(data).hexdigest()[:16]


def save_keypair(name, public, private):
    """Save a key pair. The private key file gets mode 0600 (owner only);
    the public key is saved separately so it can be shared freely."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    pub_path = os.path.join(KEYS_DIR, name + "_public.json")
    priv_path = os.path.join(KEYS_DIR, name + "_private.json")
    with open(pub_path, "w", encoding="utf-8") as f:
        json.dump({"n": str(public["n"]), "e": public["e"]}, f)
    with open(priv_path, "w", encoding="utf-8") as f:
        json.dump({"n": str(private["n"]), "e": private["e"],
                   "d": str(private["d"])}, f)
    os.chmod(priv_path, 0o600)
    os.chmod(pub_path, 0o644)
    return pub_path, priv_path


def load_public(name):
    with open(os.path.join(KEYS_DIR, name + "_public.json"), encoding="utf-8") as f:
        data = json.load(f)
    return {"n": int(data["n"]), "e": data["e"]}


def load_private(name):
    with open(os.path.join(KEYS_DIR, name + "_private.json"), encoding="utf-8") as f:
        data = json.load(f)
    return {"n": int(data["n"]), "e": data["e"], "d": int(data["d"])}


def _short_hex(data, shown=48):
    h = data.hex()
    return h[:shown] + "..." if len(h) > shown else h


# ---------------------------------------------------------------------------
# Task 2 — RSA key infrastructure
# ---------------------------------------------------------------------------

def demo2():
    print("=== Task 2: RSA key pairs for Hospital A and Hospital B ===")
    print("Generating 2048-bit RSA key pairs (this takes a few seconds)...")
    for name, label in (("hospital_a", "Hospital A (Central Hospital, Brampton)"),
                        ("hospital_b", "Hospital B (Satellite Clinic, Mississauga)")):
        public, private = rsa_keypair(2048)
        pub_path, priv_path = save_keypair(name, public, private)
        print()
        print(label)
        print("  modulus size: %d bits" % public["n"].bit_length())
        print("  public exponent (e): %d" % public["e"])
        print("  public key fingerprint (SHA-256, first 16 hex): %s"
              % _key_fingerprint(public))
        print("  public key saved to:  %s" % pub_path)
        print("  private key saved to: %s" % priv_path)
        print("  private key permissions: %s (owner read/write only)"
              % oct(os.stat(priv_path).st_mode & 0o777))
    print()
    print("Public keys exported as JSON and ready to share with the other")
    print("hospital. Private keys never leave their own hospital's folder.")


# ---------------------------------------------------------------------------
# Task 3 — RSA message encryption
# ---------------------------------------------------------------------------

CARDIAC_MESSAGE = "Patient ID 98321 requires immediate cardiac intervention."


def demo3():
    print("=== Task 3: RSA-encrypted patient message ===")
    pub_b = load_public("hospital_b")
    priv_b = load_private("hospital_b")
    print("Hospital A encrypts with Hospital B's PUBLIC key.")
    print("Plaintext: %s" % CARDIAC_MESSAGE)
    ciphertext = rsa_encrypt(CARDIAC_MESSAGE.encode(), pub_b)
    print("Ciphertext (%d bytes, hex, first 48 chars): %s"
          % (len(ciphertext), _short_hex(ciphertext)))
    print("Ciphertext sent over the insecure network...")
    print("Hospital B decrypts with its own PRIVATE key.")
    recovered = rsa_decrypt(ciphertext, priv_b).decode()
    print("Decrypted: %s" % recovered)
    print("Round-trip check: %s"
          % ("MATCH - message arrived unchanged" if recovered == CARDIAC_MESSAGE
             else "MISMATCH - something went wrong"))
    print()
    print("Only Hospital B can read this: the private key needed to undo")
    print("the encryption never left Hospital B.")


# ---------------------------------------------------------------------------
# Task 4 — digital signatures
# ---------------------------------------------------------------------------

GLUCOSE_ORIGINAL = "Glucose level: 6.5 mmol/L"
GLUCOSE_TAMPERED = "Glucose level: 16.5 mmol/L"


def demo4():
    print("=== Task 4: digital signature and tamper detection ===")
    priv_a = load_private("hospital_a")
    pub_a = load_public("hospital_a")
    print("Doctor at Hospital A signs the lab result with Hospital A's")
    print("PRIVATE key. The signature covers the SHA-256 hash of the message.")
    print("Message: %s" % GLUCOSE_ORIGINAL)
    signature = rsa_sign(GLUCOSE_ORIGINAL.encode(), priv_a)
    print("Signature (%d bytes, hex, first 48 chars): %s"
          % (len(signature), _short_hex(signature)))
    print()
    print("Hospital B verifies with Hospital A's PUBLIC key.")
    ok = rsa_verify(GLUCOSE_ORIGINAL.encode(), signature, pub_a)
    print("Verify original message: %s" % ok)
    print()
    print("--- Attacker changes the result in transit ---")
    print("Tampered message: %s" % GLUCOSE_TAMPERED)
    ok_tampered = rsa_verify(GLUCOSE_TAMPERED.encode(), signature, pub_a)
    print("Verify tampered message: %s" % ok_tampered)
    if not ok_tampered:
        print("TAMPER DETECTED - signature does not match the altered text.")
        print("Hospital B rejects the result and asks Hospital A to resend it.")


# ---------------------------------------------------------------------------
# Task 5 — RSA session-key exchange
# ---------------------------------------------------------------------------

def demo5():
    print("=== Task 5: RSA session-key exchange (hybrid encryption) ===")
    pub_b = load_public("hospital_b")
    priv_b = load_private("hospital_b")
    session_key = secrets.token_bytes(32)  # 256-bit AES-style session key
    print("Hospital A creates a fresh 256-bit session key for this transfer.")
    print("Session key (hex, first 48 chars): %s" % _short_hex(session_key))
    print("Hospital A encrypts the session key with Hospital B's PUBLIC key.")
    wrapped = rsa_encrypt(session_key, pub_b)
    print("Wrapped session key (%d bytes, hex, first 48 chars): %s"
          % (len(wrapped), _short_hex(wrapped)))
    print("Wrapped key sent over the insecure network...")
    print("Hospital B unwraps it with its PRIVATE key.")
    unwrapped = rsa_decrypt(wrapped, priv_b)
    print("Unwrapped session key (hex, first 48 chars): %s" % _short_hex(unwrapped))
    print("Session keys match: %s" % (unwrapped == session_key))
    print()
    print("Both hospitals now share the same session key and can switch to")
    print("fast symmetric encryption (for example AES) for the large dataset.")
    print("RSA was only used to move the small key, not the data itself.")


# ---------------------------------------------------------------------------
# Task 6 — Diffie-Hellman
# ---------------------------------------------------------------------------

# RFC 3526, 2048-bit MODP Group (Group 14). A standard public parameter,
# not a secret. The demo checks at run time that it is prime.
DH_PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024"
    "E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6"
    "F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F241"
    "17C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D"
    "39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED"
    "529077096966D670C354E4ABC9804F1746C08CA18217C32905E46"
    "2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52"
    "C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510157"
    "28E5A8AACAA68FFFFFFFFFFFFFFFF"
)
DH_GENERATOR = 2


def demo6():
    print("=== Task 6: Diffie-Hellman key exchange ===")
    p = int(DH_PRIME_HEX, 16)
    g = DH_GENERATOR
    print("Public parameters (RFC 3526, 2048-bit MODP group):")
    print("  prime p: %d bits, prime check: %s"
          % (p.bit_length(), "PASSED" if is_probable_prime(p) else "FAILED"))
    print("  generator g: %d" % g)
    print()
    print("Each hospital picks a private value and keeps it secret.")
    a_private = secrets.randbits(256)
    b_private = secrets.randbits(256)
    a_public = pow(g, a_private, p)
    b_public = pow(g, b_private, p)
    print("Hospital A private value: kept secret (256-bit random number)")
    print("Hospital A public value (hex, first 48 chars): %s" % _short_hex(a_public.to_bytes(256, "big")))
    print("Hospital B private value: kept secret (256-bit random number)")
    print("Hospital B public value (hex, first 48 chars): %s" % _short_hex(b_public.to_bytes(256, "big")))
    print()
    print("Public values exchanged over the insecure channel.")
    print("Each side now computes the shared secret on its own:")
    secret_a = pow(b_public, a_private, p)
    secret_b = pow(a_public, b_private, p)
    print("  Hospital A shared secret (SHA-256, first 32 hex): %s"
          % hashlib.sha256(secret_a.to_bytes(256, "big")).hexdigest()[:32])
    print("  Hospital B shared secret (SHA-256, first 32 hex): %s"
          % hashlib.sha256(secret_b.to_bytes(256, "big")).hexdigest()[:32])
    print("Shared secrets match: %s" % (secret_a == secret_b))
    print()
    print("An attacker who saw both public values still cannot work out")
    print("the shared secret without solving the discrete logarithm problem.")


# ---------------------------------------------------------------------------

DEMOS = {"demo2": demo2, "demo3": demo3, "demo4": demo4,
         "demo5": demo5, "demo6": demo6}


def main(argv):
    if len(argv) != 2 or argv[1] not in DEMOS and argv[1] != "demo":
        print(__doc__)
        print("usage: python3 secure_comms.py {demo2|demo3|demo4|demo5|demo6|demo}")
        return 1
    if argv[1] == "demo":
        for name in ("demo2", "demo3", "demo4", "demo5", "demo6"):
            DEMOS[name]()
            print()
    else:
        DEMOS[argv[1]]()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
