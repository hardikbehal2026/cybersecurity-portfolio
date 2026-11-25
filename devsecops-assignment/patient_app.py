"""Secure mini patient application (MCSC-6002 Assignment 5%, Part B).

A console program to register patients (ID + name), save them securely,
and look them up by ID.

Security, as the assignment asks for:
- Confidentiality: names are stored encrypted, and only decrypted when
  they are shown on screen.
- Integrity: a SHA-256 hash is stored with every record and checked on
  every read. A changed record is reported, never shown.
- Input validation: patient IDs must be numbers only. Anything else is
  rejected with a clear message, and the program keeps running.
- Availability: bad input, a missing data file, or a damaged data file
  never crashes the program. Errors are handled and explained.

Honest limit: the encryption here is a teaching demo (a SHA-256 keystream
XOR, the same approach as the earlier labs). It shows the idea of
encrypting at rest, but it is NOT production cryptography. A real clinic
system would use a vetted library, proper key management, and access
control. The key comes from the PATIENT_APP_KEY environment variable;
without one, a clearly labelled demo key is used.
"""

import hashlib
import json
import os
import re
from pathlib import Path

DATA_FILE = Path("patients.json")
APP_KEY = os.environ.get("PATIENT_APP_KEY", "demo-key-assignment-5-only")


def is_valid_id(patient_id):
    """A patient ID is valid only when it is all digits."""
    return bool(patient_id) and patient_id.isdigit()


def is_valid_name(name):
    """Names must have letters in them, and no digits-only input."""
    return bool(name.strip()) and bool(re.search(r"[A-Za-z]", name))


def _keystream(patient_id, length):
    """Bytes to XOR with, built from the app key and the patient ID."""
    stream = b""
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(
            (APP_KEY + ":" + patient_id + ":" + str(counter)).encode()
        ).digest()
        stream += block
        counter += 1
    return stream[:length]


def encrypt_name(name, patient_id):
    """Return the name encrypted, as a hex string."""
    raw = name.encode("utf-8")
    stream = _keystream(patient_id, len(raw))
    mixed = bytes(a ^ b for a, b in zip(raw, stream))
    return mixed.hex()


def decrypt_name(cipher_hex, patient_id):
    """Reverse encrypt_name. Raises ValueError on bad hex."""
    raw = bytes.fromhex(cipher_hex)
    stream = _keystream(patient_id, len(raw))
    plain = bytes(a ^ b for a, b in zip(raw, stream))
    return plain.decode("utf-8")


def record_hash(patient_id, name):
    """SHA-256 hash of one record, used to spot tampering."""
    return hashlib.sha256((patient_id + ":" + name).encode()).hexdigest()


def load_records():
    """Read the data file. A missing or damaged file means empty records,
    never a crash."""
    if not DATA_FILE.exists():
        return {}
    try:
        with open(DATA_FILE, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        print("Warning: the patient data file could not be read. Starting empty.")
        return {}
    if not isinstance(data, dict):
        print("Warning: the patient data file is damaged. Starting empty.")
        return {}
    return data


def save_records(records):
    """Write the records to the data file."""
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as handle:
            json.dump(records, handle, indent=2)
    except OSError:
        print("Error: could not save the patient data file.")
        return False
    return True


def save_patient(patient_id, name):
    """Register one patient. Returns True on success, False if the
    input is invalid."""
    if not is_valid_id(patient_id):
        print("Invalid patient ID: only numbers are allowed.")
        return False
    if not is_valid_name(name):
        print("Invalid name: please enter a real name.")
        return False
    records = load_records()
    records[patient_id] = {
        "name_encrypted": encrypt_name(name.strip(), patient_id),
        "record_hash": record_hash(patient_id, name.strip()),
    }
    if save_records(records):
        print("Patient " + patient_id + " saved.")
        return True
    return False


def find_patient(patient_id):
    """Look up a patient by ID. Returns the name, or None when the ID
    is invalid, missing, or the record has been tampered with."""
    if not is_valid_id(patient_id):
        print("Invalid patient ID: only numbers are allowed.")
        return None
    records = load_records()
    record = records.get(patient_id)
    if record is None:
        print("No patient found with ID " + patient_id + ".")
        return None
    try:
        name = decrypt_name(record["name_encrypted"], patient_id)
    except (KeyError, ValueError):
        print("Record for ID " + patient_id + " is damaged and cannot be read.")
        return None
    if record_hash(patient_id, name) != record.get("record_hash"):
        print("Warning: record for ID " + patient_id + " has been changed!")
        print("The stored hash does not match, so the name is not shown.")
        return None
    return name


def list_patients():
    """Show every stored patient, checking each record's hash first."""
    records = load_records()
    if not records:
        print("No patients stored yet.")
        return
    for patient_id in sorted(records):
        name = find_patient(patient_id)
        if name is not None:
            print(patient_id + ": " + name)


def main():
    """Menu loop. Any bad input just prints a message and asks again."""
    while True:
        print()
        print("Patient records")
        print("1. Register a patient")
        print("2. Search by patient ID")
        print("3. List all patients")
        print("4. Exit")
        try:
            choice = input("Choose 1-4: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print("Goodbye.")
            return
        if choice == "1":
            try:
                patient_id = input("Enter patient ID (numbers only): ").strip()
                name = input("Enter patient name: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                print("Goodbye.")
                return
            save_patient(patient_id, name)
        elif choice == "2":
            try:
                patient_id = input("Enter patient ID to search: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                print("Goodbye.")
                return
            name = find_patient(patient_id)
            if name is not None:
                print("Found: " + patient_id + " - " + name)
        elif choice == "3":
            list_patients()
        elif choice == "4":
            print("Goodbye.")
            return
        else:
            print("That is not a valid choice. Please enter 1, 2, 3 or 4.")


if __name__ == "__main__":
    main()
