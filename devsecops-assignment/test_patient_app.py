"""Tests for patient_app.py (MCSC-6002 Assignment 5%, Part B).

Run with: pytest test_patient_app.py -v
"""

import json

import patient_app


def test_valid_registration_and_search(tmp_path, monkeypatch):
    """A valid patient can be saved and found again by ID."""
    monkeypatch.chdir(tmp_path)
    assert patient_app.save_patient("1001", "Aarav Sharma") is True
    assert patient_app.find_patient("1001") == "Aarav Sharma"


def test_name_is_stored_encrypted(tmp_path, monkeypatch):
    """The stored name must not be readable as plain text, and the
    stored hash must match the record."""
    monkeypatch.chdir(tmp_path)
    patient_app.save_patient("1002", "Priya Nair")
    with open(patient_app.DATA_FILE, encoding="utf-8") as handle:
        stored = json.load(handle)
    assert "Priya Nair" not in json.dumps(stored)
    record = stored["1002"]
    assert record["record_hash"] == patient_app.record_hash("1002", "Priya Nair")
    assert patient_app.decrypt_name(record["name_encrypted"], "1002") == "Priya Nair"


def test_invalid_id_is_rejected(tmp_path, monkeypatch):
    """A non-numeric ID is rejected and nothing is saved."""
    monkeypatch.chdir(tmp_path)
    assert patient_app.save_patient("12AB", "Test Person") is False
    assert patient_app.save_patient("1001; echo hi", "Test Person") is False
    assert patient_app.find_patient("12AB") is None
    assert patient_app.load_records() == {}


def test_tampered_record_is_detected(tmp_path, monkeypatch):
    """If the stored name is changed without updating the hash,
    the lookup refuses to show it."""
    monkeypatch.chdir(tmp_path)
    patient_app.save_patient("1003", "Rohan Mehta")
    with open(patient_app.DATA_FILE, encoding="utf-8") as handle:
        stored = json.load(handle)
    stored["1003"]["name_encrypted"] = patient_app.encrypt_name("Someone Else", "1003")
    with open(patient_app.DATA_FILE, "w", encoding="utf-8") as handle:
        json.dump(stored, handle)
    assert patient_app.find_patient("1003") is None


def test_missing_patient_returns_none(tmp_path, monkeypatch):
    """Searching for an ID that was never saved returns None."""
    monkeypatch.chdir(tmp_path)
    assert patient_app.find_patient("9999") is None
