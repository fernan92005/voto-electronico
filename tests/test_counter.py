"""Tests del contador electoral."""
import json

import pytest

from src.admin import Admin
from src.counter import Counter
from src.crypto_utils import generate_rsa_keypair
from src.voter import Voter


@pytest.fixture(scope="module")
def keys():
    return generate_rsa_keypair(bits=2048)


def _make_valid_payload(keys) -> tuple[bytes, Voter]:
    """Helper: crea un payload JSON válido y firmado."""
    admin = Admin(keys["privkey_chaum"])
    admin.register_voter("VC1")
    v = Voter("VC1", keys["pubkey_chaum"], [])
    v.prepare_ballot("A")
    v.blind_ballot()
    v.submit_to_admin(admin)
    payload = json.dumps({
        "candidate": "A",
        "nonce": v.nonce.hex(),
        "sig": v.sig_admin,
    }).encode()
    return payload, v


def test_counter_rejects_duplicate_signature(keys):
    """Un payload idéntico enviado dos veces: el segundo se descarta como
    duplicado y duplicate_count debe ser 1."""
    payload, _ = _make_valid_payload(keys)
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    counter.tally([payload, payload])
    assert counter.duplicate_count == 1
    assert counter.tally_result["A"] == 1  # el primero es válido


def test_counter_rejects_malformed_json(keys):
    """Payload que no es JSON válido cuenta como inválido."""
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    counter.tally([b"not valid json {["])
    assert counter.invalid_count == 1


def test_counter_rejects_unknown_candidate(keys):
    """Candidato fuera de la lista esperada cuenta como inválido."""
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    payload = json.dumps({
        "candidate": "Z",
        "nonce": "aabbccdd",
        "sig": 99999,
    }).encode()
    counter.tally([payload])
    assert counter.invalid_count == 1


def test_counter_rejects_missing_fields(keys):
    """JSON válido pero sin el campo 'sig' cuenta como inválido."""
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    payload = json.dumps({"candidate": "A", "nonce": "aabbccdd"}).encode()
    counter.tally([payload])
    assert counter.invalid_count == 1
