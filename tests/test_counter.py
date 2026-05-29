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


def _voto_valido(keys) -> bytes:
    """Helper: crea un mensaje JSON válido y firmado."""
    admin = Admin(keys["privkey_chaum"])
    admin.register_voter("VC1")
    v = Voter("VC1", keys["pubkey_chaum"], [])
    v.preparar_voto("A")
    v.cegar_voto()
    v.submit_to_admin(admin)
    return json.dumps({
        "candidate": "A",
        "nonce": v.nonce.hex(),
        "sig": v.sig_admin,
    }).encode()


def test_counter_rejects_duplicate_signature(keys):
    """El mismo voto enviado dos veces: el segundo se descarta como
    duplicado y duplicados debe ser 1."""
    payload = _voto_valido(keys)
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    counter.contar([payload, payload])
    assert counter.duplicados == 1
    assert counter.resultado["A"] == 1  # el primero es válido


def test_counter_rejects_malformed_json(keys):
    """Un mensaje que no es JSON válido cuenta como inválido."""
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    counter.contar([b"not valid json {["])
    assert counter.invalidos == 1


def test_counter_rejects_unknown_candidate(keys):
    """Un candidato que no está en la lista cuenta como inválido."""
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    payload = json.dumps({
        "candidate": "Z",
        "nonce": "aabbccdd",
        "sig": 99999,
    }).encode()
    counter.contar([payload])
    assert counter.invalidos == 1


def test_counter_rejects_missing_fields(keys):
    """JSON válido pero sin el campo 'sig' cuenta como inválido."""
    counter = Counter(keys["pubkey_chaum"], ["A", "B"])
    payload = json.dumps({"candidate": "A", "nonce": "aabbccdd"}).encode()
    counter.contar([payload])
    assert counter.invalidos == 1
