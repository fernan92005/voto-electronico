"""Tests del cliente votante."""
import pytest

from src.admin import Admin
from src.crypto_utils import ballot_to_int, generate_rsa_keypair, verify
from src.voter import Voter


@pytest.fixture(scope="module")
def keys():
    return {
        "admin": generate_rsa_keypair(bits=2048),
        "m1": generate_rsa_keypair(bits=2048),
        "m2": generate_rsa_keypair(bits=2048),
    }


def test_voter_full_flow(keys):
    admin = Admin(keys["admin"]["privkey_chaum"])
    admin.register_voter("V1")
    mixnet_pubs = [keys["m1"]["pub"], keys["m2"]["pub"]]
    v = Voter("V1", keys["admin"]["pubkey_chaum"], mixnet_pubs)

    v.prepare_ballot("A")
    v.blind_ballot()
    sig = v.submit_to_admin(admin)

    # La firma desciegada es válida sobre m = H(candidate||nonce)
    m = ballot_to_int("A", v.nonce, keys["admin"]["pubkey_chaum"].n)
    assert verify(m, sig, keys["admin"]["pubkey_chaum"]) is True


def test_voter_emit_to_mixnet_produces_bytes(keys):
    admin = Admin(keys["admin"]["privkey_chaum"])
    admin.register_voter("V2")
    mixnet_pubs = [keys["m1"]["pub"], keys["m2"]["pub"]]
    v = Voter("V2", keys["admin"]["pubkey_chaum"], mixnet_pubs)
    v.prepare_ballot("B")
    v.blind_ballot()
    v.submit_to_admin(admin)
    ct = v.emit_to_mixnet()
    assert isinstance(ct, bytes)
    assert len(ct) > 0


def test_voter_blinded_value_does_not_equal_message(keys):
    admin = Admin(keys["admin"]["privkey_chaum"])
    admin.register_voter("V3")
    mixnet_pubs = [keys["m1"]["pub"], keys["m2"]["pub"]]
    v = Voter("V3", keys["admin"]["pubkey_chaum"], mixnet_pubs)
    v.prepare_ballot("A")
    v.blind_ballot()
    assert v.blinded != v.m  # propiedad blindness a nivel sintáctico


def test_voter_emit_before_submit_raises(keys):
    """emit_to_mixnet sin haber completado el flujo lanza RuntimeError."""
    v = Voter("VX", keys["admin"]["pubkey_chaum"], [])
    with pytest.raises(RuntimeError):
        v.emit_to_mixnet()


def test_voter_blind_before_prepare_raises(keys):
    """blind_ballot antes de prepare_ballot lanza RuntimeError."""
    v = Voter("VX", keys["admin"]["pubkey_chaum"], [])
    with pytest.raises(RuntimeError):
        v.blind_ballot()


def test_voter_double_prepare_raises(keys):
    """Llamar prepare_ballot dos veces consecutivas lanza RuntimeError."""
    v = Voter("VX", keys["admin"]["pubkey_chaum"], [])
    v.prepare_ballot("A")
    with pytest.raises(RuntimeError):
        v.prepare_ballot("B")
