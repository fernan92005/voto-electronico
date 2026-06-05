"""Tests del cliente votante."""
import pytest

from src.admin import Admin
from src.crypto_utils import voto_a_entero, generate_rsa_keypair, verify
from src.voter import Voter


@pytest.fixture(scope="module")
def keys():
    return {
        "admin": generate_rsa_keypair(bits=2048),
        "m1": generate_rsa_keypair(bits=2048),
        "m2": generate_rsa_keypair(bits=2048),
    }


def test_voter_full_flow(keys):
    admin = Admin(keys["admin"]["privkey"])
    admin.register_voter("V1")
    mixnet_pubs = [keys["m1"]["pub"], keys["m2"]["pub"]]
    v = Voter("V1", keys["admin"]["pubkey"], mixnet_pubs)

    v.preparar_voto("A")
    v.cegar_voto()
    sig = v.submit_to_admin(admin)

    # La firma desciegada es válida sobre m = H(candidato||nonce)
    m = voto_a_entero("A", v.nonce, keys["admin"]["pubkey"].n)
    assert verify(m, sig, keys["admin"]["pubkey"]) is True


def test_voter_emit_to_mixnet_produces_bytes(keys):
    admin = Admin(keys["admin"]["privkey"])
    admin.register_voter("V2")
    mixnet_pubs = [keys["m1"]["pub"], keys["m2"]["pub"]]
    v = Voter("V2", keys["admin"]["pubkey"], mixnet_pubs)
    v.preparar_voto("B")
    v.cegar_voto()
    v.submit_to_admin(admin)
    ct = v.emit_to_mixnet()
    assert isinstance(ct, bytes)
    assert len(ct) > 0


def test_voter_blinded_value_does_not_equal_message(keys):
    admin = Admin(keys["admin"]["privkey"])
    admin.register_voter("V3")
    mixnet_pubs = [keys["m1"]["pub"], keys["m2"]["pub"]]
    v = Voter("V3", keys["admin"]["pubkey"], mixnet_pubs)
    v.preparar_voto("A")
    v.cegar_voto()
    assert v.blinded != v.m  # el cegado oculta el voto real


def test_voter_emit_before_submit_raises(keys):
    """emit_to_mixnet sin haber completado el flujo lanza RuntimeError."""
    v = Voter("VX", keys["admin"]["pubkey"], [])
    with pytest.raises(RuntimeError):
        v.emit_to_mixnet()


def test_voter_blind_before_prepare_raises(keys):
    """cegar_voto antes de preparar_voto lanza RuntimeError."""
    v = Voter("VX", keys["admin"]["pubkey"], [])
    with pytest.raises(RuntimeError):
        v.cegar_voto()


def test_voter_double_prepare_raises(keys):
    """Llamar preparar_voto dos veces seguidas lanza RuntimeError."""
    v = Voter("VX", keys["admin"]["pubkey"], [])
    v.preparar_voto("A")
    with pytest.raises(RuntimeError):
        v.preparar_voto("B")
