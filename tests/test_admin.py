"""Tests del administrador electoral."""
import pytest

from src.admin import Admin
from src.crypto_utils import blind, generate_rsa_keypair, random_coprime


@pytest.fixture(scope="module")
def keys():
    return generate_rsa_keypair(bits=2048)


def test_admin_signs_authorized_voter(keys):
    admin = Admin(keys["privkey_chaum"])
    admin.register_voter("V1")
    pub = keys["pubkey_chaum"]
    r = random_coprime(pub.n)
    b = blind(12345, r, pub)
    s = admin.sign_blinded_ballot("V1", b)
    assert isinstance(s, int)
    assert s > 0


def test_admin_rejects_unauthorized(keys):
    admin = Admin(keys["privkey_chaum"])
    # V_NOT no registrado
    with pytest.raises(PermissionError):
        admin.sign_blinded_ballot("V_NOT", 12345)


def test_admin_rejects_double_voting(keys):
    admin = Admin(keys["privkey_chaum"])
    admin.register_voter("V1")
    admin.sign_blinded_ballot("V1", 12345)
    with pytest.raises(ValueError):
        admin.sign_blinded_ballot("V1", 67890)


def test_admin_serves_multiple_distinct_voters(keys):
    admin = Admin(keys["privkey_chaum"])
    for vid in ("V1", "V2", "V3"):
        admin.register_voter(vid)
    s1 = admin.sign_blinded_ballot("V1", 100)
    s2 = admin.sign_blinded_ballot("V2", 200)
    s3 = admin.sign_blinded_ballot("V3", 300)
    assert s1 != s2 != s3
    assert admin.served == {"V1", "V2", "V3"}


def test_admin_voter_set_grows_with_registration(keys):
    """Registrar 3 votantes debe dejar admin.eligible con cardinalidad 3."""
    admin = Admin(keys["privkey_chaum"])
    for vid in ("VA", "VB", "VC"):
        admin.register_voter(vid)
    assert len(admin.eligible) == 3
