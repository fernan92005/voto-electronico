"""Tests de la firma ciega de Chaum y utilidades criptográficas."""
import math

import pytest

from src.crypto_utils import (
    voto_a_entero,
    blind,
    decrypt_layer,
    encrypt_layer,
    generate_rsa_keypair,
    random_coprime,
    sign_blinded,
    unblind,
    verify,
)
from src.types import RSAKey


@pytest.fixture(scope="module")
def keys():
    return generate_rsa_keypair(bits=2048)


def test_keypair_generation(keys):
    assert keys["pubkey_chaum"].exp == 65537
    assert keys["privkey_chaum"].n == keys["pubkey_chaum"].n
    assert keys["pubkey_chaum"].n.bit_length() >= 2047


def test_blind_sign_unblind_verify_roundtrip(keys):
    pub = keys["pubkey_chaum"]
    priv = keys["privkey_chaum"]
    m = 12345678901234567890
    r = random_coprime(pub.n)
    b = blind(m, r, pub)
    s = sign_blinded(b, priv)
    sig = unblind(s, r, pub)
    assert verify(m, sig, pub)


def test_signer_does_not_see_message(keys):
    pub = keys["pubkey_chaum"]
    m = 42
    r1 = random_coprime(pub.n)
    r2 = random_coprime(pub.n)
    b1 = blind(m, r1, pub)
    b2 = blind(m, r2, pub)
    # Distintos r producen distintos b, y ninguno coincide con m
    assert b1 != b2
    assert b1 != m
    assert b2 != m


def test_invalid_blinding_factor_raises():
    fake_pub = RSAKey(n=6, exp=3)  # n = 2 * 3
    # r=2 no es coprimo con n=6 (gcd=2)
    with pytest.raises(ValueError):
        blind(5, 2, fake_pub)


def test_verify_rejects_tampered_signature(keys):
    pub = keys["pubkey_chaum"]
    priv = keys["privkey_chaum"]
    m = 7777777
    r = random_coprime(pub.n)
    b = blind(m, r, pub)
    s = sign_blinded(b, priv)
    sig = unblind(s, r, pub)
    tampered = sig ^ 1  # cambia el último bit
    assert not verify(m, tampered, pub)


def test_chaum_example_paper_numbers():
    """Validación con los números pedagógicos del paper (RSA juguete).

    p=7, q=11, n=77, e=13, d=37, m=19, r=2 deben producir b=31, s=59,
    sig=68 y verify=True. Sirve para comprobar que la matemática es correcta.
    """
    pub = RSAKey(n=77, exp=13)
    priv = RSAKey(n=77, exp=37)
    m = 19
    r = 2
    b = blind(m, r, pub)
    assert b == 31
    s = sign_blinded(b, priv)
    assert s == 59
    sig = unblind(s, r, pub)
    assert sig == 68
    assert verify(m, sig, pub) is True


def test_random_coprime_returns_coprime():
    n = 30
    for _ in range(20):
        r = random_coprime(n)
        assert math.gcd(r, n) == 1
        assert 2 <= r <= n - 1


def test_voto_a_entero_determinista():
    n = 2 ** 100  # módulo arbitrario
    nonce = b"\x01" * 16
    a = voto_a_entero("CandidateA", nonce, n)
    b = voto_a_entero("CandidateA", nonce, n)
    c = voto_a_entero("CandidateB", nonce, n)
    assert a == b
    assert a != c


def test_encrypt_decrypt_layer_roundtrip(keys):
    plaintext = b"un mensaje secreto" * 10
    ct = encrypt_layer(plaintext, keys["pub"])
    recovered = decrypt_layer(ct, keys["priv"])
    assert recovered == plaintext
