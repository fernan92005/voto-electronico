"""Primitivas criptográficas: RSA y firma ciega de Chaum."""

from .types import RSAKey


def generate_rsa_keypair(bits: int = 2048) -> tuple[RSAKey, RSAKey]:
    """Genera un par de claves RSA. Devuelve (pubkey, privkey)."""
    raise NotImplementedError


def blind(m: int, r: int, pubkey: RSAKey) -> int:
    """Ciega el mensaje m con el factor r usando la clave pública: b = m * r^e mod n."""
    raise NotImplementedError


def sign_blinded(b: int, privkey: RSAKey) -> int:
    """Firma el valor cegado con la clave privada: s' = b^d mod n."""
    raise NotImplementedError


def unblind(s: int, r: int, pubkey: RSAKey) -> int:
    """Quita el factor de cegado: s = s' * r^-1 mod n."""
    raise NotImplementedError


def verify(m: int, sig: int, pubkey: RSAKey) -> bool:
    """Verifica una firma RSA sobre m: sig^e mod n == m."""
    raise NotImplementedError


def random_coprime(n: int) -> int:
    """Devuelve un entero aleatorio coprimo con n, válido como factor de cegado."""
    raise NotImplementedError
