"""Operaciones criptográficas del esquema.

- Firma ciega de Chaum sobre RSA (blind, sign_blinded, unblind, verify).
- Generación de claves y mapeo determinista de votos a enteros en Z_n.
- Cifrado por capas para la mixnet (híbrido AES-GCM + RSA-OAEP).

ADVERTENCIA: la firma usa RSA sin padding (textbook). Es necesario para que
se cumpla "(m * r^e)^d = m^d * r (mod n)" y funcione la firma ciega, pero
deja el esquema vulnerable a ataques de mensaje pequeño y maleabilidad.
"""
from __future__ import annotations

import hashlib
import math
import secrets
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.types import RSAKey

# Generación de claves

def generate_rsa_keypair(bits: int = 2048) -> dict:
    """Genera un par de claves RSA.

    Devuelve un diccionario con:
    - priv / pub: objetos de cryptography para el cifrado OAEP.
    - privkey / pubkey: instancias de RSAKey (n, d) y (n, e) para la aritmética.

    El exponente público se fija en e = 65537, el valor estándar.
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    priv_nums = priv.private_numbers()
    pub_nums = pub.public_numbers()
    return {
        "priv": priv,
        "pub": pub,
        "privkey": RSAKey(n=pub_nums.n, exp=priv_nums.d),
        "pubkey": RSAKey(n=pub_nums.n, exp=pub_nums.e),
    }


def random_coprime(n: int) -> int:
    """Genera un entero aleatorio r en [2, n-1] con gcd(r, n) = 1.

    La coprimalidad asegura que exista el inverso r^-1 mod n que usa unblind.
    Con primos RSA grandes el reintento casi nunca ocurre.
    """
    while True:
        r = secrets.randbelow(n - 2) + 2  # r en [2, n-1]
        if math.gcd(r, n) == 1:
            return r



# Firma ciega 

def blind(m: int, r: int, pubkey: RSAKey) -> int:
    """Ciega el mensaje m: devuelve b = m * r^e mod n.

    r debe ser coprimo con n. El cegado oculta m al firmante, ya que r es
    secreto del votante.
    """
    if math.gcd(r, pubkey.n) != 1:
        raise ValueError("el factor de cegado r debe ser coprimo con n")
    return (m * pow(r, pubkey.exp, pubkey.n)) % pubkey.n


def sign_blinded(b: int, privkey: RSAKey) -> int:
    """Firma RSA estándar del mensaje cegado: s = b^d mod n.

    El firmante no hace nada especial; la lógica del cegado está en el votante.
    """
    return pow(b, privkey.exp, privkey.n)


def unblind(s: int, r: int, pubkey: RSAKey) -> int:
    """Quita el cegado: sigma = s * r^-1 mod n.

    Como s = (m * r^e)^d = m^d * r, se obtiene sigma = m^d, la firma de m.
    """
    r_inv = pow(r, -1, pubkey.n)  # inverso modular (Python 3.8+)
    return (s * r_inv) % pubkey.n


def verify(m: int, sig: int, pubkey: RSAKey) -> bool:
    """Verificación RSA estándar: comprueba sig^e == m (mod n)."""
    return pow(sig, pubkey.exp, pubkey.n) == (m % pubkey.n)

# Mapeo determinista de votos a entero en Z_n

def voto_a_entero(candidato: str, nonce: bytes, modulo: int) -> int:
    """Convierte (candidato, nonce) en un entero de [0, modulo) con SHA-256.

    Hashear antes de firmar mitiga los problemas de RSA textbook (estilo
    RSA-FDH): distribuye el mensaje sobre Z_n y elimina la estructura que
    explotan los ataques. El nonce evita que dos votos iguales coincidan.
    SHA-256 solo da 256 bits frente a los 2048 de n; en producción se usaría
    MGF1 o SHAKE para cubrir todo Z_n.
    """
    data = candidato.encode("utf-8") + b"|" + nonce
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % modulo


# Cifrado por capas para la mixnet (AES-GCM + RSA-OAEP)

_OAEP_PADDING = OAEP(
    mgf=MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def encrypt_layer(plaintext: bytes, pubkey: rsa.RSAPublicKey) -> bytes:
    """Cifra una capa con cifrado híbrido (AES-GCM 256 + RSA-OAEP).

    El contenido se cifra con AES-GCM bajo una clave aleatoria, y esa clave
    se cifra con RSA-OAEP. Formato concatenado : longitud || rsa_ct || iv || aes_ct.
    """
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    aes_ct = AESGCM(aes_key).encrypt(iv, plaintext, None)
    rsa_ct = pubkey.encrypt(aes_key, _OAEP_PADDING)
    return struct.pack(">H", len(rsa_ct)) + rsa_ct + iv + aes_ct


def decrypt_layer(ciphertext: bytes, privkey: rsa.RSAPrivateKey) -> bytes:
    """Inversa de encrypt_layer."""
    (rsa_ct_len,) = struct.unpack(">H", ciphertext[:2])
    rsa_ct = ciphertext[2:2 + rsa_ct_len]
    rest = ciphertext[2 + rsa_ct_len:]
    iv = rest[:12]
    aes_ct = rest[12:]
    aes_key = privkey.decrypt(rsa_ct, _OAEP_PADDING)
    return AESGCM(aes_key).decrypt(iv, aes_ct, None)
