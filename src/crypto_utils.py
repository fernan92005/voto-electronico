"""Operaciones criptográficas del esquema.

Contiene:
- La construcción de firma ciega de Chaum sobre RSA *textbook*
  (cuatro operaciones: ``blind``, ``sign_blinded``, ``unblind``, ``verify``).
- Utilidades de generación de claves y de mapeo determinista de votos a
  enteros en ``Z_n``.
- Cifrado/descifrado por capas para la mixnet (esquema híbrido AES-GCM
  + RSA-OAEP).

ADVERTENCIA
-----------
La operación de firma usa RSA *sin padding* (textbook). Esto es necesario
para que la propiedad multiplicativa
``(m * r^e)^d = m^d * r (mod n)`` se cumpla y la firma ciega funcione, pero
deja el esquema vulnerable a ataques de mensajes pequeños y a la
*maleabilidad multiplicativa*. En producción se usa el esquema RSA-FDH
(Full Domain Hash, Bellare-Rogaway 1996). Aquí se mantiene textbook por
claridad pedagógica.
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


# ----------------------------------------------------------------------------
# Generación de claves
# ----------------------------------------------------------------------------

def generate_rsa_keypair(bits: int = 2048) -> dict:
    """Genera un par de claves RSA.

    Devuelve un diccionario con cuatro entradas:

    - ``'priv'``: objeto ``RSAPrivateKey`` de la librería ``cryptography``,
      usado para el cifrado por capas (OAEP).
    - ``'pub'``: clave pública correspondiente.
    - ``'privkey_chaum'``: instancia de :class:`RSAKey` con (n, d), para las
      operaciones aritméticas de Chaum.
    - ``'pubkey_chaum'``: instancia de :class:`RSAKey` con (n, e=65537).

    El exponente público se fija en ``e = 65537`` (número de Fermat F4),
    el valor estándar por su equilibrio entre seguridad y velocidad.
    """
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = priv.public_key()
    priv_nums = priv.private_numbers()
    pub_nums = pub.public_numbers()
    return {
        "priv": priv,
        "pub": pub,
        "privkey_chaum": RSAKey(n=pub_nums.n, exp=priv_nums.d),
        "pubkey_chaum": RSAKey(n=pub_nums.n, exp=pub_nums.e),
    }


def random_coprime(n: int) -> int:
    """Genera un entero aleatorio ``r ∈ [2, n-1]`` con ``gcd(r, n) = 1``.

    La coprimalidad es necesaria para que exista el inverso ``r^{-1} mod n``
    que necesita :func:`unblind`. Con primos grandes de RSA la probabilidad
    de encontrar un ``r`` no coprimo por azar es despreciable; el bucle de
    reintento se incluye por completitud.
    """
    while True:
        r = secrets.randbelow(n - 2) + 2  # r en [2, n-1]
        if math.gcd(r, n) == 1:
            return r


# ----------------------------------------------------------------------------
# Firma ciega de Chaum (las cuatro operaciones)
# ----------------------------------------------------------------------------

def blind(m: int, r: int, pubkey: RSAKey) -> int:
    """Ciega el mensaje ``m`` con el factor aleatorio ``r``.

    Devuelve ``b = m * r^e mod n``. El parámetro ``r`` debe ser coprimo con
    ``n``; si no lo es se lanza ``ValueError``.

    El cegado oculta el contenido al firmante: dado ``b``, el firmante no
    puede recuperar ``m`` porque ``r`` es secreto del votante.
    """
    if math.gcd(r, pubkey.n) != 1:
        raise ValueError("el factor de cegado r debe ser coprimo con n")
    return (m * pow(r, pubkey.exp, pubkey.n)) % pubkey.n


def sign_blinded(b: int, privkey: RSAKey) -> int:
    """Firma RSA estándar del mensaje cegado: ``s = b^d mod n``.

    El firmante no hace nada especial aquí. Toda la lógica del cegado
    vive en el lado del votante (en :func:`blind` y :func:`unblind`).
    """
    return pow(b, privkey.exp, privkey.n)


def unblind(s: int, r: int, pubkey: RSAKey) -> int:
    """Quita el cegado de la firma: ``sigma = s * r^{-1} mod n``.

    Por la conmutatividad del cegado con la firma RSA,
    ``s = b^d = (m r^e)^d = m^d r^{ed} = m^d r``, luego
    ``sigma = m^d r r^{-1} = m^d``, que es la firma RSA estándar de ``m``.
    """
    r_inv = pow(r, -1, pubkey.n)  # inverso modular (Python 3.8+)
    return (s * r_inv) % pubkey.n


def verify(m: int, sig: int, pubkey: RSAKey) -> bool:
    """Verificación RSA estándar: comprueba ``sig^e ≡ m (mod n)``.

    Es la misma operación que se usaría para verificar una firma RSA
    normal; el verificador no distingue si la firma se produjo por el
    método ciego o directamente.
    """
    return pow(sig, pubkey.exp, pubkey.n) == (m % pubkey.n)


# ----------------------------------------------------------------------------
# Mapeo determinista de votos a entero en Z_n
# ----------------------------------------------------------------------------

def voto_a_entero(candidato: str, nonce: bytes, modulo: int) -> int:
    """Convierte (candidato, nonce) a un entero en ``[0, modulo)`` usando
    SHA-256.

    Esta función mitiga *parcialmente* los problemas de RSA textbook al
    hashear el mensaje antes de firmarlo, en la línea del esquema
    RSA-FDH (Full Domain Hash, Bellare-Rogaway 1996): el hash distribuye
    el dominio de mensajes uniformemente sobre ``Z_n``, eliminando la
    estructura algebraica que explotan los ataques de mensaje pequeño y
    el forjado existencial. El nonce de 16 bytes garantiza además que
    dos votos al mismo candidato producen valores distintos. La diferencia
    con RSA-FDH puro es que SHA-256 tiene imagen de 256 bits frente a los
    2048 de ``n``; en producción se usaría MGF1 o SHAKE para cubrir
    todo ``Z_n``.
    """
    data = candidato.encode("utf-8") + b"|" + nonce
    digest = hashlib.sha256(data).digest()
    return int.from_bytes(digest, "big") % modulo


# ----------------------------------------------------------------------------
# Cifrado por capas para la mixnet (AES-GCM + RSA-OAEP)
# ----------------------------------------------------------------------------

_OAEP_PADDING = OAEP(
    mgf=MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def encrypt_layer(plaintext: bytes, pubkey: rsa.RSAPublicKey) -> bytes:
    """Cifra una capa con cifrado híbrido (AES-GCM 256 + RSA-OAEP).

    El contenido se cifra con AES-GCM bajo una clave AES aleatoria;
    esa clave se cifra con la clave pública del nodo usando RSA-OAEP.
    El resultado se serializa como ``longitud || rsa_ct || iv || aes_ct``.
    """
    aes_key = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)
    aes_ct = AESGCM(aes_key).encrypt(iv, plaintext, None)
    rsa_ct = pubkey.encrypt(aes_key, _OAEP_PADDING)
    return struct.pack(">H", len(rsa_ct)) + rsa_ct + iv + aes_ct


def decrypt_layer(ciphertext: bytes, privkey: rsa.RSAPrivateKey) -> bytes:
    """Inversa de :func:`encrypt_layer`."""
    (rsa_ct_len,) = struct.unpack(">H", ciphertext[:2])
    rsa_ct = ciphertext[2:2 + rsa_ct_len]
    rest = ciphertext[2 + rsa_ct_len:]
    iv = rest[:12]
    aes_ct = rest[12:]
    aes_key = privkey.decrypt(rsa_ct, _OAEP_PADDING)
    return AESGCM(aes_key).decrypt(iv, aes_ct, None)
