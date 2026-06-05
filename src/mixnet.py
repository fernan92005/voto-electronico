"""Nodo de mezcla (mixnode)

Cada nodo recibe un lote de mensajes cifrados, descifra su capa, permuta
aleatoriamente el lote y lo reenvía. La permutación destruye la
correlación entrada-salida: un observador no puede ligar qué ciphertext
de entrada se corresponde con qué payload de salida, siempre y cuando
al menos un nodo de la cadena sea honesto
"""
from __future__ import annotations

import logging
import secrets
from typing import List

from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto_utils import decrypt_layer

logger = logging.getLogger(__name__)


class MixNode:
    """Nodo individual de la mixnet."""

    def __init__(self, node_id: str, privkey: rsa.RSAPrivateKey) -> None:
        self.node_id = node_id
        self.privkey = privkey

    def peel_and_shuffle(self, batch: List[bytes]) -> List[bytes]:
        """Descifra la capa externa de cada mensaje y permuta el lote

        Usa Fisher-Yates con :mod:`secrets` para la permutación uniforme
        criptográficamente segura
        """
        logger.info("peeling+shuffling lote de %d en nodo %s", len(batch), self.node_id)
        peeled = [decrypt_layer(c, self.privkey) for c in batch]
        n = len(peeled)
        # Fisher-Yates con aleatoriedad criptográfica
        for i in range(n - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            peeled[i], peeled[j] = peeled[j], peeled[i]
        return peeled
