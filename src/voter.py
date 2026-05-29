"""Cliente votante

Ejecuta el flujo completo del votante: preparación del voto, cegado,
solicitud de firma al administrador, desciego de la firma y emisión por
la mixnet con cifrado por capas
"""
from __future__ import annotations

import json
import logging
import secrets
from typing import List

from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto_utils import (
    voto_a_entero,
    blind,
    encrypt_layer,
    random_coprime,
    unblind,
)
from src.types import RSAKey

logger = logging.getLogger(__name__)


class Voter:
    """Estado y operaciones de un votante individual.

    El flujo es lineal y obligatorio:
    ``preparar_voto`` → ``cegar_voto`` → ``submit_to_admin`` → ``emit_to_mixnet``.
    Llamar a cualquier método fuera de su turno lanza ``RuntimeError``.
    """

    def __init__(
        self,
        voter_id: str,
        admin_pubkey: RSAKey,
        mixnet_pubkeys: List[rsa.RSAPublicKey],
    ) -> None:
        self.voter_id = voter_id
        self.admin_pubkey = admin_pubkey
        self.mixnet_pubkeys = mixnet_pubkeys
        self._state: str = "init"
        # Datos del flujo:
        self.candidate: str | None = None
        self.nonce: bytes | None = None
        self.m: int | None = None
        self.r: int | None = None
        self.blinded: int | None = None
        self.sig_admin: int | None = None

    def _require_state(self, metodo: str, esperado: str) -> None:
        if self._state != esperado:
            raise RuntimeError(
                f"no se puede llamar a {metodo} desde el estado {self._state}"
            )

     
    # Firma ciega

    def preparar_voto(self, candidato: str) -> None:
        """Construye ``m = H(candidato || nonce) mod n``.

        Estado requerido: ``init`` → pasa a ``preparado``.
        """
        self._require_state("preparar_voto", "init")
        logger.info("preparando voto para %s", candidato)
        self.candidate = candidato
        self.nonce = secrets.token_bytes(16)
        self.m = voto_a_entero(candidato, self.nonce, self.admin_pubkey.n)
        self._state = "preparado"

    def cegar_voto(self) -> int:
        """Ciega ``m`` con un factor aleatorio coprimo con ``n``.

        Estado requerido: ``preparado`` → pasa a ``cegado``.
        """
        self._require_state("cegar_voto", "preparado")
        self.r = random_coprime(self.admin_pubkey.n)
        self.blinded = blind(self.m, self.r, self.admin_pubkey)
        self._state = "cegado"
        return self.blinded

    def submit_to_admin(self, admin) -> int:
        """Envía el voto cegado al admin, recibe la firma cegada, la
        deciega y devuelve la firma final del administrador sobre ``m``.

        Estado requerido: ``cegado`` → pasa a ``firmado``.
        """
        self._require_state("submit_to_admin", "cegado")
        s = admin.firmar_voto_cegado(self.voter_id, self.blinded)
        self.sig_admin = unblind(s, self.r, self.admin_pubkey)
        self._state = "firmado"
        return self.sig_admin

# Emisión de mixnet

    def emit_to_mixnet(self) -> bytes:
        """Construye la cebolla y devuelve el mensaje cifrado final.

        El contenido interno es JSON con ``{candidate, nonce, sig}``. Se
        cifra desde el último nodo hacia el primero, de forma que cada
        nodo solo puede descifrar su capa.

        Estado requerido: ``firmado`` → pasa a ``emitido``.
        """
        self._require_state("emit_to_mixnet", "firmado")
        logger.info("emitiendo voto en cebolla para votante %s", self.voter_id)
        payload = json.dumps(
            {
                "candidate": self.candidate,
                "nonce": self.nonce.hex(),
                "sig": self.sig_admin,
            }
        ).encode("utf-8")
        ct = payload
        for pk in reversed(self.mixnet_pubkeys):
            ct = encrypt_layer(ct, pk)
        self._state = "emitido"
        return ct
