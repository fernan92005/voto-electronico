"""Cliente votante.

Ejecuta el flujo completo del votante: preparación del ballot, cegado,
solicitud de firma al administrador, desciego de la firma y emisión por
la mixnet con cifrado por capas.
"""
from __future__ import annotations

import json
import logging
import secrets
from typing import List

from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto_utils import (
    ballot_to_int,
    blind,
    encrypt_layer,
    random_coprime,
    unblind,
)
from src.types import RSAKey

logger = logging.getLogger(__name__)


class Voter:
    """Estado y operaciones de un votante individual.

    El flujo obligatorio es lineal:
    ``prepare_ballot`` → ``blind_ballot`` → ``submit_to_admin`` → ``emit_to_mixnet``.
    Llamar a cualquier método fuera de su estado esperado lanza ``RuntimeError``.
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

    def _require_state(self, method: str, expected: str) -> None:
        if self._state != expected:
            raise RuntimeError(
                f"no se puede llamar a {method} desde el estado {self._state}"
            )

    # ------------------------------------------------------------------
    # Fase 2: firma ciega
    # ------------------------------------------------------------------
    def prepare_ballot(self, candidate: str) -> None:
        """Construye ``m = H(candidate || nonce) mod n``.

        Estado requerido: ``init`` → pasa a ``prepared``.
        """
        self._require_state("prepare_ballot", "init")
        logger.info("preparando ballot para %s", candidate)
        self.candidate = candidate
        self.nonce = secrets.token_bytes(16)
        self.m = ballot_to_int(candidate, self.nonce, self.admin_pubkey.n)
        self._state = "prepared"

    def blind_ballot(self) -> int:
        """Cega ``m`` con un factor aleatorio coprimo con ``n``.

        Estado requerido: ``prepared`` → pasa a ``blinded``.
        """
        self._require_state("blind_ballot", "prepared")
        self.r = random_coprime(self.admin_pubkey.n)
        self.blinded = blind(self.m, self.r, self.admin_pubkey)
        self._state = "blinded"
        return self.blinded

    def submit_to_admin(self, admin) -> int:
        """Envía el ballot cegado al admin, recibe la firma cegada, la
        deciega y devuelve la firma final del administrador sobre ``m``.

        Estado requerido: ``blinded`` → pasa a ``signed``.
        """
        self._require_state("submit_to_admin", "blinded")
        s = admin.sign_blinded_ballot(self.voter_id, self.blinded)
        self.sig_admin = unblind(s, self.r, self.admin_pubkey)
        self._state = "signed"
        return self.sig_admin

    # ------------------------------------------------------------------
    # Fase 3: emisión por mixnet
    # ------------------------------------------------------------------
    def emit_to_mixnet(self) -> bytes:
        """Construye la cebolla y devuelve el ciphertext final.

        El payload interno es JSON con ``{candidate, nonce, sig}``. Se
        cifra desde el último nodo hacia el primero, de forma que cada
        nodo solo puede descifrar su capa.

        Estado requerido: ``signed`` → pasa a ``emitted``.
        """
        self._require_state("emit_to_mixnet", "signed")
        logger.info("emitiendo cebolla para votante %s", self.voter_id)
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
        self._state = "emitted"
        return ct
