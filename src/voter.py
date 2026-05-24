"""Cliente votante.

Ejecuta el flujo completo del votante: preparación del ballot, cegado,
solicitud de firma al administrador, desciego de la firma y emisión por
la mixnet con cifrado por capas.
"""
from __future__ import annotations

import json
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


class Voter:
    """Estado y operaciones de un votante individual."""

    def __init__(
        self,
        voter_id: str,
        admin_pubkey: RSAKey,
        mixnet_pubkeys: List[rsa.RSAPublicKey],
    ) -> None:
        self.voter_id = voter_id
        self.admin_pubkey = admin_pubkey
        self.mixnet_pubkeys = mixnet_pubkeys
        # Estado del flujo:
        self.candidate: str | None = None
        self.nonce: bytes | None = None
        self.m: int | None = None  # m = ballot_to_int(candidate, nonce)
        self.r: int | None = None  # factor de cegado
        self.blinded: int | None = None  # b = blind(m, r)
        self.sig_admin: int | None = None  # sigma = unblind(s, r)

    # ------------------------------------------------------------------
    # Fase 2: firma ciega
    # ------------------------------------------------------------------
    def prepare_ballot(self, candidate: str) -> None:
        """Construye ``m = H(candidate || nonce) mod n``."""
        self.candidate = candidate
        self.nonce = secrets.token_bytes(16)
        self.m = ballot_to_int(candidate, self.nonce, self.admin_pubkey.n)

    def blind_ballot(self) -> int:
        """Cega ``m`` con un factor aleatorio coprimo con ``n``."""
        assert self.m is not None, "llamar a prepare_ballot primero"
        self.r = random_coprime(self.admin_pubkey.n)
        self.blinded = blind(self.m, self.r, self.admin_pubkey)
        return self.blinded

    def submit_to_admin(self, admin) -> int:
        """Envía el ballot cegado al admin, recibe la firma cegada, la
        deciega y devuelve la firma final del administrador sobre ``m``."""
        assert self.blinded is not None, "llamar a blind_ballot primero"
        s = admin.sign_blinded_ballot(self.voter_id, self.blinded)
        assert self.r is not None
        self.sig_admin = unblind(s, self.r, self.admin_pubkey)
        return self.sig_admin

    # ------------------------------------------------------------------
    # Fase 3: emisión por mixnet
    # ------------------------------------------------------------------
    def emit_to_mixnet(self) -> bytes:
        """Construye la cebolla y devuelve el ciphertext final.

        El payload interno es JSON con ``{candidate, nonce, sig}``. Se
        cifra desde el último nodo hacia el primero, de forma que cada
        nodo solo puede descifrar su capa.
        """
        assert self.candidate is not None
        assert self.nonce is not None
        assert self.sig_admin is not None
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
        return ct
