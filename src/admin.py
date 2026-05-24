"""Administrador electoral.

Mantiene la lista de votantes elegibles y un registro de IDs ya servidos.
Firma ciegamente los ballots de votantes autorizados, garantizando
``eligibility`` y ``uniqueness``.
"""
from __future__ import annotations

import logging

from src.crypto_utils import sign_blinded
from src.types import RSAKey

logger = logging.getLogger(__name__)


class Admin:
    """Autoridad de registro y firma ciega.

    Posee la clave privada ``d`` que firma los ballots cegados.
    """

    def __init__(self, privkey: RSAKey) -> None:
        self.privkey = privkey
        self.eligible: set[str] = set()
        self.served: set[str] = set()

    def register_voter(self, voter_id: str) -> None:
        """Añade un votante a la lista de elegibles."""
        self.eligible.add(voter_id)

    def sign_blinded_ballot(self, voter_id: str, blinded: int) -> int:
        """Firma un ballot cegado tras validar eligibility y uniqueness.

        Lanza ``PermissionError`` si el votante no está en la whitelist y
        ``ValueError`` si ya fue servido.
        """
        if voter_id not in self.eligible:
            logger.info("rechazado por no estar en whitelist: %s", voter_id)
            raise PermissionError(f"votante {voter_id} no autorizado")
        if voter_id in self.served:
            logger.info("rechazado por doble voto: %s", voter_id)
            raise ValueError(f"votante {voter_id} ya fue servido")
        logger.info("firmando ballot de %s", voter_id)
        self.served.add(voter_id)
        return sign_blinded(blinded, self.privkey)
