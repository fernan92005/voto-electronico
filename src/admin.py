"""
Administrador electoral

Mantiene la lista de votantes elegibles y un registro de los que ya
han votado. Firma ciegamente los votos de votantes autorizados
"""
from __future__ import annotations

import logging

from src.crypto_utils import sign_blinded
from src.types import RSAKey

logger = logging.getLogger(__name__)


class Admin:
    """Autoridad de registro y firma ciega

    Posee la clave privada d que firma los votos cegados
    """

    def __init__(self, privkey: RSAKey) -> None:
        self.privkey = privkey
        self.eligible: set[str] = set()
        self.served: set[str] = set()

    def register_voter(self, voter_id: str) -> None:
        """Añade un votante a la lista de elegibles"""
        self.eligible.add(voter_id)

    def firmar_voto_cegado(self, voter_id: str, blinded: int) -> int:
        """Firma un voto cegado tras comprobar que el votante está
        registrado y que no ha votado ya

        Lanza PermissionError si el votante no está en la lista y
        ValueError si ya votó
        """
        if voter_id not in self.eligible:
            logger.info("rechazado por no estar en la lista: %s", voter_id)
            raise PermissionError(f"votante {voter_id} no autorizado")
        if voter_id in self.served:
            logger.info("rechazado por intento de doble voto: %s", voter_id)
            raise ValueError(f"votante {voter_id} ya votó")

        logger.info("firmando voto de %s", voter_id)
        self.served.add(voter_id)
        return sign_blinded(blinded, self.privkey)
