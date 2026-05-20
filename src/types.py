"""Tipos de datos del protocolo de voto electrónico."""

from dataclasses import dataclass


@dataclass(frozen=True)
class RSAKey:
    """Clave RSA. Sirve tanto para pública (exp=e) como para privada (exp=d)."""

    n: int
    exp: int


@dataclass(frozen=True)
class Ballot:
    """Papeleta en claro: candidato elegido más un nonce para evitar colisiones."""

    candidate: str
    nonce: bytes


@dataclass(frozen=True)
class BlindedBallot:
    """Papeleta cegada lista para enviar al administrador."""

    value: int
    voter_id: str


@dataclass(frozen=True)
class SignedBallot:
    """Papeleta en claro acompañada de la firma del administrador."""

    ballot: Ballot
    admin_signature: int
