"""Contador final: verifica firmas y tabula los votos."""

from .types import RSAKey


class Counter:
    """Actor 'contador' del protocolo."""

    def __init__(self, admin_pubkey: RSAKey, candidates: list[str]) -> None:
        """Inicializa el contador con la clave pública del admin y la lista de candidatos."""
        raise NotImplementedError

    def tally(self, batch: list) -> dict[str, int]:
        """Verifica cada papeleta firmada y devuelve el recuento por candidato."""
        raise NotImplementedError
