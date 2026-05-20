"""Administrador electoral: firma ciega de papeletas para votantes registrados."""

from .types import RSAKey


class Admin:
    """Actor 'administrador' del protocolo."""

    def __init__(self, privkey: RSAKey) -> None:
        """Inicializa el administrador con su clave privada de firma."""
        self._already_signed: set[str] = set()
        raise NotImplementedError

    def register_voter(self, voter_id: str, voter_cert) -> None:
        """Registra a un votante autorizado mediante su certificado."""
        raise NotImplementedError

    def sign_blinded_ballot(self, voter_id: str, blinded: int) -> int:
        """Firma el valor cegado si el votante está registrado y no ha votado aún."""
        raise NotImplementedError
