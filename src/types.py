"""Tipos compartidos por todos los módulos."""
from dataclasses import dataclass


@dataclass(frozen=True)
class RSAKey:
    """Representación mínima de una clave RSA

    Se usa la misma estructura para clave pública (exp = e) y privada (exp = d).
    Las operaciones de firma ciega trabajan directamente con (n, exp) sin
    necesidad de objetos de la librería cryptography
    """

    n: int
    exp: int

    def __repr__(self) -> str:  # pragma: no cover
        return f"RSAKey(n={self.n.bit_length()} bits, exp={self.exp})"
