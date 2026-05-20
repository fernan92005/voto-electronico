"""Mixnet de descifrado: cada nodo pela una capa, baraja y reenvía."""

from .types import RSAKey


class MixNode:
    """Nodo individual de la mixnet de descifrado."""

    def __init__(self, node_id: str, privkey: RSAKey) -> None:
        """Inicializa el nodo con un identificador y su clave privada de descifrado."""
        raise NotImplementedError

    def receive(self, batch: list) -> None:
        """Recibe un lote de mensajes cifrados desde el nodo anterior (o del votante)."""
        raise NotImplementedError

    def peel_layer(self, msg) -> object:
        """Quita la capa de cifrado correspondiente a este nodo."""
        raise NotImplementedError

    def shuffle(self, batch: list) -> list:
        """Baraja el lote para romper la correlación posicional entrada-salida."""
        raise NotImplementedError

    def forward(self, batch: list, next_node) -> None:
        """Reenvía el lote barajado al siguiente nodo (o al contador si es el último)."""
        raise NotImplementedError
