"""Cliente del votante: prepara, ciega, firma y emite la papeleta."""

from .types import Ballot, BlindedBallot, RSAKey, SignedBallot


class Voter:
    """Actor 'votante' del protocolo."""

    def __init__(
        self,
        voter_id: str,
        admin_pubkey: RSAKey,
        mixnet_pubkeys: list[RSAKey],
    ) -> None:
        """Inicializa el votante con su id y las claves públicas que necesita."""
        raise NotImplementedError

    def prepare_ballot(self, candidate: str) -> Ballot:
        """Construye una papeleta para el candidato dado con un nonce fresco."""
        raise NotImplementedError

    def blind_ballot(self, ballot: Ballot) -> BlindedBallot:
        """Aplica el cegado RSA sobre la papeleta serializada."""
        raise NotImplementedError

    def submit_to_admin(self, admin) -> int:
        """Envía la papeleta cegada al administrador y devuelve la firma cegada."""
        raise NotImplementedError

    def unblind_signature(self, blinded_sig: int) -> int:
        """Quita el factor de cegado para obtener la firma real sobre la papeleta."""
        raise NotImplementedError

    def emit_to_mixnet(self, first_node, signed_ballot: SignedBallot) -> None:
        """Emite la papeleta firmada (cifrada en capas) al primer nodo de la mixnet."""
        raise NotImplementedError
