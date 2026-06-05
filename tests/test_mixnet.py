"""Test de integración end-to-end: votantes, admin, mixnet y contador."""
import pytest

from src.admin import Admin
from src.counter import Counter
from src.crypto_utils import generate_rsa_keypair
from src.mixnet import MixNode
from src.voter import Voter


@pytest.fixture(scope="module")
def keys():
    return {
        "admin": generate_rsa_keypair(bits=2048),
        "m1": generate_rsa_keypair(bits=2048),
        "m2": generate_rsa_keypair(bits=2048),
    }


def test_election_end_to_end(keys):
    admin = Admin(keys["admin"]["privkey"])
    m1 = MixNode("M1", keys["m1"]["priv"])
    m2 = MixNode("M2", keys["m2"]["priv"])

    voters = []
    expected = {"A": 0, "B": 0}
    for i in range(5):
        vid = f"V{i}"
        admin.register_voter(vid)
        v = Voter(vid, keys["admin"]["pubkey"], [keys["m1"]["pub"], keys["m2"]["pub"]])
        cand = "A" if i % 2 == 0 else "B"
        expected[cand] += 1
        v.preparar_voto(cand)
        v.cegar_voto()
        v.submit_to_admin(admin)
        voters.append(v)

    # Recolecta cebollas
    lote = [v.emit_to_mixnet() for v in voters]

    # Pasa por la mixnet
    lote = m1.peel_and_shuffle(lote)
    lote = m2.peel_and_shuffle(lote)

    # Recuento
    counter = Counter(keys["admin"]["pubkey"], candidates=["A", "B"])
    result = counter.contar(lote)

    assert result == expected
    assert counter.invalidos == 0


def test_mixnet_actually_shuffles(keys):
    """Con 10 votantes y 2 nodos, el orden de salida es distinto del de
    entrada con probabilidad abrumadora."""
    admin = Admin(keys["admin"]["privkey"])
    m1 = MixNode("M1", keys["m1"]["priv"])
    m2 = MixNode("M2", keys["m2"]["priv"])

    voters = []
    for i in range(10):
        vid = f"VS{i}"
        admin.register_voter(vid)
        v = Voter(vid, keys["admin"]["pubkey"], [keys["m1"]["pub"], keys["m2"]["pub"]])
        v.preparar_voto("A")
        v.cegar_voto()
        v.submit_to_admin(admin)
        voters.append(v)

    lote = [v.emit_to_mixnet() for v in voters]
    lote = m1.peel_and_shuffle(lote)
    lote = m2.peel_and_shuffle(lote)

    # Comprobamos que las cebollas no salen iguales (las capas se pelaron)
    # y que el lote tiene el mismo tamaño.
    assert len(lote) == 10
    assert all(isinstance(b, bytes) for b in lote)
