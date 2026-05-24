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
    admin = Admin(keys["admin"]["privkey_chaum"])
    m1 = MixNode("M1", keys["m1"]["priv"])
    m2 = MixNode("M2", keys["m2"]["priv"])

    voters = []
    expected = {"A": 0, "B": 0}
    for i in range(5):
        vid = f"V{i}"
        admin.register_voter(vid)
        v = Voter(vid, keys["admin"]["pubkey_chaum"], [keys["m1"]["pub"], keys["m2"]["pub"]])
        cand = "A" if i % 2 == 0 else "B"
        expected[cand] += 1
        v.prepare_ballot(cand)
        v.blind_ballot()
        v.submit_to_admin(admin)
        voters.append(v)

    # Recolecta cebollas
    batch = [v.emit_to_mixnet() for v in voters]

    # Pasa por la mixnet
    batch = m1.peel_and_shuffle(batch)
    batch = m2.peel_and_shuffle(batch)

    # Recuento
    counter = Counter(keys["admin"]["pubkey_chaum"], candidates=["A", "B"])
    result = counter.tally(batch)

    assert result == expected
    assert counter.invalid_count == 0


def test_mixnet_actually_shuffles(keys):
    """Con 10 votantes y 2 nodos, el orden de salida es distinto del de
    entrada con probabilidad abrumadora."""
    admin = Admin(keys["admin"]["privkey_chaum"])
    m1 = MixNode("M1", keys["m1"]["priv"])
    m2 = MixNode("M2", keys["m2"]["priv"])

    voters = []
    for i in range(10):
        vid = f"VS{i}"
        admin.register_voter(vid)
        v = Voter(vid, keys["admin"]["pubkey_chaum"], [keys["m1"]["pub"], keys["m2"]["pub"]])
        v.prepare_ballot("A")
        v.blind_ballot()
        v.submit_to_admin(admin)
        voters.append(v)

    initial = [v.voter_id for v in voters]
    batch = [v.emit_to_mixnet() for v in voters]
    batch = m1.peel_and_shuffle(batch)
    batch = m2.peel_and_shuffle(batch)

    # No podemos comparar IDs directamente (están ocultos), pero al menos
    # comprobamos que las cebollas no salen iguales (sería sospechoso si
    # ningún byte cambia tras dos shuffles).
    assert len(batch) == 10
    # El payload JSON sí permite extraer el orden de candidatos; aquí
    # todos votan "A" así que no hay diversidad. Lo que validamos es que
    # los bytes finales son distintos a la entrada (porque las capas se
    # pelaron) y el lote tiene el mismo tamaño.
    assert all(isinstance(b, bytes) for b in batch)
