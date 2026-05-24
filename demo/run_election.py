"""Demo end-to-end de una elección con 10 votantes y 2 candidatos."""
from __future__ import annotations

import os
import random
import sys
import time

# Permitir ejecutar el script directamente sin instalar como paquete
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.admin import Admin  # noqa: E402
from src.counter import Counter  # noqa: E402
from src.crypto_utils import generate_rsa_keypair  # noqa: E402
from src.mixnet import MixNode  # noqa: E402
from src.voter import Voter  # noqa: E402


NUM_VOTERS = 10
CANDIDATES = ["A", "B"]


def main() -> int:
    print("=" * 64)
    print("  DEMO: voto electrónico con firma ciega de Chaum + mixnet")
    print("=" * 64)

    print("\n[setup] Generando claves RSA-2048 para admin y 2 mixnodes...")
    t0 = time.perf_counter()
    admin_keys = generate_rsa_keypair(bits=2048)
    m1_keys = generate_rsa_keypair(bits=2048)
    m2_keys = generate_rsa_keypair(bits=2048)
    print(f"[setup] Claves listas en {time.perf_counter()-t0:.2f}s")

    admin = Admin(admin_keys["privkey_chaum"])
    m1 = MixNode("M1", m1_keys["priv"])
    m2 = MixNode("M2", m2_keys["priv"])
    counter = Counter(admin_keys["pubkey_chaum"], CANDIDATES)

    # ---------- Fase 1: registro ----------
    print("\n[fase 1] Registro de votantes")
    voters = []
    for i in range(NUM_VOTERS):
        vid = f"V{i:02d}"
        admin.register_voter(vid)
        v = Voter(vid, admin_keys["pubkey_chaum"], [m1_keys["pub"], m2_keys["pub"]])
        voters.append(v)
        print(f"   - {vid} registrado")

    # ---------- Fase 2-3: firma ciega + emisión ----------
    print("\n[fase 2-3] Cada votante: prepara ballot, ciega, firma con admin,")
    print("           deciega y emite por mixnet (cifrado por capas)")
    expected = {c: 0 for c in CANDIDATES}
    batch: list[bytes] = []
    t_blind_total = 0.0
    t_emit_total = 0.0
    for v in voters:
        cand = random.choice(CANDIDATES)
        expected[cand] += 1

        t = time.perf_counter()
        v.prepare_ballot(cand)
        v.blind_ballot()
        v.submit_to_admin(admin)
        t_blind_total += time.perf_counter() - t

        t = time.perf_counter()
        ct = v.emit_to_mixnet()
        t_emit_total += time.perf_counter() - t
        batch.append(ct)
        print(f"   - {v.voter_id} -> ballot cifrado en cebolla ({len(ct)} bytes)")

    # ---------- Fase 4: mezcla ----------
    print("\n[fase 4] Mezcla por cadena de mixnodes")
    t = time.perf_counter()
    batch = m1.peel_and_shuffle(batch)
    t_m1 = time.perf_counter() - t
    print(f"   - M1 pela capa y baraja: {len(batch)} mensajes en {t_m1*1000:.1f} ms")

    t = time.perf_counter()
    batch = m2.peel_and_shuffle(batch)
    t_m2 = time.perf_counter() - t
    print(f"   - M2 pela capa y baraja: {len(batch)} mensajes en {t_m2*1000:.1f} ms")

    # ---------- Fase 5: recuento ----------
    print("\n[fase 5] Recuento")
    t = time.perf_counter()
    result = counter.tally(batch)
    t_tally = time.perf_counter() - t

    print("\n" + "=" * 64)
    print("  RESULTADO")
    print("=" * 64)
    for cand in CANDIDATES:
        print(f"   {cand}: {result[cand]} votos")
    print(f"   Inválidos descartados: {counter.invalid_count}")

    print(f"\n   Esperado (auditoría interna): {expected}")
    print(f"   Obtenido del recuento:        {result}")
    ok = expected == result
    print(f"   {'✓ COINCIDE' if ok else '✗ NO COINCIDE'}")

    print("\n" + "=" * 64)
    print("  MÉTRICAS (tiempos medios)")
    print("=" * 64)
    print(f"   Firma ciega (blind+submit+unblind): {t_blind_total*1000/NUM_VOTERS:7.2f} ms/votante")
    print(f"   Cifrado cebolla (2 capas):          {t_emit_total*1000/NUM_VOTERS:7.2f} ms/votante")
    print(f"   Mixnode M1 (lote de {NUM_VOTERS}):           {t_m1*1000:7.2f} ms")
    print(f"   Mixnode M2 (lote de {NUM_VOTERS}):           {t_m2*1000:7.2f} ms")
    print(f"   Recuento + verify (lote de {NUM_VOTERS}):    {t_tally*1000:7.2f} ms")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
