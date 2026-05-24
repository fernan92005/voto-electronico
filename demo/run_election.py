"""Demo end-to-end de una elección con votantes y candidatos configurables."""
from __future__ import annotations

import argparse
import logging
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Demo de voto electrónico con firma ciega de Chaum + mixnet"
    )
    parser.add_argument(
        "--voters", type=int, default=10, metavar="N",
        help="número de votantes (default: 10)",
    )
    parser.add_argument(
        "--candidates", type=str, default="A,B", metavar="A,B,...",
        help="candidatos separados por coma (default: A,B)",
    )
    parser.add_argument(
        "--key-bits", type=int, default=2048, metavar="N",
        help="tamaño de las claves RSA en bits (default: 2048)",
    )
    parser.add_argument(
        "--seed", type=int, default=None, metavar="N",
        help="semilla para reproducibilidad de la asignación de votos (default: None)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="activa logging INFO en todos los módulos src/",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(name)s %(levelname)s %(message)s",
    )

    if args.seed is not None:
        random.seed(args.seed)

    num_voters = args.voters
    candidates = [c.strip() for c in args.candidates.split(",") if c.strip()]

    print("=" * 64)
    print("  DEMO: voto electrónico con firma ciega de Chaum + mixnet")
    print("=" * 64)
    print(f"  Votantes: {num_voters}  |  Candidatos: {candidates}  |  Bits RSA: {args.key_bits}")

    print(f"\n[setup] Generando claves RSA-{args.key_bits} para admin y 2 mixnodes...")
    t0 = time.perf_counter()
    admin_keys = generate_rsa_keypair(bits=args.key_bits)
    m1_keys = generate_rsa_keypair(bits=args.key_bits)
    m2_keys = generate_rsa_keypair(bits=args.key_bits)
    print(f"[setup] Claves listas en {time.perf_counter()-t0:.2f}s")

    admin = Admin(admin_keys["privkey_chaum"])
    m1 = MixNode("M1", m1_keys["priv"])
    m2 = MixNode("M2", m2_keys["priv"])
    counter = Counter(admin_keys["pubkey_chaum"], candidates)

    # ---------- Fase 1: registro ----------
    print("\n[fase 1] Registro de votantes")
    voters = []
    for i in range(num_voters):
        vid = f"V{i:02d}"
        admin.register_voter(vid)
        v = Voter(vid, admin_keys["pubkey_chaum"], [m1_keys["pub"], m2_keys["pub"]])
        voters.append(v)
        print(f"   - {vid} registrado")

    # ---------- Fase 2-3: firma ciega + emisión ----------
    print("\n[fase 2-3] Cada votante: prepara ballot, ciega, firma con admin,")
    print("           deciega y emite por mixnet (cifrado por capas)")
    expected = {c: 0 for c in candidates}
    batch: list[bytes] = []
    t_blind_total = 0.0
    t_emit_total = 0.0
    for v in voters:
        cand = random.choice(candidates)
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
    for cand in candidates:
        print(f"   {cand}: {result[cand]} votos")
    print(f"   Inválidos descartados: {counter.invalid_count}")
    print(f"   Duplicados descartados: {counter.duplicate_count}")

    print(f"\n   Esperado (auditoría interna): {expected}")
    print(f"   Obtenido del recuento:        {result}")
    ok = expected == result
    print(f"   {'[OK] COINCIDE' if ok else '[FAIL] NO COINCIDE'}")

    print("\n" + "=" * 64)
    print("  MÉTRICAS (tiempos medios)")
    print("=" * 64)
    print(f"   Firma ciega (blind+submit+unblind): {t_blind_total*1000/num_voters:7.2f} ms/votante")
    print(f"   Cifrado cebolla (2 capas):          {t_emit_total*1000/num_voters:7.2f} ms/votante")
    print(f"   Mixnode M1 (lote de {num_voters}):           {t_m1*1000:7.2f} ms")
    print(f"   Mixnode M2 (lote de {num_voters}):           {t_m2*1000:7.2f} ms")
    print(f"   Recuento + verify (lote de {num_voters}):    {t_tally*1000:7.2f} ms")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
