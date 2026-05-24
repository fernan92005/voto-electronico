"""Contador / escrutador final.

Recibe el lote final de la mixnet (payloads JSON en claro tras pelar todas
las capas), verifica la firma del administrador sobre cada ballot y cuenta
los votos válidos por candidato.
"""
from __future__ import annotations

import json
from typing import Dict, List

from src.crypto_utils import ballot_to_int, verify
from src.types import RSAKey


class Counter:
    """Contador electoral con verificación de firma."""

    def __init__(self, admin_pubkey: RSAKey, candidates: List[str]) -> None:
        self.admin_pubkey = admin_pubkey
        self.candidates = candidates
        self.tally_result: Dict[str, int] = {c: 0 for c in candidates}
        self.invalid_count = 0

    def tally(self, final_batch: List[bytes]) -> Dict[str, int]:
        """Recuenta los votos válidos del lote final."""
        for item in final_batch:
            try:
                payload = json.loads(item)
                candidate = payload["candidate"]
                nonce = bytes.fromhex(payload["nonce"])
                sig = int(payload["sig"])
            except (json.JSONDecodeError, KeyError, ValueError, TypeError):
                self.invalid_count += 1
                continue

            if candidate not in self.candidates:
                self.invalid_count += 1
                continue

            m = ballot_to_int(candidate, nonce, self.admin_pubkey.n)
            if verify(m, sig, self.admin_pubkey):
                self.tally_result[candidate] += 1
            else:
                self.invalid_count += 1

        return self.tally_result
