"""Contador / escrutador final.

Recibe el lote final de la mixnet (payloads JSON en claro tras pelar todas
las capas), verifica la firma del administrador sobre cada ballot y cuenta
los votos válidos por candidato.

El método ``tally()`` es resiliente a payloads mal formados (JSON inválido,
campos faltantes, nonce no-hex, tipo inesperado): los descarta sin levantar
excepción y los contabiliza en ``invalid_count``. Las firmas duplicadas se
contabilizan en ``duplicate_count`` y se descartan.
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List

from src.crypto_utils import ballot_to_int, verify
from src.types import RSAKey

logger = logging.getLogger(__name__)


class Counter:
    """Contador electoral con verificación de firma y detección de replay."""

    def __init__(self, admin_pubkey: RSAKey, candidates: List[str]) -> None:
        self.admin_pubkey = admin_pubkey
        self.candidates = candidates
        self.tally_result: Dict[str, int] = {c: 0 for c in candidates}
        self.invalid_count = 0
        self.duplicate_count = 0
        self._seen_signatures: set[int] = set()

    def tally(self, final_batch: List[bytes]) -> Dict[str, int]:
        """Recuenta los votos válidos del lote final.

        Resiliente a payloads mal formados (JSON inválido, campos faltantes,
        nonce no-hex, tipo inesperado): los descarta sin levantar excepción y
        los contabiliza en ``invalid_count``. Las firmas duplicadas se
        contabilizan en ``duplicate_count`` y se descartan, bloqueando el
        ataque donde un mixnode malicioso duplica un ciphertext para inflar
        el voto de un candidato.
        """
        for i, item in enumerate(final_batch):
            # --- Parseo de JSON ---
            try:
                payload = json.loads(item)
            except (json.JSONDecodeError, ValueError):
                logger.info("ballot %d inválido por JSON mal formado", i)
                self.invalid_count += 1
                continue

            # --- Validación de campos obligatorios ---
            if not {"candidate", "nonce", "sig"}.issubset(payload.keys()):
                logger.info("ballot %d inválido por campos faltantes", i)
                self.invalid_count += 1
                continue

            try:
                candidate = str(payload["candidate"])
                nonce = bytes.fromhex(payload["nonce"])
                sig = int(payload["sig"])
            except (ValueError, TypeError):
                logger.info("ballot %d inválido por tipo de campo incorrecto", i)
                self.invalid_count += 1
                continue

            # --- Anti-replay: detección de firma duplicada ---
            if sig in self._seen_signatures:
                logger.info("ballot %d descartado por firma duplicada", i)
                self.duplicate_count += 1
                continue
            self._seen_signatures.add(sig)

            # --- Validación de candidato ---
            if candidate not in self.candidates:
                logger.info("ballot %d inválido por candidato desconocido: %s", i, candidate)
                self.invalid_count += 1
                continue

            # --- Verificación de firma ---
            m = ballot_to_int(candidate, nonce, self.admin_pubkey.n)
            if verify(m, sig, self.admin_pubkey):
                logger.info("ballot %d válido -> %s", i, candidate)
                self.tally_result[candidate] += 1
            else:
                logger.info("ballot %d inválido por firma incorrecta", i)
                self.invalid_count += 1

        return self.tally_result
