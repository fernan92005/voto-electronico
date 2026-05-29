"""
Contador final de los votos

Recibe el lote final de la mixnet (mensajes JSON en claro tras pelar todas
las capas), verifica la firma del administrador sobre cada voto y suma
los votos válidos por candidato.

El método contar() es resistente a mensajes mal formados (JSON inválido,
campos que faltan, nonce no-hex, tipo inesperado): los descarta sin lanzar
excepción y los contabiliza en "invalidos". Los votos duplicados se
contabilizan en "duplicados" y se descartan
"""
from __future__ import annotations

import json
import logging
from typing import Dict, List

from src.crypto_utils import voto_a_entero, verify
from src.types import RSAKey

logger = logging.getLogger(__name__)


class Counter:
    """Contador electoral con verificación de firma y detección de replay"""

    def __init__(self, admin_pubkey: RSAKey, candidates: List[str]) -> None:
        self.admin_pubkey = admin_pubkey
        self.candidates = candidates
        self.resultado: Dict[str, int] = {c: 0 for c in candidates}
        self.invalidos = 0
        self.duplicados = 0
        self._firmas_vistas: set[int] = set()

    def contar(self, lote: List[bytes]) -> Dict[str, int]:
        """
        Cuenta los votos válidos del lote final.

        Este método es resistente a mensajes mal formados (JSON inválido,
        campos que faltan, nonce no-hex, tipo inesperado): los descarta sin lanzar
        excepción y los contabiliza en "invalidos". Los votos duplicados se
        contabilizan en "duplicados" y se descartan
                """

        for i, item in enumerate(lote):
            # Parseo de JSON
            try:
                payload = json.loads(item)
            except (json.JSONDecodeError, ValueError):
                logger.info("voto %d descartado: JSON mal formado", i)
                self.invalidos += 1
                continue

            #  Comprobación de campos obligatorios 
            if not {"candidate", "nonce", "sig"}.issubset(payload.keys()):
                logger.info("voto %d descartado: faltan campos", i)
                self.invalidos += 1
                continue

            try:
                candidato = str(payload["candidate"])
                nonce = bytes.fromhex(payload["nonce"])
                sig = int(payload["sig"])
            except (ValueError, TypeError):
                logger.info("voto %d descartado: tipo de campo incorrecto", i)
                self.invalidos += 1
                continue

            # Detección de voto duplicado
            if sig in self._firmas_vistas:
                logger.info("voto %d descartado: firma duplicada", i)
                self.duplicados += 1
                continue
            self._firmas_vistas.add(sig)

            # Candidato válido
            if candidato not in self.candidates:
                logger.info("voto %d descartado: candidato desconocido '%s'", i, candidato)
                self.invalidos += 1
                continue

            # Verificación de firma
            m = voto_a_entero(candidato, nonce, self.admin_pubkey.n)
            if verify(m, sig, self.admin_pubkey):
                logger.info("voto %d válido -> %s", i, candidato)
                self.resultado[candidato] += 1
            else:
                logger.info("voto %d descartado: firma incorrecta", i)
                self.invalidos += 1

        return self.resultado
