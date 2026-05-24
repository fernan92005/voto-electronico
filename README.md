# Voto electrónico con firma ciega de Chaum y mixnet

Implementación didáctica de un esquema de voto electrónico que combina:

- **Firma ciega de Chaum** sobre RSA — el administrador firma el voto sin verlo.
- **Mixnet de descifrado de 2 nodos** — los votos firmados se mezclan antes de llegar al contador.

> ⚠️ PoC educativo. Usa **RSA *textbook*** sin padding PKCS#1/OAEP en la firma ciega (necesario para que la propiedad multiplicativa funcione). No usar en producción.

## Estructura

```
src/
  crypto_utils.py    # blind, sign_blinded, unblind, verify + utilidades cifrado capas
  types.py           # RSAKey
  voter.py           # clase Voter
  admin.py           # clase Admin
  mixnet.py          # clase MixNode
  counter.py         # clase Counter
tests/               # pytest, ~15 tests cubren las 4 fases
demo/run_election.py # demo end-to-end con 10 votantes
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate     # Linux/Mac
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

## Uso

Ejecutar la batería de tests:

```bash
pytest -v
```

Ejecutar la demo de una elección completa:

```bash
python demo/run_election.py
```

## Propiedades de seguridad

| Propiedad | Cubierto |
|-----------|----------|
| Eligibility | Sí (firma de A) |
| Uniqueness | Sí (set de IDs servidos) |
| Privacy | Sí (firma ciega + mixnet) |
| Fairness | No (sin commitment) |
| Universal verifiability | No (sin bulletin board) |
| Receipt-freeness | No (votante conoce `r`) |

## Trabajo voluntario

Asignatura: Ciberseguridad (3º Ing. Software, UMA). Curso 2025-2026.
