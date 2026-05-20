# Voto Electrónico — Firma Ciega + Mixnet

Proof-of-concept didáctico de un esquema de voto electrónico basado en la
**firma ciega de Chaum sobre RSA** combinada con una **mixnet de descifrado**.

El protocolo separa dos garantías:

- **Elegibilidad** (vía firma ciega del administrador): solo votantes
  registrados pueden emitir una papeleta válida, pero el administrador no
  ve el contenido del voto.
- **Anonimato** (vía mixnet): los votos firmados se enrutan a través de
  varios nodos que descifran capa a capa y barajan el lote, rompiendo la
  correlación entre votante y papeleta antes del recuento.

Este repositorio es un trabajo académico. **No usar en producción.** Faltan
controles esenciales (autenticación de canal, pruebas de mezcla verificables,
revocación, auditoría pública, resistencia a coerción, etc.).

## Estructura

- `src/` — módulos del protocolo (votante, administrador, mixnet, contador).
- `tests/` — pruebas (de momento, solo smoke tests de import).
- `demo/` — script end-to-end (se implementa en la fase D10).
- `docs/` — especificación, modelo de amenazas y diagramas.

## Puesta en marcha

Crear y activar un entorno virtual:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Instalar dependencias:

```powershell
pip install -r requirements.txt
```

## Ejecutar tests

```powershell
pytest
```

## Ejecutar la demo

```powershell
python demo/run_election.py
```

(La demo está pendiente de implementación.)
