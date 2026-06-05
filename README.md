# Voto electrónico con firma ciega de Chaum y mixnet

**Asignatura:** Ciberseguridad — 3º Ingeniería del Software, UMA (2025-2026)  
**Tipo:** Ejercicio Voluntario

> PoC educativo. Usa **RSA textbook** sin padding en la firma ciega (necesario para que la propiedad multiplicativa funcione). No usar en producción.

---

## Protocolo (5 fases)

| Fase | Módulo | Descripción |
|------|--------|-------------|
| 1 - Registro | `src/admin.py` | El Admin registra los votantes elegibles en una lista blanca |
| 2 - Firma ciega | `src/voter.py` + `src/admin.py` | El votante ciega `m = H(candidato‖nonce)`, el Admin firma sin ver el voto, el votante desciega obteniendo `σ` válida |
| 3 - Emisión onion | `src/voter.py` | Construye JSON `{candidato, nonce, sig}` y cifra en capas (AES-GCM + RSA-OAEP) |
| 4 - Mezcla | `src/mixnet.py` | Cada nodo descifra su capa y realiza shuffle Fisher-Yates con `secrets` |
| 5 - Recuento | `src/counter.py` | Verifica la firma del Admin, suma votos válidos y descarta los inválidos |

---

## Estructura del proyecto

```
voto-electronico/
├── src/
│   ├── types.py          # RSAKey: dataclass inmutable con (n, exp)
│   ├── crypto_utils.py   # Operaciones criptográficas centrales
│   ├── admin.py          # Autoridad electoral
│   ├── voter.py          # Flujo completo del votante
│   ├── mixnet.py         # Nodos de mezcla
│   └── counter.py        # Recuento y verificación
├── tests/
│   ├── test_crypto_utils.py   # 9 tests sobre primitivas criptográficas
│   ├── test_admin.py          # 5 tests de elegibilidad y doble voto
│   ├── test_voter.py          # 6 tests del flujo del votante
│   ├── test_mixnet.py         # 2 tests de integración end-to-end
│   ├── test_counter.py        # 4 tests del contador
│   └── test_smoke.py          # Smoke tests del scaffold
├── demo/
│   ├── run_election.py   # Demo completa con argumentos configurables
│   └── metrics.md        # Métricas de rendimiento
├── README.md
├── requirements.txt
└── pytest.ini
```

---

## Criptografía

### Firma ciega de Chaum (RSA textbook)

| Función | Operación |
|---------|-----------|
| `blind(m, r, pubkey)` | `b = m · r^e mod n` |
| `sign_blinded(b, privkey)` | `s = b^d mod n` (Admin no ve `m`) |
| `unblind(s, r, pubkey)` | `σ = s · r⁻¹ mod n = m^d mod n` |
| `verify(m, sig, pubkey)` | `sig^e ≡ m (mod n)` |

> Se usa RSA textbook para preservar la propiedad multiplicativa de Chaum. En producción se usaría RSA-FDH o RSA-PSS.

### Cifrado de capas (mixnet)

- **Cuerpo:** AES-GCM con clave aleatoria de sesión
- **Clave de sesión:** cifrada con RSA-OAEP de cada nodo

### Mapeo de votos

```
m = SHA-256(candidato ‖ nonce) mod n
```

El nonce de 16 bytes garantiza que dos votos al mismo candidato producen valores distintos.

---

## Propiedades de seguridad

| Propiedad | Estado | Mecanismo |
|-----------|--------|-----------|
| Elegibilidad | Sí | Lista blanca en Admin |
| Unicidad (anti doble-voto) | Sí | Set `served` en Admin |
| Privacidad del voto | Sí | Firma ciega + mixnet |
| Anonimato (unlinkability) | Sí | Shuffle Fisher-Yates en cada nodo |
| Anti-replay en counter | Sí | De-duplicación por firma (`_seen_signatures`) |
| State machine voter | Sí | Excepciones reales, no `assert` |
| Verificabilidad universal | No | Requeriría bulletin board |
| Receipt-freeness | No | Votante conoce `r` (puede probar su voto) |
| Fairness | No | Requeriría esquema de compromiso |

---

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

---

## Uso

### 1. Tests automáticos

```bash
cd C:\INGENIERO\Ciberseguridad\practicas\voto-electronico
python -m pytest -v
```

Verás los 29 tests con su resultado. Si quieres solo un módulo concreto:

```bash
python -m pytest tests/test_counter.py -v
python -m pytest tests/test_voter.py -v
```

### 2. La demo (elección completa end-to-end)

```bash
# Básico: 10 votantes, candidatos A y B
python demo/run_election.py

# Con semilla fija (resultado reproducible)
python demo/run_election.py --voters 10 --seed 42

# Más votantes y más candidatos
python demo/run_election.py --voters 20 --candidates A,B,C --seed 7

# Con logs internos visibles (ves cada firma, cada voto)
python demo/run_election.py --voters 5 --verbose

# Claves más pequeñas = más rápido (solo para pruebas, no seguro)
python demo/run_election.py --voters 5 --key-bits 1024
```

---

## Métricas de rendimiento (10 votantes, 2 nodos mixnet, RSA-2048)

| Operación | Tiempo |
|-----------|--------|
| Generación de 3 pares de claves RSA-2048 | ~400 ms (una sola vez) |
| Firma ciega por votante | ~55 ms |
| Cifrado onion por votante (2 capas) | ~0.6 ms |
| Descifrado + shuffle por nodo (10 votos) | ~15 ms |
| Recuento + verificación (10 votos) | ~4 ms |
| Tamaño del voto en cebolla por votante | ~1260 bytes |
