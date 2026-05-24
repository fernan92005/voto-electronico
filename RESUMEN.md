# Resumen del Proyecto: Voto Electrónico con Firma Ciega de Chaum + Mixnet

**Asignatura:** Ciberseguridad — 3º Ingeniería del Software, UMA (2025-2026)  
**Tipo:** Prueba de concepto educativa (no apta para producción)

---

## Protocolo implementado (5 fases)

| Fase | Clase/Módulo | Descripción |
|------|-------------|-------------|
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
│   ├── test_crypto_utils.py   # 8 tests sobre primitivas criptográficas
│   ├── test_admin.py          # 4 tests de elegibilidad y doble voto
│   ├── test_voter.py          # 3 tests del flujo del votante
│   ├── test_mixnet.py         # 2 tests de integración end-to-end
│   └── test_smoke.py          # Smoke test del scaffold
├── demo/
│   ├── run_election.py   # Demo completa con 10 votantes
│   └── metrics.md        # Métricas de rendimiento
├── docs/
│   ├── spec.md           # Especificación del protocolo
│   ├── diagrams.md       # Diagramas del sistema
│   └── threat_model.md   # Modelo de amenazas
├── README.md
├── requirements.txt      # cryptography>=42.0, pytest>=8.0
└── pytest.ini
```

---

## Criptografía (`src/crypto_utils.py`)

### Firma ciega de Chaum (RSA textbook)

| Función | Operación |
|---------|-----------|
| `blind(m, r, pubkey)` | `b = m · r^e mod n` |
| `sign_blinded(b, privkey)` | `s = b^d mod n` (Admin no ve `m`) |
| `unblind(s, r, pubkey)` | `σ = s · r⁻¹ mod n = m^d mod n` |
| `verify(m, sig, pubkey)` | `sig^e ≡ m (mod n)` |

> **Nota pedagógica:** Se usa RSA textbook (sin padding) para preservar la propiedad multiplicativa de Chaum. En producción se usaría RSA-FDH o RSA-PSS.

### Cifrado de capas (mixnet)

- **Cuerpo:** AES-GCM con clave aleatoria de sesión
- **Clave de sesión:** cifrada con RSA-OAEP de cada nodo

### Mapeo de votos

```
m = SHA-256(candidato ‖ nonce) mod n
```

Nonce de 16 bytes aleatorios garantiza que cada voto sea único incluso para el mismo candidato.

---

## Componentes principales

### `src/admin.py` — Autoridad Electoral

- Mantiene `eligible`: conjunto de votantes registrados
- Mantiene `served`: conjunto de votantes ya atendidos (anti doble-voto)
- `register_voter(voter_id)`: añade a la lista blanca
- `sign_blinded_ballot(voter_id, blinded)`: verifica elegibilidad y unicidad antes de firmar

### `src/voter.py` — Votante

- `prepare_ballot(candidate)`: genera nonce, calcula `m = H(candidato‖nonce)`
- `blind_ballot()`: genera `r` coprimo con `n`, calcula `b = m·r^e mod n`
- `submit_to_admin(admin)`: envía `b`, recibe `s`, desciega → `σ`
- `emit_to_mixnet()`: empaqueta JSON y cifra en capas (del último nodo al primero)

### `src/mixnet.py` — Nodo de Mezcla

- `peel_and_shuffle(batch)`: descifra la capa exterior de todos los mensajes y aplica Fisher-Yates con `secrets.randbelow()` para romper la correlación entrada-salida

### `src/counter.py` — Recuento

- `tally(final_batch)`: parsea JSON, reconstruye `m`, verifica `σ` con la clave pública del Admin, contabiliza votos válidos

---

## Propiedades de seguridad

| Propiedad | Estado | Mecanismo |
|-----------|--------|-----------|
| Elegibilidad | ✅ Implementada | Lista blanca en Admin |
| Unicidad (anti doble-voto) | ✅ Implementada | Set `served` en Admin |
| Privacidad del voto | ✅ Implementada | Firma ciega + mixnet |
| Anonimato (unlinkability) | ✅ Implementado | Shuffle en cada nodo mixnet |
| Verificabilidad universal | ❌ No implementada | Requeriría bulletin board |
| Receipt-freeness | ❌ No implementada | Votante conoce `r` (puede probar su voto) |
| Fairness (parciales) | ❌ No implementada | Requeriría esquema de compromiso |

---

## Tests (18 en total)

### `test_crypto_utils.py` (8 tests)
- Roundtrip completo: blind → sign → unblind → verify
- Aislamiento del mensaje: el firmante no aprende `m`
- Rechazo de factor de cegado inválido
- Ejemplo pedagógico con `n=77` (p=7, q=11)
- Garantía de coprimalidad de `random_coprime`
- Determinismo de `ballot_to_int`
- Roundtrip de cifrado por capas

### `test_admin.py` (4 tests)
- Firma a votante autorizado
- Rechazo de votante no registrado (`PermissionError`)
- Prevención de doble voto (`ValueError`)
- Múltiples votantes distintos

### `test_voter.py` (3 tests)
- Flujo completo del votante
- Emisión onion produce bytes válidos
- Cegado sintáctico: `blinded ≠ m`

### `test_mixnet.py` (2 tests)
- Elección end-to-end con 5 votantes y 2 candidatos
- El shuffle altera el orden de la entrada

---

## Métricas de rendimiento (10 votantes, 2 nodos mixnet, RSA-2048)

| Operación | Tiempo |
|-----------|--------|
| Generación de 3 pares de claves RSA-2048 | ~400 ms (una sola vez) |
| Firma ciega por votante | ~49 ms |
| Cifrado onion por votante (2 capas) | ~0.55 ms |
| Descifrado + shuffle por nodo (10 votos) | ~15 ms |
| Recuento + verificación (10 votos) | ~3.7 ms |
| Tamaño del ballot onion por votante | ~1260 bytes |

---

## Dependencias

```
cryptography>=42.0   # RSA, AES-GCM, OAEP
pytest>=8.0          # Framework de tests
```

Python 3.10+

---

## Repositorio

[github.com/fernan92005/voto-electronico](https://github.com/fernan92005/voto-electronico)
