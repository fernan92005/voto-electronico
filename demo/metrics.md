# Métricas de la demo

Ejecución de `demo/run_election.py` con 10 votantes y 2 candidatos
sobre el sandbox de la sesión (Python 3.10, CPU virtualizada).

| Operación | Tiempo medio |
|-----------|--------------|
| Generación de 3 pares RSA-2048 | 400 ms (one-shot) |
| Firma ciega (blind + submit + unblind) | **49,40 ms/votante** |
| Cifrado cebolla (2 capas AES-GCM + RSA-OAEP) | **0,55 ms/votante** |
| Mixnode M1 (pelar + barajar lote 10) | **15,37 ms** |
| Mixnode M2 (pelar + barajar lote 10) | **15,30 ms** |
| Recuento + verify (lote 10) | **3,68 ms** |

Tamaño del ballot cebolla por votante: ~1260 bytes (2 capas).

Resultado del recuento: A=5, B=5 (esperado A=5, B=5). Coincide.
