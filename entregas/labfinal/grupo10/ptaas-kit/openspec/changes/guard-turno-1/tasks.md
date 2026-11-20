# Turno 1 — autorización (extensión de la tarea 1.2)

- [x] T1: verificar A1, A2, A3, A6 y A9 con adaptador falso. Para cada rechazo se exige `BLOCKED` en bitácora y cero llamadas al adaptador.
- [x] T2: verificar sensibilidad a una mutación del guard y ejecutar suite, evals golden y trazabilidad.

## Evidencia local — 19/11/2026

- Base: kit de `upstream/main` en `a1abb79`. Antes de corregir: cuatro casos nuevos pasaban y A9 fallaba (el guard aceptaba un nombre con espacio interno).
- Mutación manual solo en memoria: se reemplazó `Guard.is_allowed` por una función que devolvía `True` durante una corrida aislada de los cinco tests. Fallaron A2, A3 y A9. El proceso terminó y se ejecutó la suite en un proceso nuevo con el guard real.
- `python -m pytest -q`: 82 pasaron. `python evals/run_evals.py --mode golden`: 10/10. `python tools/progress.py`: 82 tests recolectados.
- Docker: DVWA, Juice Shop y runner levantados en `grupo10-ptaas`, sin publicar puertos. Los pools automáticos estaban agotados; se usó la subred local `10.253.219.0/28` con una configuración temporal y se verificó que la red era interna.
