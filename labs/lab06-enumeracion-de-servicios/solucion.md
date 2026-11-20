# Solución — Laboratorio 06 (SOLO DOCENTE)

> No compartir con alumnos.

## Levantar
```bash
make setup && make lab N=06 && make shell
```

## Flags

| Reto | Flag | Comando |
|---|---|---|
| R1 | `FLAG{dir_enumeration_backup}` | `dirb http://phantomcorp/` encuentra `/backup`; `curl -s http://phantomcorp/backup/` |
| R2 | `FLAG{git_repo_exposed}` | `curl -s http://phantomcorp/.git/config` |
| R3 | `FLAG{http_methods_put_enabled}` | `curl -X OPTIONS -i http://phantomcorp/` → header `X-Dangerous-Methods` (y `Allow` con PUT) |
| R4 | `FLAG{user_enumeration_api}` | `curl -s http://phantomcorp/api/users | jq` |
| R5 | `FLAG{tech_fingerprint_phantomcms}` | `whatweb http://phantomcorp` → PhantomCMS 3.7; `curl -s http://phantomcorp/phantomcms/VERSION` |

## Clave del inventario

| Hallazgo | Riesgo | Habilita para Lab 07 |
|---|---|---|
| `/backup/` accesible | Alto — filtra respaldos, posibles credenciales | Acceso a config/DB |
| `/.git/config` | Alto — reconstrucción de código fuente e historia | Análisis de código, secretos |
| `PUT` habilitado | Crítico — subida de webshell | RCE por upload |
| `/api/users` | Medio — lista usuarios válidos | Password spraying / fuerza bruta dirigida |
| PhantomCMS 3.7 fingerprint | Base — dirige la enumeración | Buscar CVEs del CMS |

## Errores típicos
- Correr solo dirb y perderse `.git`, OPTIONS y la API (no son de wordlist).
- No conectar el hallazgo con la fase de explotación (P4 lo fuerza).
