# Evidencia — Lab Extra 5 (JWT inseguro)

Ataque al portal `labs/labextra5-jwt/objetivo/server.py` con nuestra propia
navaja `src/jwt_tool.py` (solo stdlib): decodificar, crackear el secreto HMAC
offline y forjar tokens. El portal se levantó en `localhost` (puerto 8099 en
nuestra corrida, 8080 por defecto).

| Archivo | Qué es |
|---|---|
| `comandos.txt` | Los comandos usados, en orden. |
| `salidas/01-retos-R1-R3.txt` | Decodificación (R1), crack del secreto + forja admin (R2) y forja de identidad `sub=maria` (R3), con las 3 flags. |
| `salidas/02-control-sanidad.txt` | §4: token real de diego en `/admin` → 403; token con 1 char cambiado en la firma → 401; `alg:none` → 401. |
| `salidas/03-medicion-crack.txt` | Medición del crack offline (candidatos probados + tiempo) — insumo de P2. |
| `ctf-status-extra5.txt` | `./ctf status extra5` → 3/3. Flags validadas contra `labs/labextra5-jwt/retos.manifest`. |

## Flags (validadas contra `labs/labextra5-jwt/retos.manifest`)

| Reto | Técnica | Flag |
|---|---|---|
| R1 | Decodificación base64url del payload (claim `nota_interna` que no debía viajar) | `FLAG{jwt_solo_base64}` |
| R2 | Crack offline del secreto HMAC (`mate123`) + forja de token `role=admin` | `FLAG{jwt_forjado_admin}` |
| R3 | Forja de identidad `sub=maria` (IDOR vía claim) | `FLAG{jwt_suplantacion_idor}` |

> **Secreto crackeado:** `mate123` (palabra #11 de `caso/diccionario.txt`).
> El crack corre 100% en local recalculando `HMAC-SHA256("header.payload", candidato)`
> y comparando con la firma del token: cero requests al servidor, sin rate limit
> ni logs ni lockout. El token **es** el oráculo.
