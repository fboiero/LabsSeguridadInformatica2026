# Evidencia — Lab Extra 4 (cracking de contraseñas)

Crackeo del volcado `labs/labextra4-cracking/caso/sombra.txt` con nuestro propio
`src/cracker.py` (solo stdlib) y apertura del loot cifrado de cada usuario.

| Archivo | Qué es |
|---|---|
| `comandos.txt` | Los comandos usados, en orden. |
| `salidas/crackeo-sin-reglas.txt` | Diccionario puro: caen `operador` (md5) y `analista` (sha256); `admin` no; `root` (pbkdf2) se omite. |
| `salidas/crackeo-con-reglas.txt` | Con `--reglas`: cae también `admin` (`phantom`→`phantom2026`). |
| `salidas/descifrado-loot.txt` | Salida de `descifrar` para los 3 loot, con las 3 flags. |
| `salidas/benchmark-velocidad.txt` | Medición de intentos/segundo por algoritmo (P1). |
| `ctf-status-extra4.txt` | `./ctf status extra4` → 3/3. Flags validadas contra `labs/labextra4-cracking/retos.manifest`. |

## Flags (validadas contra `labs/labextra4-cracking/retos.manifest`)

| Reto | Usuario | Técnica | Flag | SHA-256 |
|---|---|---|---|---|
| R1 | operador (md5) | diccionario | `FLAG{crack_diccionario_md5}` | `e72bbad9…a1d4` |
| R2 | analista (sha256) | diccionario | `FLAG{crack_sha256_diccionario}` | `3c1d6420…e97c2` |
| R3 | admin (sha256) | regla `palabra+año` | `FLAG{crack_reglas_mangling}` | `891c8efc…5edb3` |

> **Nota de reproducción.** En esta máquina Windows el `python3` del PATH es el stub
> de Microsoft Store; se usó `python` y se exportó `PYTHONUTF8=1` para que la consola
> imprima los símbolos `✓`/`✗`. En el entorno Linux de la cátedra el código corre tal
> cual con `python3` y sin variables de entorno. `root` (PBKDF2-200k) **no se crackea
> por diseño** — ver P4 en el informe.
