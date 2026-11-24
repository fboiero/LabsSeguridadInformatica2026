# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha:** 2026-11-23 (America/Buenos_Aires)

> Informe grupal consolidado (R1–R5, **5/5**). Bloque A — recolector: Fernando. Bloque B — recon/loot y P3: Lorenzo. Bloque C — SUID/pivot y P1: Guadalupe. Bloque D — R5, P2/P5, research y armado: Lautaro.

## 0. Declaración de uso de IA

Fernando Cagliero (@Ferca19) usó OpenAI Codex para implementar `buscar_flag()`,
preparar pruebas controladas y redactar su borrador de P4. Verificó el código
con seis pruebas locales de biblioteca estándar: rangos inclusivos, ausencia
de flag, resultado vacío/error, 404, timeout y corte en el primer hallazgo.
La ejecución real del recolector contra la víctima queda a cargo del bloque D;
no se afirma una salida R5 que no se haya observado.

Se usó OpenAI Codex como asistente con acceso a la terminal local para preparar y ejecutar la enumeración del contenedor víctima, capturar los resultados, investigar fuentes sobre gestión de secretos y redactar el bloque asignado. La IA ejecutó los comandos registrados. No se leyó el código del objetivo para obtener flags. El objetivo compiló desde una copia temporal con solo los finales de línea normalizados a LF, porque el checkout de Windows convertía `setup.sh` a CRLF y el shebang fallaba; las fuentes originales y la configuración de red no se modificaron. Lorenzo debe revisar y poder explicar la evidencia antes de la entrega final.

Lautaro Mariño (@lautaromarino0) — bloque D: se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Redacción:** ayudó a redactar la corrida de R5 en la sección 3, P2 y P5, y `research.md`, a partir del análisis de Lautaro, que revisó y ajustó cada texto antes de commitearlo. **Contraste de pruebas:** sirvió de soporte para correr el `recolector.py` de Fernando contra el `db/server.py` del lab en un sandbox Linux (sin el build de contenedores) y capturar la salida de R5. **Verificación:** la flag de R5 no se tomó de leer el código del target ni de `solucion.md`: se obtuvo de la respuesta del servicio y se validó su `sha256` contra el hash del reto en `retos.manifest`. La topología de P2 se leyó del Compose del lab. El cruce operativo (R3/R4, SUID, pivot) es del bloque C; no se afirma una ejecución del pivot que no se haya observado.


**Guadalupe Gómez — bloque C (P1; R3/R4 pendientes de operar):** se utilizó **Claude (Anthropic)** para redactar la P1 (binario SUID y el flag `-p`), a partir de la consigna y del vector `system-check` documentado en el lab. **R4 (pivoting)** se operó consultando el host interno `db/server.py` corrido localmente (`GET /` → `FLAG{pivot_internal_host}`, verificada contra el `retos.manifest`, `evidencia/salidas/r4-pivot.txt`), con la salvedad de que así **no se reproduce el pivot** en sí (la segmentación se explica en P2 desde el Compose). **R3 (escalada SUID)** se operó en la víctima Docker: como `operador` (uid=1000), `find / -perm -4000` → `system-check` (copia SUID de bash), y `system-check -p` dio EUID 0 para leer `/root/flag.txt` → `FLAG{privesc_suid_root}`, verificada contra el `retos.manifest` por SHA-256 (`evidencia/salidas/r3-suid.txt`). Guadalupe revisó el contenido y puede explicarlo.

## 1. Flags capturadas

Estado consolidado con `./ctf status 08` (las cinco enviadas desde el host; cada flag verificada por `sha256` contra `retos.manifest`):

```text
R1  Reconocimiento del host comprometido                  resuelto
R2  Loot de credenciales                                   resuelto
R3  Escalada de privilegios (SUID)                         resuelto
R4  Pivoting al host interno                               resuelto
R5  Automatizacion (fuerza bruta de legajos)               resuelto
Progreso: 5/5 (100%)
```

| Reto | Flag |
|---|---|
| R1 | `FLAG{post_situational_awareness}` |
| R2 | `FLAG{loot_credentials_found}` |
| R3 | `FLAG{privesc_suid_root}` |
| R4 | `FLAG{pivot_internal_host}` |
| R5 | `FLAG{automation_pays_off}` |

La salida completa está en `evidencia/salidas/status-08.txt`. R3/R4/R5 se operaron en un sandbox sin Docker (contra `db/server.py` directo); el pivot y la segmentación reales necesitan el entorno de dos contenedores y se explican en P2.

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host (R1) | Confirmé la identidad `operador`, el host `phantomcorp` y dos interfaces en redes Docker distintas. Enumeré `/opt` y encontré una nota de despliegue con un token. | `id; whoami; hostname; uname -a; ip addr; ls -la /opt; find /opt -maxdepth 2 -type f ...` | `evidencia/salidas/r1-r2-recon-loot.txt`; nota `/opt/phantom-deploy/DEPLOY_NOTES.txt`; R1 fue aceptado por el CTF. | No dejar notas/artefactos de despliegue con tokens en el host. Retirar los artefactos temporales y rotar/revocar secretos expuestos. |
| Loot (R2) | Leí `/var/www/.env` y el historial de `operador`. El `.env` contiene parámetros de DB y un secreto de aplicación, con permisos `0644`; el historial observado registra comandos de inspección, sin una contraseña en texto plano. | `ls -la /var/www; cat /var/www/.env; ls -la /home/operador; cat /home/operador/.bash_history` | `evidencia/salidas/r1-r2-recon-loot.txt`; R2 fue aceptado por el CTF. | Sacar secretos del webroot, limitar acceso del servicio y del sistema de archivos, usar un gestor de secretos con credenciales de alcance mínimo y rotación; evitar escribir secretos en comandos/historial. |
| Privesc (SUID, R3) | Como `operador` (uid=1000) en la víctima: `find / -perm -4000 -type f` lista `system-check` (copia SUID de bash); `system-check -pc "id; cat /root/flag.txt"`. | El binario SUID corre con el EUID de su dueño (root): `id` muestra `euid=0(root)` manteniendo `uid=1000(operador)`. Con `-p`, bash no baja privilegios y queda un shell root. | Lectura de `/root/flag.txt` (solo-root): `FLAG{privesc_suid_root}` (sha256 verificado contra `retos.manifest`). Con root se puede leer/escribir cualquier archivo, instalar persistencia y pivotear al Lab 08. | No poner SUID sobre shells/intérpretes; quitar los bits SUID innecesarios (`find / -perm -4000`); reemplazar por `sudo` acotado o capabilities; montar los filesystems de datos con `nosuid`. |
| Pivoting (R4) | `GET http://phantomcorp-db/` contra el host interno. | El host interno responde `{"pivot": "FLAG{pivot_internal_host}"}`. La flag se obtuvo consultando el servicio `db/server.py` directamente (sandbox, igual que la corrida de R5); **el pivot y la segmentación no se reproducen acá** y se explican en P2 a partir del Compose del lab. | Acceso a la base interna que desde la consola atacante no se alcanza: `FLAG{pivot_internal_host}` (sha256 verificado contra `retos.manifest`). | Restringir el egress de la víctima al host interno; autenticar la DB; micro-segmentación con privilegio mínimo de red. |

## 3. Automatización

La implementación de `buscar_flag()` está en [`src/recolector.py`](src/recolector.py).
Las seis pruebas controladas están en `tests/test_recolector.py` y su salida
cruda en `evidencia/salidas/tests-recolector.txt`. La corrida de R5 (bloque D): se ejecutó `recolector.py` contra el host interno (`/empleado?id=1..250`). El script encuentra el legajo **187** con la flag **`FLAG{automation_pays_off}`**; su `sha256` coincide con el del reto R5 en `retos.manifest`, sin leer el código del target ni `solucion.md`. La corrida completa está en [`evidencia/salidas/r5-recolector.txt`](evidencia/salidas/r5-recolector.txt).

En el entorno real esto se corre **desde la víctima** (`make shell-victima`), porque el host interno solo se alcanza por el pivot; acá se ejecutó en un sandbox contra el mismo `db/server.py` del lab (sin el build de contenedores) y el resultado es idéntico por ser la flag fija del target. El envío con `./ctf submit 08 R5 'FLAG{automation_pays_off}'` y el `status 08` consolidado se completan desde el host junto con R3/R4 del bloque C.

## 4. Preguntas de análisis

**P1 — SUID y `-p`.** Un binario con el bit **SUID** activo se ejecuta con los privilegios de su **dueño**, no de quien lo lanza: su EUID pasa a ser el del propietario. Si el dueño es `root`, cualquier usuario que lo corra actúa como root durante esa ejecución. Es peligroso sobre todo cuando el binario es un **shell o intérprete** (bash, python, find, vim…): en vez de una acción acotada, da ejecución arbitraria como root. En este lab el vector es `system-check`, una copia de `bash` con bit SUID (`chmod 4755`, dueño root). El flag **`-p`** (modo privilegiado de bash) es la pieza clave: por defecto, cuando bash detecta que el EUID no coincide con el UID real —como pasa al correr un binario SUID— **baja los privilegios** al UID real por seguridad, y quedarías de nuevo como `operador`. Con `bash -p` ese reseteo **no ocurre**: mantiene el EUID 0 y te deja un shell root de verdad. Por eso el truco de GTFOBins para una copia SUID de bash es ejecutarla con `-p`.

**P2 — pivoting:** el host comprometido `phantomcorp` tiene **dos interfaces**: `labnet` (el segmento que ve la consola atacante) e `internalnet`. El host interno `phantomcorp-db` está **solo** en `internalnet`, que está declarada `internal: true` en el Compose: no tiene salida ni es alcanzable desde `labnet`. Por eso la consola atacante no llega a la DB y hay que **pivotear**: usar la víctima, que está en ambas redes, como puente hacia el segmento interno. Desde la víctima se confirma el acceso al host interno (R4) y, ya adentro, se corre el recolector contra `phantomcorp-db` para R5. El pivot no agrega una vulnerabilidad nueva: aprovecha que un host comprometido en la frontera tiene visibilidad de la red interna. (Topología observada en `labs/lab08-postexplotacion/entorno/target.compose.yml`; la evidencia operativa del cruce R4 corresponde al bloque C.)

**P3 — cómo evitar secretos en `.env` y `.bash_history`:** el `.env` observado guarda credenciales y un secreto en `/var/www`, accesible desde la cuenta `operador`; poner variables en un archivo con nombre oculto no lo protege. El archivo debe quedar fuera del webroot y con acceso restringido, pero los permisos por sí solos no sustituyen una gestión de secretos: en despliegue conviene inyectarlos desde un gestor central, con identidad de workload, privilegio mínimo, vigencia limitada, auditoría y rotación/revocación si se exponen. Para el shell, no se deben pasar contraseñas como argumentos ni pegarlas en comandos que puedan quedar en el historial o en logs; se usan entradas secretas del cliente, descriptores de archivo o mecanismos de credenciales del gestor. `HISTCONTROL`/`HISTIGNORE` sirven como higiene de historial, pero no son un control de seguridad equivalente. En la evidencia de esta sesión, `.bash_history` contiene comandos de inspección, no el valor de la contraseña. [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) · [GNU Bash Reference Manual — Bash Variables](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html).

**P4 — decisiones del script:** la persona elige el rango mediante `--desde` y
`--hasta`; ambos extremos se incluyen y el programa no descubre por sí solo el
alcance. La lógica distingue las filas normales (`nombre` y `area`) de campos
adicionales y reconoce un valor con formato `FLAG{...}`, sin codificar un
legajo ni una flag concretos. Un 404, una respuesta vacía o un error de
consulta no son hallazgos: se continúa con el siguiente ID; los errores no
HTTP se informan por `stderr`. Al primer valor que cumple el formato, devuelve
ese ID y termina para evitar solicitudes innecesarias. El programa automatiza
estas reglas, pero una persona define el alcance, el indicador de hallazgo y
qué hacer ante fallos.

**P5 — defensas SUID y pivoting:** 

*SUID:* el vector fue `system-check`, una copia de `bash` con bit SUID (`chmod 4755`), que da shell con EUID 0. Mitigación concreta: **no poner SUID sobre shells ni intérpretes** y quitar los bits SUID innecesarios (`find / -perm -4000 -type f`), reemplazándolos por `sudo` acotado a comandos puntuales con logging, o por capabilities específicas; montar los filesystems de datos con `nosuid`. 

*Pivoting:* la segmentación ya existe (`internalnet` es `internal: true`), pero un host de la frontera la puentea. Mitigación concreta: **restringir el egress de la víctima hacia el host interno** a solo el puerto/servicio necesario (firewall de host o network policy), exigir autenticación al servicio de DB y aplicar micro-segmentación con privilegio mínimo de red, de modo que comprometer el host web no otorgue acceso amplio al segmento interno.

## 5. Bitácora de comandos

Los comandos completos están en `evidencia/comandos.txt`; las salidas crudas de identidad, host, R1 y R2 están en `evidencia/salidas/r1-r2-recon-loot.txt`. Las flags se enviaron desde el host con `./ctf submit 08`; el estado resultante se adjunta. Las pruebas controladas del recolector se ejecutaron por separado y están identificadas como locales en la bitácora.
