# Informe — Laboratorio 07 · Explotación

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha:** 2026-11-19 (America/Buenos_Aires)

> Esta edición documenta el bloque asignado a Lorenzo (R1 y R2). Las demás filas y respuestas quedan pendientes de sus responsables antes de integrar la entrega del grupo.

## 0. Declaración de uso de IA

Se usó OpenAI Codex como asistente con acceso a la terminal local para planificar el bloque, preparar y ejecutar requests HTTP contra el contenedor PhantomCorp del laboratorio, interpretar las respuestas observadas y redactar este informe y la evidencia de R1/R2. La IA ejecutó las requests registradas; no se consultó el código del objetivo para obtener las flags. Las pruebas de esta edición se verificaron con las respuestas HTTP y el estado del CTF (2/5). Lorenzo debe revisar y poder explicar los payloads antes de la entrega final.

## 1. Flags capturadas

Estado observado con `./ctf status 07`:

```text
R1  SQLi - bypass de autenticacion                         resuelto
R2  SQLi - extraccion de datos con UNION                   resuelto
R3  Inyeccion de comandos (RCE)                            pendiente
R4  Path traversal / LFI                                   pendiente
R5  IDOR - control de acceso roto                          pendiente
Progreso: 2/5 (40%)
```

La salida completa está en `evidencia/salidas/status-07.txt`. R3–R5 corresponden a otros bloques del reparto y no se atribuyen a Lorenzo en esta edición.

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) | `user=admin' --` y `pass=not-the-password` | Reconstrucción inferida a partir de la consigna: `SELECT user, rol FROM users WHERE user='admin' --' AND pass='not-the-password'`. `--` inicia el comentario SQL y el motor ignora la condición de contraseña que sigue. | El servidor respondió `Bienvenido admin (rol: admin)` y devolvió la flag de R1; la autenticación ocurrió sin conocer la contraseña. | Consulta parametrizada para usuario y contraseña; almacenar contraseñas con un KDF adecuado y verificar el hash después de recuperar el registro. No concatenar valores dentro del SQL. |
| SQLi UNION (R2) | `q=x' UNION SELECT * FROM secrets -- `; control de aridad `UNION SELECT 1,2` (aceptado) frente a `UNION SELECT 1,2,3` (error). | Reconstrucción inferida según el buscador documentado: `SELECT nombre, precio FROM productos WHERE nombre LIKE '%x' UNION SELECT * FROM secrets -- %'`. Dos columnas funcionan; tres producen el error de aridad. `SELECT * FROM secrets` mostró una fila presentada como `flag_union - $FLAG{sqli_union_dump}`. | Lectura de un registro de la tabla `secrets` a través del buscador; la respuesta entregó la flag R2. El intento de nombres de columnas no observados dio `no such column: name`, por lo que no se afirma un esquema que no se haya comprobado. | Parametrizar `q` como dato de `LIKE`; no concatenarlo como SQL. Restringir además la consulta al conjunto de campos previsto y no exponer errores SQL al cliente. |
| Command injection (R3) | `host=127.0.0.1;cat /app/flags/cmdi.txt` (probe previo `host=127.0.0.1;id` → `uid=0(root)`). | El endpoint arma `ping -c1 <host>` y `host` va directo al shell: `ping -c1 127.0.0.1;cat /app/flags/cmdi.txt`. El `;` encadena un segundo comando. | **RCE como root** (uid=0): se leyó `/app/flags/cmdi.txt` → `FLAG{command_injection_rce}` (sha256 verificado contra `retos.manifest`). Con RCE se puede leer/escribir cualquier archivo, instalar persistencia y pivotear (Lab 08). | No pasar entrada a un shell: usar `subprocess` con lista de argumentos y sin `shell=True`; validar `host` con allowlist (regex de IP/hostname); correr el servicio sin privilegios, nunca como root. |
| Path traversal (R4) | `archivo=../flags/lfi.txt`. | El archivo se abre desde `public/`: `archivo` se concatena y queda `/app/public/../flags/lfi.txt` → `/app/flags/lfi.txt`. Un solo `../` alcanza porque `public/` cuelga de `/app`; `../../flags/lfi.txt` sobrepasa (`/flags`) y da `No such file`. | Lectura de un archivo **fuera de `public/`** → `FLAG{path_traversal_lfi}` (sha256 verificado contra `retos.manifest`). Permite leer archivos arbitrarios del servidor (config, secretos). | Canonicalizar con `os.path.realpath` y verificar que el resultado quede **dentro** del directorio base; rechazar `..`; servir solo desde un allowlist. No construir rutas por concatenación directa. |
| IDOR (R5) | Pendiente — bloque de Guadalupe. | Pendiente. | Pendiente. | Pendiente. |

Los SQL reconstruidos son inferencias basadas en la plantilla/consigna y el comportamiento HTTP, no capturas internas de la consulta ejecutada. Las respuestas crudas y probes están en `evidencia/salidas/r1-r2-http.txt`.

## 3. Preguntas de análisis

- **P1 — bypass R1:** pendiente — bloque de Guadalupe.
- **P2 — aridad de UNION:** pendiente — bloque de Guadalupe. Evidencia de apoyo para integrar: la variante con dos expresiones devolvió una fila (`1 - $2`); la variante con tres devolvió el error de distinto número de columnas. Ver `evidencia/salidas/r1-r2-http.txt`.
- **P3 — después del RCE:** pendiente — bloque de Fernando.
- **P4 — parametrización:** pendiente — bloque de Fernando.
- **P5 — autorización del IDOR:** pendiente — bloque de Guadalupe.

## 4. Bitácora de comandos

Las requests se enviaron desde el atacante del Compose, únicamente contra `phantomcorp` local. El registro de comandos reproducibles está en `evidencia/comandos.txt`; las respuestas HTTP completas están en `evidencia/salidas/r1-r2-http.txt`. Las flags observadas se enviaron desde el host mediante `./ctf submit 07 R1 ...` y `./ctf submit 07 R2 ...`; el estado resultante (2/5) está adjunto.
