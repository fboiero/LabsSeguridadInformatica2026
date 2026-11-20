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
| Command injection (R3) | Pendiente — bloque de Lautaro. | Pendiente. | Pendiente. | Pendiente. |
| Path traversal (R4) | Pendiente — bloque de Lautaro. | Pendiente. | Pendiente. | Pendiente. |
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
