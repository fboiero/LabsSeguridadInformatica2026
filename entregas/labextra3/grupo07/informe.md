# Entregable — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial:** Lorenzo implementó D1/D2 y respondió P3; Fernando implementó D4/D5 y respondió P4. D3/P2/P5 siguen asignados a Lautaro; regresión integrada, P1, evidencia final, conclusión e integración corresponden a Guadalupe. Se conservan resultados parciales separados de Lorenzo (D1/D2) y Fernando (D4/D5); no se ejecutó el verificador después de combinar ambos bloques. El estado CTF capturado por Lorenzo es 2/5 (D1/D2).

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para organizar el parche y redactar mis filas/P3. Apliqué los cambios a la copia de `objetivo/server.py`, comparé el diff contra el original y ejecuté el verificador oficial con `--dir` sobre mi copia. Verifiqué las flags de D1/D2 con `./ctf status extra3`. No usé IA para inventar salidas ni para atribuirme los bloques pendientes. Fernando Cagliero (@Ferca19) usó OpenAI Codex para implementar D4/D5, preparar un harness local y redactar P4; la salida real de su verificación se conserva. No se afirman como integradas las verificaciones independientes.

---

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación (salida del ataque bloqueado) |
|---|---|---|---|
| D1 | El verificador inicial observó `Server: 'PhantomServer/2.4.1-debug '`. | `VERSION` queda vacío y `sys_version` sigue vacío; el header ya no identifica el producto ni la versión. El diff está en `evidencia/salidas/d1-d2.diff`. | El verificador con `--dir` observó `header Server: ''` y marcó D1 bloqueado. Salida: `evidencia/salidas/verificador-parcial.txt`. D1 aceptado por el CTF. |
| D2 | El verificador inicial recibió HTTP 200 de `/api/status` con `debug`, la ruta de la base y el PID. | Se eliminó la rama que publicaba el endpoint; la ruta cae en el 404 genérico. | El verificador recibió `GET /api/status -> 404 '404 - no existe'` y marcó D2 bloqueado. Salida: `evidencia/salidas/verificador-parcial.txt`. D2 aceptado por el CTF. |
| D3 | Pendiente: asignado a Lautaro. | Pendiente. | No probado por Lorenzo. |
| D4 | Los payloads de SQLi podían alterar la consulta de login. | Consulta SQLite parametrizada con valores enlazados. | En el harness local, los bypasses devuelven 401 y el login legítimo 200; salida en `evidencia/salidas/verificacion-d4-d5.txt`. |
| D5 | `archivo=../../etc/passwd` podía salir del directorio de descargas. | `realpath` del destino y raíz, con `commonpath` para exigir que permanezca dentro del directorio permitido. | El harness bloqueó traversal directo, codificado y un nombre con prefijo similar; `manual.txt` sigue disponible. Salida en `evidencia/salidas/verificacion-d4-d5.txt`. |

### Nota sobre D5 y el entorno

El verificador inicial del original dio 1/5: D1–D4 vulnerables, D5 aparecía bloqueado. Después de mis cambios dio 3/5: D1 y D2 bloqueados por mi parche y D5 aparecía igual que antes. Como `server.py` original no se modificó y el target copiado no tiene parche D5 de mi parte, esa señal es un falso positivo del entorno Windows/ruta POSIX para esta comprobación, no un arreglo. Ese resultado precede al parche D5 de Fernando y no se atribuye a su código. El CTF confirma 2/5 y solo D1/D2 están aceptados. Se conservaron ambas salidas completas.

## 2. Regresión funcional

El harness local de Fernando, ejecutado contra su copia con D4/D5 antes de integrar D1/D2, confirmó GET / 200, login legítimo 200, bypasses SQLi 401 y descarga de manual.txt 200, además de bloquear traversal. La regresión funcional de la copia ya integrada queda para la verificación de Guadalupe.
## 3. Evidencia de progreso

- Verificador inicial: `evidencia/salidas/verificador-inicial.txt` (salida 1/5 observada en Windows).
- Verificador contra la copia tras el bloque de Lorenzo: `evidencia/salidas/verificador-parcial.txt` (3/5 observado; D1/D2 aceptados y el D5 no atribuido al parche).
- Estado completo del CTF: `evidencia/salidas/status-extra3.txt` (2/5; D1/D2 ✓).
- Diff D1/D2: `evidencia/salidas/d1-d2.diff`.
- Verificación local D4/D5 y regresiones: `evidencia/salidas/verificacion-d4-d5.txt`.

No se capturó una nueva corrida del verificador contra el código combinado; no se atribuye un resultado integrado 4/5.

## 4. Preguntas P1–P5

### P1 — Antes/después de una defensa

Pendiente: asignada a Guadalupe, quien integra la evidencia completa del grupo.

### P2 — `robots.txt` y autorización

Pendiente: asignada a Lautaro.

### P3 — ¿D1 es una defensa real?

Neutralizar el banner es una medida de reducción de información: dificulta que un escaneo pasivo identifique inmediatamente producto y versión, y puede reducir ruido automatizado. No corrige una vulnerabilidad de autenticación, autorización ni ejecución. Un atacante todavía puede inferir tecnología por respuestas, rutas, formato de errores o comportamiento, y el producto vulnerable permanece vulnerable. Por eso ocultar versión puede ser una capa auxiliar, pero confiar en que el atacante no la descubra es seguridad por oscuridad y da una falsa sensación de protección. La defensa real está en corregir y actualizar el software y en controles que impidan el acceso no autorizado.

### P4 — Reemplazar comillas frente a consultas parametrizadas

Eliminar comillas con user.replace es un filtro de sintaxis SQL y depende de una lista incompleta de caracteres y formas de escritura. No separa de manera fiable el dato del código: comentarios, operadores, codificaciones y diferencias entre motores o contextos de consulta pueden dejar variantes sin cubrir, y el escape manual es fácil de aplicar de forma inconsistente. La consulta parametrizada mantiene fija la estructura SQL y enlaza usuario y contraseña como valores separados; el motor no los interpreta como operadores ni cláusulas. Esa es la defensa estructural. El parche D4 usa parámetros SQLite y la evidencia bloquea los dos payloads del verificador.

### P5 — Ranking de los cinco problemas

Pendiente: asignada a Lautaro.

## 5. Conclusión

Pendiente: integración de Guadalupe después de recibir los demás bloques y la evidencia de regresión.
