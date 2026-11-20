# Entregable — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial:** Lorenzo implementó D1/D2 y respondió P3. D3/P2/P5/evidencia parcial son de Lautaro; D4/D5/P4 son de Fernando; regresión funcional, P1, evidencia final, conclusión e integración son de Guadalupe. Esos bloques siguen pendientes. El estado del CTF observado es 2/5.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para organizar el parche y redactar mis filas/P3. Apliqué los cambios a la copia de `objetivo/server.py`, comparé el diff contra el original y ejecuté el verificador oficial con `--dir` sobre mi copia. Verifiqué las flags de D1/D2 con `./ctf status extra3`. No usé IA para inventar salidas ni para atribuirme los bloques pendientes. Declaraciones de los demás: pendientes.

---

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación (salida del ataque bloqueado) |
|---|---|---|---|
| D1 | El verificador inicial observó `Server: 'PhantomServer/2.4.1-debug '`. | `VERSION` queda vacío y `sys_version` sigue vacío; el header ya no identifica el producto ni la versión. El diff está en `evidencia/salidas/d1-d2.diff`. | El verificador con `--dir` observó `header Server: ''` y marcó D1 bloqueado. Salida: `evidencia/salidas/verificador-parcial.txt`. D1 aceptado por el CTF. |
| D2 | El verificador inicial recibió HTTP 200 de `/api/status` con `debug`, la ruta de la base y el PID. | Se eliminó la rama que publicaba el endpoint; la ruta cae en el 404 genérico. | El verificador recibió `GET /api/status -> 404 '404 - no existe'` y marcó D2 bloqueado. Salida: `evidencia/salidas/verificador-parcial.txt`. D2 aceptado por el CTF. |
| D3 | Pendiente: asignado a Lautaro. | Pendiente. | No probado por Lorenzo. |
| D4 | Pendiente: asignado a Fernando. | Pendiente. | No probado por Lorenzo. |
| D5 | El original también apareció como “bloqueado” en este verificador de Windows, aunque no fue modificado. | Pendiente: asignado a Fernando. El resultado inicial no se considera fix ni evidencia válida de defensa. | Pendiente de verificación en el entorno previsto por el grupo. |

### Nota sobre D5 y el entorno

El verificador inicial del original dio 1/5: D1–D4 vulnerables, D5 aparecía bloqueado. Después de mis cambios dio 3/5: D1 y D2 bloqueados por mi parche y D5 aparecía igual que antes. Como `server.py` original no se modificó y el target copiado no tiene parche D5 de mi parte, esa señal es un falso positivo del entorno Windows/ruta POSIX para esta comprobación, no un arreglo. No presenté D5. El CTF confirma 2/5 y solo D1/D2 están aceptados. Se conservaron ambas salidas completas.

## 2. Regresión funcional

Pendiente de la comprobación integrada asignada a Guadalupe: `GET /`, login legítimo y descarga de `manual.txt`. No se declara una regresión funcional probada en esta entrega parcial.

## 3. Evidencia de progreso

- Verificador inicial: `evidencia/salidas/verificador-inicial.txt` (salida 1/5 observada en Windows).
- Verificador contra la copia tras el bloque de Lorenzo: `evidencia/salidas/verificador-parcial.txt` (3/5 observado; D1/D2 aceptados y el D5 no atribuido al parche).
- Estado completo del CTF: `evidencia/salidas/status-extra3.txt` (2/5; D1/D2 ✓).
- Diff D1/D2: `evidencia/salidas/d1-d2.diff`.

## 4. Preguntas P1–P5

### P1 — Antes/después de una defensa

Pendiente: asignada a Guadalupe, quien integra la evidencia completa del grupo.

### P2 — `robots.txt` y autorización

Pendiente: asignada a Lautaro.

### P3 — ¿D1 es una defensa real?

Neutralizar el banner es una medida de reducción de información: dificulta que un escaneo pasivo identifique inmediatamente producto y versión, y puede reducir ruido automatizado. No corrige una vulnerabilidad de autenticación, autorización ni ejecución. Un atacante todavía puede inferir tecnología por respuestas, rutas, formato de errores o comportamiento, y el producto vulnerable permanece vulnerable. Por eso ocultar versión puede ser una capa auxiliar, pero confiar en que el atacante no la descubra es seguridad por oscuridad y da una falsa sensación de protección. La defensa real está en corregir y actualizar el software y en controles que impidan el acceso no autorizado.

### P4 — Reemplazar comillas frente a consultas parametrizadas

Pendiente: asignada a Fernando.

### P5 — Ranking de los cinco problemas

Pendiente: asignada a Lautaro.

## 5. Conclusión

Pendiente: integración de Guadalupe después de recibir los demás bloques y la evidencia de regresión.
