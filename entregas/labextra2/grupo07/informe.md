# Entregable — Lab Extra 2: El repo que delata

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial de la rama:** Lorenzo preparó la copia forense privada y documentó únicamente P5 y su research asignado. Las secciones R1/R2/P2 de Fernando, R3/P3/P4 y exposición/remediación de Guadalupe, y línea de tiempo/P1 de Lautaro siguen pendientes. Todavía no se recibió evidencia de esos bloques. El CTF marca 0/3; no se presentaron flags.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para consultar documentación oficial y redactar P5/research y esta estructura a partir de mis comandos y evidencia local. Verifiqué la conservación de reflog/objetos en la copia del caso y contrasté las capacidades descritas en las fuentes oficiales enlazadas. No usé IA para inventar ejecuciones ni hallazgos de los otros integrantes. Declaraciones de los demás: pendientes de sus aportes.

---

## 1. Línea de tiempo de la filtración

Pendiente: asignada a Lautaro. Las capturas conservadas hasta ahora solo demuestran la preparación y preservación de la copia local; no sustituyen el análisis de timeline de su bloque.

## 2. Hallazgos

### R1 — Secreto en commit viejo

Pendiente: asignado a Fernando. Sin comandos ni salida de hallazgo recibidos.

### R2 — Commit “perdido”

Pendiente: asignado a Fernando. La copia de análisis contiene el reflog y los objetos no referenciados; su evidencia de investigación del contenido queda pendiente de Fernando.

### R3 — Rama abandonada

Pendiente: asignado a Guadalupe. Sin comandos ni salida de hallazgo recibidos.

## 3. Evaluación de exposición

Pendiente: asignada a Guadalupe. Las estimaciones sobre bots, colaboradores, forks y tiempos deben basarse en su análisis y citar sus límites.

## 4. Plan de remediación (P4)

Pendiente: asignado a Guadalupe.

## 5. Preguntas P1–P5

### P1 — Línea de tiempo

Pendiente: asignado a Lautaro.

### P2 — Modelo de objetos de Git

Pendiente: asignado a Fernando.

### P3 — Rama abandonada

Pendiente: asignado a Guadalupe.

### P4 — Orden de remediación

Pendiente: asignado a Guadalupe.

### P5 — Prevención antes del commit y del push

Dos barreras complementarias son un hook local de pre-commit que ejecute un detector de secretos como Gitleaks y la protección server-side de push del hosting. El hook local puede frenar el secreto antes de crear el commit, cuando detecta el patrón; push protection puede bloquearlo al intentar enviar commits al repositorio remoto. Para que sirvan deben configurarse, mantenerse y aplicarse a los equipos y tipos de secreto pertinentes.

Ninguna reemplaza rotar una credencial ya expuesta. Un hook local puede no estar instalado o ser omitido, y una regla remota puede tener patrones no cubiertos o permitir un bypass. La comparación y sus límites están desarrollados en `research.md`.

## 6. Evidencia de progreso

`evidencia/salidas/status-extra2.txt` conserva la salida completa observada: R1, R2 y R3 pendientes (0/3). `evidencia/salidas/` contiene además las salidas de preparación de la copia privada. Las capturas crudas de los tres comandos de hallazgo se incorporarán cuando las entreguen sus responsables; no se adjuntan resultados simulados.
