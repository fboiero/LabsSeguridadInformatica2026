# Entregable — Lab Extra 2: El repo que delata

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial:** Lorenzo preparó la copia forense privada y documentó P5/research; Fernando agregó evidencia de R1/R2 y P2. R3, exposición/remediación y P3/P4 siguen pendientes de Guadalupe; la línea de tiempo completa y P1, de Lautaro. No se presentaron flags y no se ejecutó ctf submit.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para consultar documentación oficial y redactar P5/research y esta estructura a partir de mis comandos y evidencia local. Verifiqué la conservación de reflog/objetos en la copia del caso y contrasté las capacidades descritas en las fuentes oficiales enlazadas. No usé IA para inventar ejecuciones ni hallazgos de los otros integrantes. Fernando Cagliero (@Ferca19) usó OpenAI Codex para ejecutar y revisar los comandos Git en el repo ficticio, resumir R1/R2 y redactar P2. No se obtuvieron flags leyendo el generador: se recuperaron con git log, reflog, fsck, show y cat-file. Las salidas crudas se adjuntan. Las declaraciones de Guadalupe y Lautaro quedan pendientes de cada autor.

---

## 1. Línea de tiempo de la filtración

La reconstrucción completa de P1 corresponde a Lautaro. En R1 se observó la introducción del token en `9333f2b` (2026-08-10 18:47 -03:00) y su eliminación del árbol en `eafb81c` (2026-08-11 10:05 -03:00), 15 h 18 min después. La eliminación no quitó el commit anterior de la historia.

## 2. Hallazgos

### R1 — Secreto en commit viejo

- **Comando:** git -C labs/labextra2-git-forense/caso/repo-delata log main --date=iso-strict --format='%H %ad %an <%ae> %s' --patch.
- **Salida:** [r1-git-log-p.txt](evidencia/salidas/r1-git-log-p.txt).
- El diff de `9333f2b` agrega `PHANTOM_API_TOKEN` y el de `eafb81c` elimina esa línea del árbol actual. El valor recuperado fue `FLAG{git_log_no_olvida}`. Es un token ficticio; su alcance no se probó ni se infiere de la cadena por sí sola.

### R2 — Commit “perdido”

- **Comandos:** git reflog --all --date=iso-strict; git fsck --full --no-reflogs --unreachable; git show bc9d0dbe6aca41d639a515395cc983e139979102; git cat-file -p fc979fdad9fb6246fd683eb2087b2d7e94ef0563.
- El reflog registra un reset de `main` hacia `HEAD~1` el 2026-08-12 14:22 -03:00, después del commit `bc9d0db`. `fsck` encuentra el commit inalcanzable, su árbol y el blob de notas; `git show` y `git cat-file` permiten leerlos.
- La nota contiene la llave ficticia de staging y `FLAG{git_reflog_rescata}`. El acceso efectivo que permitiría esa llave no se probó.
- Salidas: [r2-reflog.txt](evidencia/salidas/r2-reflog.txt), [r2-fsck.txt](evidencia/salidas/r2-fsck.txt), [r2-commit-content.txt](evidencia/salidas/r2-commit-content.txt) y [r2-unreachable-blob.txt](evidencia/salidas/r2-unreachable-blob.txt).

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

Git guarda commits, árboles y blobs como objetos identificados por su contenido; las ramas y `HEAD` son referencias que apuntan a commits. `reset --hard` mueve la referencia y actualiza el árbol de trabajo, pero no borra inmediatamente los objetos que dejaron de estar referenciados. En este caso, `git reflog` conserva la referencia previa a `bc9d0db`, y `git fsck --no-reflogs --unreachable` confirma que el objeto todavía está en el almacén. `git show <commit>` y `git cat-file -p <blob>` reconstruyen el contenido encontrado.

### P3 — Rama abandonada

Pendiente: asignado a Guadalupe.

### P4 — Orden de remediación

Pendiente: asignado a Guadalupe.

### P5 — Prevención antes del commit y del push

Dos barreras complementarias son un hook local de pre-commit que ejecute un detector de secretos como Gitleaks y la protección server-side de push del hosting. El hook local puede frenar el secreto antes de crear el commit, cuando detecta el patrón; push protection puede bloquearlo al intentar enviar commits al repositorio remoto. Para que sirvan deben configurarse, mantenerse y aplicarse a los equipos y tipos de secreto pertinentes.

Ninguna reemplaza rotar una credencial ya expuesta. Un hook local puede no estar instalado o ser omitido, y una regla remota puede tener patrones no cubiertos o permitir un bypass. La comparación y sus límites están desarrollados en `research.md`.

## 6. Evidencia de progreso

[`status-extra2.txt`](evidencia/salidas/status-extra2.txt) conserva la captura de Lorenzo: R1, R2 y R3 pendientes (0/3) al momento de esa corrida, antes de incorporar el análisis de Fernando. No se ejecutó `./ctf submit` ni se capturó un estado posterior; las flags y la consolidación del grupo siguen pendientes. Las salidas de cada bloque están en `evidencia/salidas/`.
