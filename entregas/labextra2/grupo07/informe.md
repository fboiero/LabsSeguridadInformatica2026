# Entregable — Lab Extra 2: El repo que delata

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado parcial:** Lorenzo preparó la copia forense privada y documentó P5/research; Fernando agregó evidencia de R1/R2 y P2. Guadalupe completó R3, la evaluación de exposición, el plan de remediación y P3/P4. La línea de tiempo completa (P1) sigue pendiente de Lautaro. Las flags R1–R3 fueron recuperadas y verificadas por `sha256` contra `retos.manifest`; el `ctf submit` se hace desde el host.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para consultar documentación oficial y redactar P5/research y esta estructura a partir de mis comandos y evidencia local. Verifiqué la conservación de reflog/objetos en la copia del caso y contrasté las capacidades descritas en las fuentes oficiales enlazadas. No usé IA para inventar ejecuciones ni hallazgos de los otros integrantes. Fernando Cagliero (@Ferca19) usó OpenAI Codex para ejecutar y revisar los comandos Git en el repo ficticio, resumir R1/R2 y redactar P2. No se obtuvieron flags leyendo el generador: se recuperaron con git log, reflog, fsck, show y cat-file. Las salidas crudas se adjuntan. La declaración de Lautaro queda pendiente de su autor.

**Declaración de uso de IA — Guadalupe (@guadagomezgg8):** bloque R3, evaluación de exposición, plan de remediación y P3/P4. Usé **Claude (Anthropic)** para (a) regenerar el caso determinista con `caso/generar-caso.sh` y ejecutar la investigación de la rama abandonada (`git branch -a`, `git log feature/pasarela-pagos --not main`, `git show`), con las salidas en `evidencia/salidas/r3-rama-abandonada.txt`, y (b) redactar R3, la exposición, la remediación, P3/P4 y esta declaración. No se leyó el generador ni `solucion.md`: la flag de R3 salió del contenido del archivo versionado y se validó su `sha256` contra `retos.manifest`. Reviso y puedo explicar cada paso.

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

- **Comandos:** `git branch -a`; `git log --oneline feature/pasarela-pagos --not main`; `git log --all --oneline -- .env.pasarela`; `git show feature/pasarela-pagos:.env.pasarela`.
- La rama `feature/pasarela-pagos` nunca se mergeó a `main`: tiene un único commit propio, `f2e54e7` *«wip: pasarela de pagos (falta todo)»* (autor `dev-jperez`, 2026-08-05 16:30 -03:00). Ahí vive `.env.pasarela`, con la cabecera literal «NO COMMITEAR ESTO (lo commitee igual, despues lo veo)» y la variable `PAGOS_SECRET=FLAG{git_rama_abandonada}`. El archivo no existe en `main` —por eso `git log` sobre `main` no lo muestra—; `--all` y `branch -a` sí lo ven.
- Flag recuperada: `FLAG{git_rama_abandonada}`, verificada por `sha256` contra `retos.manifest`. Es un secreto ficticio; su validez real no se probó. Salida: [r3-rama-abandonada.txt](evidencia/salidas/r3-rama-abandonada.txt).

## 3. Evaluación de exposición

La pregunta no es «¿lo sacamos de `main`?» sino «¿quién pudo verlo ya?». El secreto vivió en un commit versionado; una vez que alguien clona o forkea, el objeto existe fuera de nuestro control.

- **Si el repo fuera público:** exposición máxima. Servicios de escaneo (GitGuardian, TruffleHog) y atacantes barren cada push público; el tiempo mediano entre push y primer uso de una credencial filtrada se mide en minutos. La rama queda además accesible por hash directo en la API del hosting, indexable y forkeable. Se asume el secreto comprometido desde el push.
- **Si fuera privado con 30 colaboradores:** la superficie son esos 30 —más sus clones locales, backups y la CI con acceso—, no «nadie». No se puede auditar quién lo copió ni a qué máquinas llegó. El riesgo es menor que en público pero no nulo: una laptop comprometida, un log de CI o un colaborador descontento alcanzan.
- **Límite del análisis:** sin logs de acceso del hosting (clones, fetches, vistas por API) no se puede afirmar que *nadie* lo vio; solo acotar quién *pudo*. Ante la duda, se trata como expuesto.

## 4. Plan de remediación (P4)

El orden importa: primero cortar el valor, después limpiar la historia.

1. **Rotar/revocar ya** `PAGOS_SECRET` (y revisar `PAGOS_ENDPOINT`): emitir una credencial nueva e invalidar la vieja en el proveedor de pagos. Es lo único que neutraliza una fuga ya ocurrida.
2. **Reescribir la historia** solo *después*: borrar la rama `feature/pasarela-pagos` y, si el secreto estuviera en más commits, `git filter-repo`/BFG + force-push. Esto evita exposiciones *futuras*, no las pasadas.
3. **Avisar y re-clonar:** pedir a los colaboradores que descarten clones viejos (el objeto sobrevive en ellos y en el reflog local).
4. **Prevenir:** detector de secretos en pre-commit (Gitleaks) y push protection del hosting, como detalla P5.

La trampa clásica es invertir 1 y 2 —reescribir y creer que alcanza—: si alguien ya clonó, forkeó o escaneó, la credencial vieja sigue válida hasta que se rota.

## 5. Preguntas P1–P5

### P1 — Línea de tiempo

Pendiente: asignado a Lautaro.

### P2 — Modelo de objetos de Git

Git guarda commits, árboles y blobs como objetos identificados por su contenido; las ramas y `HEAD` son referencias que apuntan a commits. `reset --hard` mueve la referencia y actualiza el árbol de trabajo, pero no borra inmediatamente los objetos que dejaron de estar referenciados. En este caso, `git reflog` conserva la referencia previa a `bc9d0db`, y `git fsck --no-reflogs --unreachable` confirma que el objeto todavía está en el almacén. `git show <commit>` y `git cat-file -p <blob>` reconstruyen el contenido encontrado.

### P3 — Rama abandonada

Una rama abandonada es un archivero de secretos que nadie mira pero cualquiera con acceso al repo puede leer. **Si el repo es público:** `.env.pasarela` es visible para todos aunque `main` esté «limpio» — `git clone` baja todas las ramas y los bots las escanean igual; es el Ejemplo C del lab (*«total eso no está en main»*). **Si es privado con 30 colaboradores:** el secreto está al alcance de los 30 y de todo sistema con acceso (CI, backups, clones). En ambos casos la credencial sigue vigente mientras no se rote: la rama no «esconde» el secreto, solo lo saca del radar de quien lo commiteó. Decir «está en una rama vieja» confunde *poco visible* con *no expuesto*.

### P4 — Orden de remediación

**Rotar primero, reescribir después.** (1) Rotar el secreto en el proveedor e invalidar el viejo —único paso que corta una fuga consumada—. (2) Revocar accesos derivados si los hubo. (3) Recién entonces reescribir la historia (borrar la rama, `filter-repo`/BFG, force-push) para cerrar la exposición futura. (4) Hacer re-clonar a todos y sumar las barreras de prevención de P5. El motivo del orden es el Ejemplo B: el force-push no recupera lo que ya se clonó, forkeó o indexó; mientras la credencial no se rote, sigue sirviendo.

### P5 — Prevención antes del commit y del push

Dos barreras complementarias son un hook local de pre-commit que ejecute un detector de secretos como Gitleaks y la protección server-side de push del hosting. El hook local puede frenar el secreto antes de crear el commit, cuando detecta el patrón; push protection puede bloquearlo al intentar enviar commits al repositorio remoto. Para que sirvan deben configurarse, mantenerse y aplicarse a los equipos y tipos de secreto pertinentes.

Ninguna reemplaza rotar una credencial ya expuesta. Un hook local puede no estar instalado o ser omitido, y una regla remota puede tener patrones no cubiertos o permitir un bypass. La comparación y sus límites están desarrollados en `research.md`.

## 6. Evidencia de progreso

[`status-extra2.txt`](evidencia/salidas/status-extra2.txt) conserva la captura de Lorenzo: R1, R2 y R3 pendientes (0/3) al momento de esa corrida, antes de incorporar el análisis de Fernando. No se ejecutó `./ctf submit` ni se capturó un estado posterior; las flags y la consolidación del grupo siguen pendientes. Las salidas de cada bloque están en `evidencia/salidas/`.
