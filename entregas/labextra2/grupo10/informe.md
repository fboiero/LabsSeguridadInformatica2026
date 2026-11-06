# Entregable — Lab Extra 2: El repo que delata

> Copiá este archivo a `entregas/labextra2/grupoXX/informe.md` y completalo.

**Grupo:** 10 · **Integrantes:** Ramello, Belén Rocío — @belramello · Corazza, Carolina Paula — @carocor1 · Kordek, Chiara Agustina — @chiarakordek · Saby, Juan Pablo — @JuanSaby

**Declaración de uso de IA:** se utilizó ChatGPT mediante OpenCode para ejecutar el generador y comandos de Git con herramientas de terminal, guardar sus salidas reales y asistir en la redacción de R1/P1.

---

## 1. Línea de tiempo de la filtración

Tabla cronológica de TODOS los eventos relevantes de la historia (incluí los
commits "legítimos" también: el contexto es parte del informe):

| Fecha | Autor | Commit (hash corto) | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| | | | | |

## 2. Hallazgos

### R1 — Secreto en commit viejo

- **Entorno y comandos exactos:** Git Bash para Windows. Se ejecutó el generador de la cátedra en una carpeta temporal nueva, convirtiendo únicamente los finales CRLF del script a LF, sin reconstruir los archivos ni los commits manualmente. Se desactivó `core.autocrlf` solo para esa ejecución. No se modificó el caso preexistente. Desde la raíz del repositorio:
  ```bash
  bash entregas/labextra2/grupo10/evidencia/reproducir-r1.sh
  ```
  Dentro del repo generado, el procedimiento ejecuta:
  ```bash
  git --no-pager log --oneline > "$EVIDENCIA/salidas/historia-r1.txt"
  git --no-pager log -p > "$EVIDENCIA/salidas/historia-diffs-r1.txt"
  git --no-pager log -p -- config.py > "$EVIDENCIA/salidas/r1.txt"
  git --no-pager log --format='%h | %H | %an <%ae> | %aI | %s' -- config.py > "$EVIDENCIA/salidas/timeline-r1.txt"
  ```
  `git log` muestra los commits y sus metadatos; `--oneline` resume cada commit en una línea y `-p` añade sus cambios. En la historia aparecen los mensajes de hotfix y limpieza; al revisar los diffs se ve que el archivo afectado es `config.py` y se recupera el token. Luego `-- config.py` limita la consulta a ese archivo para guardar el hallazgo. Las salidas anteriores al filtro están en `historia-r1.txt` e `historia-diffs-r1.txt`; el listado de comandos está en `evidencia/comandos-carolina.txt`. `$EVIDENCIA` es la ruta de evidencia definida por el procedimiento adjunto.
- **Salida relevante:** extracto de `evidencia/salidas/r1.txt`; el archivo adjunto contiene la salida completa, redirigida directamente por Bash:
  ```diff
  commit eafb81c3ec5790ce4741629458e11ab5c1a690b8
  Author: dev-jperez <jperez@phantomcorp.example>
  Date:   Tue Aug 11 10:05:00 2026 -0300

      fix: sacar credenciales del codigo (ups)

  diff --git a/config.py b/config.py
  index 04e01ad..3d61e50 100644
  --- a/config.py
  +++ b/config.py
  @@ -1,4 +1,3 @@
  -# Config de emergencia — arreglar el deploy roto YA (después lo pasamos a env)
  -PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"
  +# Config — sin secretos, por fin
   REGION = "us-east-1"
  -DEBUG = True
  +DEBUG = False

  commit 9333f2b4a09f7a320cb66d621c3bd53b4f694941
  Author: dev-jperez <jperez@phantomcorp.example>
  Date:   Mon Aug 10 18:47:00 2026 -0300

      hotfix: deploy roto en produccion (config temporal)

  diff --git a/config.py b/config.py
  new file mode 100644
  index 0000000..04e01ad
  --- /dev/null
  +++ b/config.py
  @@ -0,0 +1,4 @@
  +# Config de emergencia — arreglar el deploy roto YA (después lo pasamos a env)
  +PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"
  +REGION = "us-east-1"
  +DEBUG = True
  ```
- **Qué secreto se expuso y qué habilita:** `PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"`, un token ficticio asociado a la API de PhantomCorp. Una credencial real vigente permitiría actuar con los permisos asignados al token; el caso no especifica esos permisos ni demuestra acceso a una API real. El commit de limpieza elimina la línea del archivo actual, pero el diff conserva su valor.

### R2 — Commit "perdido"
- **Comando(s) exacto(s):**
  ```
  git log --oneline --all
  git reflog
  git fsck --unreachable --no-reflogs
  git show bc9d0db
  ```
- **¿Cómo llegaste del reflog/fsck al contenido del objeto?** `git log --oneline --all` solo mostró 5 commits, sin rastro de ningún `reset`. `git reflog` reveló el movimiento real de `HEAD`: en `HEAD@{5}` hay un commit `bc9d0db` ("wip: notas del cluster nuevo (no mergear todavia)"), y en `HEAD@{4}` un `reset: moving to HEAD~1` que lo dejó sin ninguna rama apuntándolo. Para confirmar que el objeto seguía existiendo sin depender del reflog, corrí `git fsck --unreachable --no-reflogs`, que listó `bc9d0db` como *unreachable commit* (junto con su árbol y su blob). Con el hash en mano, `git show bc9d0db` mostró el diff completo de ese commit.
- **Qué secreto se expuso:** el commit agrega `notas_investigacion.txt` con el texto `staging_key: FLAG{git_reflog_rescata}`, descrito como la llave de acceso a un cluster de staging que el equipo de infra había pasado "para probar". El propio archivo aclara que la intención era rotarla y borrar las notas una vez migrado todo; el `reset --hard` reemplazó esa intención, pero el objeto siguió existiendo en el repositorio.

### R3 — Rama abandonada
- Comando(s) exacto(s):
- Qué secreto se expuso:

## 3. Evaluación de exposición

Si este repo hubiera estado **público en GitHub** desde el commit inicial:
¿cuál de los 3 secretos habría sido encontrado primero por un bot? ¿Por qué?
¿Cuánto tiempo estimás que tardaría?

## 4. Plan de remediación (respondiendo P4)

Ordená y justificá: rotación de secretos, reescritura de historia, contacto a
quienes forkearon/clonaron, revocación de accesos, lecciones aprendidas.

## 5. Preguntas P1–P5

### P1 — Línea de tiempo del token de la API (Carolina)

La salida propia de Git (`evidencia/salidas/timeline-r1.txt`) permite reconstruir:

| Evento | Hash completo | Autor | Fecha (-03:00) | Mensaje |
|---|---|---|---|---|
| Introducción del token | `9333f2b4a09f7a320cb66d621c3bd53b4f694941` | dev-jperez <jperez@phantomcorp.example> | 10/08/2026 18:47 | hotfix: deploy roto en produccion (config temporal) |
| Eliminación de la línea en main | `eafb81c3ec5790ce4741629458e11ab5c1a690b8` | dev-jperez <jperez@phantomcorp.example> | 11/08/2026 10:05 | fix: sacar credenciales del codigo (ups) |

Entre ambos commits transcurrieron **15 horas y 18 minutos**: es el tiempo con el token presente en la versión corriente de `main`, no el final de su exposición histórica. No hay evidencia de rotación ni de la fecha de publicación del repo; no se puede deducir la duración exacta de una exposición pública solo de estas fechas.

**No alcanza con el commit de limpieza.** `git log -p -- config.py` recupera el valor desde la historia incluso después de eliminarlo del archivo actual. Cada commit referencia una instantánea de los archivos y sus commits padres: el de limpieza crea una versión nueva, no modifica el commit de hotfix ni su contenido. El commit viejo sigue alcanzable, y las copias clonadas o forkeadas pueden conservarlo. Ante una credencial real se debe revocar/rotar primero: borrar la línea o reescribir la historia no invalida una copia del token.

### P2 — Por qué `reset --hard` no borra el commit

En el modelo de objetos de git, un commit es un objeto inmutable guardado en `.git/objects`, identificado por el hash de su contenido. Una rama (`main`, `feature/...`) no es más que un archivo de texto con ese hash adentro: una etiqueta que *apunta* a un commit, no el commit en sí. `git reset --hard HEAD~1` mueve esa etiqueta (y el puntero `HEAD`) un commit hacia atrás y pisa el working directory para que coincida; lo único que cambia es a qué objeto apunta la rama. El objeto commit que quedó "atrás" no se toca ni se elimina: sigue completo en el object store, simplemente ninguna rama lo referencia.

Esto es exactamente lo que pasó con `bc9d0db`: el dev corrió el `reset` pensando que sus notas "desaparecían", pero el commit, su árbol y su blob siguieron existiendo. Dos comandos lo demuestran:

1. **`git reflog`** — muestra el historial real de movimientos de `HEAD` en este repositorio local (no depende de que una rama señale el commit). Ahí aparece `HEAD@{5} bc9d0db ...` antes del `reset: moving to HEAD~1` de `HEAD@{4}`: el reflog conserva la referencia aunque ninguna rama lo haga.
2. **`git fsck --unreachable --no-reflogs`** — recorre el object store completo, sin mirar el reflog, y encuentra objetos que existen pero que ningún ref alcanza. Marcó a `bc9d0db` como *unreachable commit*, lo que prueba que el objeto sigue ahí por sí mismo, independientemente de cualquier historial de `HEAD`.

Git retiene estos objetos "colgados" durante un período (el reflog expira, y la recolección de basura —`git gc`— puede eventualmente liberarlos, por defecto a los ~90 días), pero mientras eso no ocurra, el secreto sigue recuperable por cualquiera con acceso al repositorio. Por eso un `reset --hard` nunca es una forma de remediar una filtración: hay que rotar el secreto.

## 6. Evidencia de progreso

- Captura de `./ctf status extra2` con los 3 ✓.
- Confirmá que adjuntaste `evidencia/comandos.txt` y `evidencia/salidas/`
  (ver README § Reporte y evidencia).
