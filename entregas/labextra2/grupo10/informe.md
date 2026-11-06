# Entregable — Lab Extra 2: El repo que delata

> Copiá este archivo a `entregas/labextra2/grupoXX/informe.md` y completalo.

**Grupo:** 10 · **Integrantes:** Ramello, Belén Rocío — @belramello · Corazza, Carolina Paula — @carocor1 · Kordek, Chiara Agustina — @chiarakordek · Saby, Juan Pablo — @JuanSaby

**Declaración de uso de IA:** (obligatoria)

---

## 1. Línea de tiempo de la filtración

Tabla cronológica de TODOS los eventos relevantes de la historia (incluí los
commits "legítimos" también: el contexto es parte del informe):

| Fecha | Autor | Commit (hash corto) | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| | | | | |

## 2. Hallazgos

### R1 — Secreto en commit viejo
- Comando(s) exacto(s):
- Salida relevante (pegá el diff):
- Qué secreto se expuso y qué habilita:

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
