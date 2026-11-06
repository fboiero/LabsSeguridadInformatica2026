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

(Desarrollá las 5 preguntas del README.)

## 6. Evidencia de progreso

- Captura de `./ctf status extra2` con los 3 ✓.
- Confirmá que adjuntaste `evidencia/comandos.txt` y `evidencia/salidas/`
  (ver README § Reporte y evidencia).
