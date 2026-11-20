# Entregable — Lab Extra 2: El repo que delata

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando
Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño
(@lautaromarino0) · **Fecha:** 19/11/2026 (America/Buenos_Aires)

## Declaración de uso de IA

Fernando Cagliero (@Ferca19) usó OpenAI Codex para ejecutar y revisar los
comandos Git en el repo ficticio generado por el laboratorio, resumir los
hallazgos R1/R2 y redactar P2. No se obtuvieron flags leyendo el generador ni
el código del caso: se recuperaron con `git log -p`, `git reflog`, `git fsck`
y `git show`/`git cat-file`. Las salidas crudas se adjuntan. Las declaraciones
de Lorenzo, Guadalupe y Lautaro quedan pendientes de cada autor.

---

## 1. Línea de tiempo de la filtración

La reconstrucción completa de P1 corresponde a Lautaro. La evidencia de R1
identifica la introducción del token en `9333f2b` (2026-08-10 18:47 -03:00) y
su eliminación del árbol en `eafb81c` (2026-08-11 10:05 -03:00). La diferencia
entre esos commits es 15 h 18 min; la eliminación no retiró el commit anterior
de la historia.

## 2. Hallazgos

### R1 — Secreto en commit viejo

- **Comando:** `git -C labs/labextra2-git-forense/caso/repo-delata log main --date=iso-strict --format='%H %ad %an <%ae> %s' --patch`
- **Salida:** [`evidencia/salidas/r1-git-log-p.txt`](evidencia/salidas/r1-git-log-p.txt).
- El diff de `9333f2b` agrega `PHANTOM_API_TOKEN`; el diff de `eafb81c`
  elimina esa línea del árbol actual. El valor recuperado fue
  `FLAG{git_log_no_olvida}`. Es un token de API ficticio; podría permitir
  operaciones dentro de su alcance, pero ese alcance no se probó ni se infiere
  de la cadena por sí sola.

### R2 — Commit «perdido»

- **Comandos:** `git reflog --all --date=iso-strict`,
  `git fsck --full --no-reflogs --unreachable`,
  `git show bc9d0dbe6aca41d639a515395cc983e139979102` y
  `git cat-file -p fc979fdad9fb6246fd683eb2087b2d7e94ef0563`.
- El reflog registra que el 2026-08-12 14:22 -03:00 se hizo reset de `main`
  hacia `HEAD~1`, después del commit `bc9d0db`. `fsck` encuentra ese commit
  inalcanzable, su árbol y el blob de notas. `git show` reconstruye el commit y
  muestra la ruta; `git cat-file` lee directamente el blob.
- La nota recuperada contiene la llave ficticia de staging y el valor
  `FLAG{git_reflog_rescata}`. El acceso efectivo que permitiría esa llave no
  se probó.
- Salidas: [`r2-reflog.txt`](evidencia/salidas/r2-reflog.txt),
  [`r2-fsck.txt`](evidencia/salidas/r2-fsck.txt),
  [`r2-commit-content.txt`](evidencia/salidas/r2-commit-content.txt) y
  [`r2-unreachable-blob.txt`](evidencia/salidas/r2-unreachable-blob.txt).

### R3 — Rama abandonada

Pendiente — bloque de Guadalupe. No se documenta aquí su flag.

## 3. Evaluación de exposición

P3 y la estimación de tiempo de detección corresponden a Guadalupe. Pendiente
de completar con evidencia/fuentes del grupo; no se atribuye una medición a un
bot.

## 4. Plan de remediación (P4)

Pendiente — bloque de Guadalupe. Debe acordarse con el grupo antes de integrar
la remediación completa.

## 5. Preguntas P1–P5

**P1 — línea de tiempo completa:** pendiente — bloque de Lautaro. Los commits
de R1 se referencian en §1 y en la salida cruda.

**P2 — por qué `reset --hard` no borró las notas:** Git guarda commits, árboles
y blobs como objetos identificados por su contenido; las ramas y `HEAD` son
referencias que apuntan a commits. `reset --hard` mueve la referencia y
actualiza el árbol de trabajo, pero no borra inmediatamente los objetos que
dejaron de estar referenciados. En este caso, `git reflog` conserva la
referencia previa a `bc9d0db`, y `git fsck --no-reflogs --unreachable` confirma
que el objeto todavía está en el almacén. `git show <commit>` y
`git cat-file -p <blob>` reconstruyen el contenido encontrado.

**P3 — riesgos de la rama abandonada:** pendiente — Guadalupe.

**P4 — orden de remediación:** pendiente — Guadalupe.

**P5 — prevención antes del commit y al hacer push:** pendiente — Lorenzo.

## 6. Evidencia de progreso

Las salidas y comandos de R1/R2 están adjuntos. No se ejecutó `./ctf submit`
ni se adjunta una captura de `./ctf status extra2`; el estado del CTF queda
pendiente de la consolidación grupal y de R3.
