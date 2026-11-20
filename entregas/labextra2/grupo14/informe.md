# Entregable — Lab Extra 2: El repo que delata

**Grupo:** 14 · **Integrantes:** Peron, Fede (@fedeeperon) · Gomez Redondo, Laureano (@Laureano-GR) · Cesano, Martín (@martincesano) · Gaido, Martín (@martingaidoo) · Chiapero, Valentina (@valechiapero)

**Declaración de uso de IA:** Usamos un asistente de IA para ordenar el informe
y revisar la redacción de las respuestas P1–P5. La investigación forense (los
comandos `git log -p`, `reflog`, `fsck`, `show` y la lectura de cada diff) la
corrimos y verificamos nosotros contra el repo generado por `caso/generar-caso.sh`.

---

## 1. Línea de tiempo de la filtración

| Fecha | Autor | Commit | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| 2026-08-05 | dev-jperez | `0abdf95` | wip pasarela de pagos (en rama `feature/pasarela-pagos`) | **Sí** — `.env.pasarela` con `PAGOS_SECRET` |
| 2026-08-10 | dev-jperez | `de33a75` | inicial: deploy-tool, token por variable de entorno | No (usa env var, bien hecho) |
| 2026-08-10 | dev-jperez | `9333f2b` | hotfix "deploy roto": metió `PHANTOM_API_TOKEN` hardcodeado en `config.py` | **Sí** — token de API en claro |
| 2026-08-12 | dev-jperez | `bc9d0db` | wip notas del cluster; luego `reset --hard` lo saca de `main` | **Sí** — `staging_key` (commit colgado) |
| 2026-08-11 | dev-jperez | `eafb81c` | "sacar credenciales (ups)": borra el token del archivo | No borra la historia: el token sigue en `9333f2b` |
| 2026-08-20 | dev-jperez | `fa714bd` | docs: estado del proyecto | No |

> Nota: el commit de notas (`bc9d0db`, 12-ago) es posterior en el tiempo pero
> quedó fuera de `main` por el `reset --hard`; se recupera por reflog/fsck.

## 2. Hallazgos

### R1 — Secreto en commit viejo → `FLAG{git_log_no_olvida}`
- Comando: `git log -p -- config.py` / `git show eafb81c`
- Salida: el diff del commit de "limpieza" muestra la línea borrada
  `-PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"`. El token entró en el hotfix
  `9333f2b` y se "quitó" en `eafb81c`, pero el diff de limpieza lo expone igual.
- Habilita: acceso a la API de PhantomCorp con el token de producción.

### R2 — Commit "perdido" → `FLAG{git_reflog_rescata}`
- Comando: `git reflog` (aparece `HEAD@{5}: commit: wip: notas del cluster`,
  hash `bc9d0db`) → `git show bc9d0db`. `git fsck --lost-found` lo lista como
  dangling commit.
- Del reflog al contenido: el reflog guarda a dónde apuntó HEAD aunque la rama
  ya no lo referencie; con el hash, `git show`/`git cat-file -p` leen el objeto.
- Secreto: `notas_investigacion.txt` → `staging_key: FLAG{git_reflog_rescata}`.

### R3 — Rama abandonada → `FLAG{git_rama_abandonada}`
- Comando: `git branch -a` (existe `feature/pasarela-pagos`) →
  `git show feature/pasarela-pagos` / `git show 0abdf95`.
- Secreto: `.env.pasarela` → `PAGOS_SECRET=FLAG{git_rama_abandonada}`.

## 3. Evaluación de exposición

Si el repo hubiera sido **público** desde el commit inicial, el primero en caer
sería el **token de API de `config.py`** (R1): los bots de scraping y los
escáneres (GitHub Secret Scanning, Gitleaks sobre forks, TruffleHog) priorizan
patrones de credenciales en archivos de config del árbol principal. Un push
público lo deja indexado en **segundos a minutos**. El `.env.pasarela` de la
rama también es muy visible (patrón `*_SECRET` en `.env`). Las notas del cluster
(commit colgado) son las más difíciles: no están en ninguna rama, hay que
mirar el historial de objetos.

## 4. Plan de remediación (P4)

1. **Revocar y rotar YA** los 3 secretos (token de API, staging_key,
   PAGOS_SECRET) en el proveedor. Es lo único que corta el daño real.
2. **Revocar accesos** derivados y revisar logs de uso del token por si ya se
   explotó.
3. **Avisar a quienes forkearon/clonaron**: su copia conserva la historia.
4. **Reescribir la historia** (`git filter-repo` / BFG) y forzar push — es lo
   **menos urgente**: una vez rotados los secretos, lo que quede en la historia
   ya no sirve. Reescribir sin rotar antes es seguridad de teatro.
5. **Lecciones**: pre-commit hooks + secret scanning en CI; `.env` en
   `.gitignore`; secretos solo por variables de entorno / vault.

## 5. Preguntas P1–P5

- **P1.** El token entró en `9333f2b` (hotfix, 10-ago) y se "sacó" en `eafb81c`
  (11-ago): ~1 día en el árbol de trabajo, pero **expuesto para siempre** en la
  historia. El commit de limpieza **no alcanza**: solo cambia el estado actual,
  no borra el objeto; `git show` del hotfix o del diff de limpieza lo revelan.
- **P2.** `reset --hard` solo mueve la referencia de la rama a otro commit; el
  commit viejo (`bc9d0db`) queda como objeto **colgado** en `.git/objects`,
  referenciado por el reflog hasta que corra el GC (semanas). Lo demuestran
  `git reflog` (ve HEAD@{5}) y `git fsck --lost-found` (lo lista como dangling).
- **P3.** Público: cualquiera clona la rama y lee el `.env` → compromiso
  inmediato del secreto de pagos. Privado con 30 colaboradores: la superficie
  son esas 30 personas (+ sus equipos/máquinas/forks internos); un solo equipo
  o credencial comprometida expone el secreto, y queda en todas las copias.
- **P4.** (desarrollado en §4) Orden: rotar → revocar → avisar forks →
  reescribir historia → prevención. Reescribir es lo menos urgente porque, con
  los secretos ya rotados, la historia filtrada deja de tener valor.
- **P5.** (1) **pre-commit hook** local (gitleaks / detect-secrets) que corre en
  tu máquina y aborta el commit si detecta un secreto. (2) **pre-receive /
  push protection** en el servidor (GitHub Secret Scanning push protection,
  server-side hook) que rechaza el push con secretos antes de aceptarlo.

## 6. Evidencia de progreso

- `evidencia/salidas/ctf-status.txt` → `./ctf status extra2` con los 3 ✓ (3/3, 100%).
- `evidencia/comandos.txt` + `evidencia/salidas/` (log, reflog y `git show` de cada hallazgo).
