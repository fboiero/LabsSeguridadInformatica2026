# Informe — Lab Extra 2: El repo que delata (forense git)

**Grupo:** 02

**Integrantes:**

- Romero Jimena Soledad (legajo 15377) — @Jimena-Romero
- Milanesio Hebe Del Lourdes (legajo 15343) — @hebemilanesio1
- Toranzo Juan Cruz (legajo 15308) — @JuanToranzo
- Torres Damaris (legajo 14563) — @damaris412

**Declaración de uso de IA:** usamos Claude (Anthropic), en la interfaz de chat,
para ayudar a redactar este informe y a ordenar la línea de tiempo a partir de
las salidas reales de git que corrimos nosotros. Toda la investigación se hizo
sobre el repo generado localmente (`caso/repo-delata`, generado por
`caso/generar-caso.sh`, determinista) con comandos `git` nativos; las flags
salen de la salida real de esos comandos. Confirmamos las 3 con
`./ctf status extra2` (3/3). Evidencia cruda en `evidencia/` (`comandos.txt` y
`salidas/`).

---

## 1. Línea de tiempo de la filtración

Reconstruida con `git log --all --date=iso` (ver `evidencia/salidas/timeline.txt`),
`git reflog` y `git fsck`. Autor único de toda la historia:
`dev-jperez <jperez@phantomcorp.example>`.

| Fecha (autor) | Commit | Qué pasó | ¿Expone algo? |
|---|---|---|---|
| 2026-08-05 16:30 | `0abdf95` (rama `feature/pasarela-pagos`) | WIP de la pasarela de pagos; se commitea `.env.pasarela` "que no había que subir" | **Sí** — `PAGOS_SECRET` (R3) |
| 2026-08-10 09:12 | `de33a75` (main) | Nace `deploy-tool`; el token va por variable de entorno (bien) | No |
| 2026-08-10 18:47 | `9333f2b` (main) | "hotfix" de emergencia: se hardcodea el token en `config.py` | **Sí** — `PHANTOM_API_TOKEN` (R1) |
| 2026-08-11 10:05 | `eafb81c` (main) | "fix: sacar credenciales del codigo (ups)": se borra el token de `config.py` **en un commit nuevo** | Aparenta remediar, pero el token sigue en la historia |
| 2026-08-12 14:22 | `bc9d0db` (colgado) | "wip: notas del cluster": se commitea `notas_investigacion.txt` y luego un `reset --hard` lo descarta | **Sí** — `staging_key` (R2), recuperable por reflog/fsck |
| 2026-08-20 11:00 | `fa714bd` (main, HEAD) | "docs: estado del proyecto": README dice "Historia limpia. Sin secretos ✅" | No (pero la afirmación es falsa) |

**Exposición del token de la API (`PHANTOM_API_TOKEN`):** se introdujo el
2026-08-10 18:47 (`9333f2b`) y el commit de "limpieza" fue el 2026-08-11 10:05
(`eafb81c`): unas **~15 horas** entre que entró y que lo "sacaron". Pero eso es
engañoso: **el commit de limpieza NO alcanza**. El token sigue vivo en el commit
`9333f2b`, visible con `git log -p`. La exposición real no se cuenta hasta el
commit de limpieza, sino hasta que el secreto se **rota**: mientras no se rote,
sigue expuesto para cualquiera que tenga el repo (indefinidamente).

## 2. Hallazgos

### R1 — Secreto en commit viejo

- **Comando:** `git log -p -- config.py`
- **Salida relevante** (`evidencia/salidas/r1.txt`):

```
commit 9333f2b... hotfix: deploy roto en produccion (config temporal)
+# Config de emergencia — arreglar el deploy roto YA (despues lo pasamos a env)
+PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"
...
commit eafb81c... fix: sacar credenciales del codigo (ups)
-PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"
```

- **Qué se expuso y qué habilita:** `PHANTOM_API_TOKEN`, el token contra
  `api.phantomcorp.example/v2`. `git log` solo mostraba el *mensaje* ("sacar
  credenciales"); `git log -p` muestra el *diff* y ahí está el token, agregado en
  `9333f2b` y quitado en `eafb81c` — pero presente en la historia para siempre.

**Flag R1:** `FLAG{git_log_no_olvida}`

### R2 — Commit "perdido" por un reset

- **Comandos:** `git reflog`, `git fsck --lost-found`, `git show bc9d0db`
- **Cómo llegué del reflog/fsck al contenido** (`evidencia/salidas/r2_reflog.txt`,
  `r2_fsck.txt`, `r2.txt`):

```
$ git reflog
...
eafb81c HEAD@{4}: reset: moving to HEAD~1
bc9d0db HEAD@{5}: commit: wip: notas del cluster nuevo (no mergear todavia)
...

$ git fsck --lost-found
dangling commit bc9d0dbe6aca41d639a515395cc983e139979102

$ git show bc9d0db
+    staging_key: FLAG{git_reflog_rescata}
```

El `reset --hard HEAD~1` movió la rama, pero el objeto commit `bc9d0db` quedó
**colgado** (dangling): el reflog recuerda que HEAD estuvo ahí y `fsck` lo
encuentra sin referencia. `git show` sobre ese hash revela el archivo
`notas_investigacion.txt` con la llave.

- **Qué se expuso:** `staging_key` del cluster de staging.

**Flag R2:** `FLAG{git_reflog_rescata}`

### R3 — Rama abandonada

- **Comandos:** `git branch -a`, `git ls-tree -r --name-only feature/pasarela-pagos`,
  `git show feature/pasarela-pagos:.env.pasarela`
- **Salida** (`evidencia/salidas/r3.txt`):

```
$ git branch -a
  feature/pasarela-pagos
* main

$ git show feature/pasarela-pagos:.env.pasarela
# NO COMMITEAR ESTO (lo commitee igual, despues lo veo)
PAGOS_SECRET=FLAG{git_rama_abandonada}
PAGOS_ENDPOINT=https://pagos.phantomcorp.example
```

- **Qué se expuso:** `PAGOS_SECRET` de la pasarela de pagos, en un `.env.pasarela`
  que "no había que commitear". No está en `main`, pero `--all` y el nombre de la
  rama lo exponen igual.

**Flag R3:** `FLAG{git_rama_abandonada}`

## 3. Evaluación de exposición

Si el repo hubiera estado **público en GitHub** desde el commit inicial, el
primero en caer sería el **token de la API (R1)**: entró en `9333f2b` directo en
`main`, que es la rama que los bots de escaneo (GitGuardian, TruffleHog, GitHub
Secret Scanning) revisan en **cada push**. El tiempo mediano entre push público y
primer uso de una credencial filtrada se mide en **minutos**, así que el commit
de "limpieza" del día siguiente llegó tardísimo. El `.env.pasarela` (R3) también
sería detectado —los escáneres recorren todas las ramas—, y las notas del reset
(R2) quedarían accesibles por hash en la API de GitHub aunque el `reset` las
sacara de la rama local. Conclusión: los tres cruzaron la línea en el momento del
push; borrarlos después no cambia que ya fueron vistos.

## 4. Plan de remediación (P4)

En orden:

1. **Rotar los tres secretos YA** (token de la API, staging_key del cluster,
   PAGOS_SECRET). Es lo único que corta el acceso real: si el secreto ya no vale,
   no importa quién tenga una copia del commit. Es lo *más* urgente.
2. **Revocar accesos / revisar logs** por si las credenciales ya se usaron entre
   la filtración y la rotación.
3. **Contactar a quienes forkearon/clonaron** y pedir que eliminen sus copias; en
   un repo con colaboradores, avisar que la historia va a reescribirse.
4. **Reescribir la historia** (`git filter-repo` / BFG) + force-push para sacar
   los secretos de los commits. Esto es lo *menos* urgente **no porque no
   importe**, sino porque no protege lo ya filtrado: quien clonó, forkeó o un bot
   que indexó, ya tiene el secreto. Reescribir solo evita *futuras* exposiciones;
   sin rotar, es cosmético.
5. **Lecciones aprendidas / prevención** (ver P5).

## 5. Preguntas P1–P5

**P1 — Línea de tiempo del token (ver §1).** El token entró el 2026-08-10 18:47
(`9333f2b`) y el commit de limpieza fue el 2026-08-11 10:05 (`eafb81c`), ~15 h
después. **No alcanza con el commit de limpieza:** `git log -p -- config.py`
sigue mostrando el token en `9333f2b`. La historia es append-only; borrar en un
commit nuevo no borra el commit viejo. La exposición real dura hasta la rotación.

**P2 — Por qué el `reset --hard` no funcionó.** En el modelo de objetos de git,
un commit es un objeto inmutable guardado por su hash; las ramas y `HEAD` son solo
*referencias* (etiquetas movibles). `reset --hard HEAD~1` **mueve la referencia**,
no borra el objeto: el commit `bc9d0db` queda sin que ninguna rama lo apunte, pero
sigue en el object store (git lo conserva ~90 días). Dos comandos que lo
demuestran: **`git reflog`** (recuerda que HEAD estuvo en `bc9d0db` antes del
reset) y **`git fsck --lost-found`** (lo lista como `dangling commit`).

**P3 — Riesgo de la rama abandonada.** Si el repo fuera **público**: cualquiera
—incluidos los bots— ve `feature/pasarela-pagos` con `git branch -a` o
`--all`, y el `PAGOS_SECRET` queda tan expuesto como si estuviera en `main`
("no está en main" no es un control de acceso). Si fuera **privado con 30
colaboradores**: los 30 pueden leer la rama y clonarla a sus máquinas, se
multiplican las copias locales fuera de control, y basta que una de esas máquinas
se comprometa —o que un colaborador se vaya enojado— para que el secreto se
filtre. Más gente con acceso = mayor superficie, aunque sea "privado".

**P4 — Ver §4.** Rotación primero; reescritura de historia al final, porque no
remedia lo ya expuesto.

**P5 — Dos mecanismos de prevención.**
1. **Pre-commit hook (corre en tu máquina, antes del commit):** una herramienta
   como *gitleaks* o *git-secrets* integrada con `pre-commit` escanea el diff y
   **bloquea el commit** si detecta un patrón de secreto (API keys, tokens,
   `.env`). Atrapa el secreto antes de que entre a la historia local.
2. **Escaneo server-side (corre en el servidor, al hacer push):** GitHub Secret
   Scanning / push protection, o un hook del lado del servidor, que **rechaza el
   push** si trae secretos. Es la red de contención por si el hook local no estaba
   instalado. Complemento obvio: un `.gitignore` con `.env*` para que esos
   archivos no se stageen por error.

## 6. Evidencia de progreso

```
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB extra2                   │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Secreto "borrado" en un commit viejo (git log -p)
   ✓  R2     Commit "perdido" por un reset (git reflog / fsck)
   ✓  R3     Secreto en una rama abandonada

  ██████████████████████████████  3/3 (100%)

[ OK ] ¡Lab extra2 COMPLETO! Ponete las pilas con la próxima unidad.
```

Adjuntos: `evidencia/comandos.txt` (todos los comandos en orden) y
`evidencia/salidas/` (salidas crudas de R1, R2, R3, reflog, fsck y timeline).
