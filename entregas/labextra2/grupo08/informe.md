# Informe — Lab Extra 2: El repo que delata (forense git)

**Grupo:** 08 · **Integrantes:** ver [`INTEGRANTES.md`](INTEGRANTES.md)

| Parte | Responsable | Alcance |
|---|---|---|
| Parte 1 | Leone, Lucas — @LucasLeone | Caso, R1, R2, línea de tiempo (main + reflog), P1, P2 |
| Parte 2 | Moyano, Joaquin — @Joaco919 | R3, línea de tiempo (rama), §3, §4, P3–P5, research |

**Declaración de uso de IA:**
- *Parte 1:* se usó Claude Code (Anthropic) como asistente para ejecutar los
  comandos git sobre el caso generado localmente, ordenar la salida y redactar
  el borrador. Todas las salidas pegadas son reales y están en
  `evidencia/salidas/`; fueron revisadas y validadas por el integrante
  responsable. No se consultó ninguna solución docente.
- *Parte 2:* (completa Joaquin)

---

## 1. Línea de tiempo de la filtración

Todas las fechas en UTC-3. Autor único en toda la historia:
`dev-jperez <jperez@phantomcorp.example>`. Fuentes: `git log --all`,
`git reflog --date=iso` y `git fsck` (ver `salidas/r1.txt` y `r2.txt`).

| Fecha | Autor | Commit (hash corto) | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| 2026-08-10 09:12 | dev-jperez | `de33a75` | Commit inicial: `app.py` lee `PHANTOM_API_TOKEN` de variable de entorno; README dice "el token va por variable de entorno". | No — diseño correcto. |
| 2026-08-10 18:47 | dev-jperez | `9333f2b` | "hotfix: deploy roto en produccion (config temporal)": crea `config.py` con el token hardcodeado y `DEBUG = True`. | **Sí — R1:** `PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"`. |
| 2026-08-11 10:05 | dev-jperez | `eafb81c` | "fix: sacar credenciales del codigo (ups)": borra la línea del token y pone `DEBUG = False`. | No en el árbol nuevo, pero el token **sigue en `9333f2b`**. |
| 2026-08-12 14:22 | dev-jperez | `bc9d0db` | "wip: notas del cluster nuevo (no mergear todavia)": agrega `notas_investigacion.txt` con la llave del cluster de staging. | **Sí — R2:** `staging_key: FLAG{git_reflog_rescata}`. |
| 2026-08-12 14:22 | dev-jperez | (reflog) `eafb81c` | `reset: moving to HEAD~1` — `main` vuelve a `eafb81c`; `bc9d0db` queda colgado (dangling). | El objeto **no se borra**: sigue en reflog y object store. |
| *(Parte 2)* | | `0abdf95` | *Rama `feature/pasarela-pagos` — completa Joaquin.* | |
| 2026-08-20 11:00 | dev-jperez | `fa714bd` | "docs: estado del proyecto": README declara "Historia limpia. Sin secretos. ✅". | No — pero la afirmación es falsa. |

**Ventanas de exposición:**

- **Token API (R1):** estuvo en la punta de `main` desde 2026-08-10 18:47
  hasta 2026-08-11 10:05 → **15 h 18 min** visible en el árbol de trabajo.
  En la *historia* sigue expuesto **hasta hoy** (`9333f2b` es ancestro de
  `main`): cualquiera que clone el repo lo tiene.
- **Llave staging (R2):** referenciada por `main` solo unos instantes
  (commit y reset en el mismo minuto, 14:22). Como objeto colgado sigue
  recuperable mientras viva el reflog (~90 días por defecto,
  `gc.reflogExpireUnreachable` = 30 días para commits inalcanzables) y hasta
  que corra un `git gc --prune`. Si el commit llegó a pushearse, el remoto
  también lo tiene.

> Anomalía a notar: las entradas del reflog de la rama (`checkout` a
> `feature/pasarela-pagos` y commit `0abdf95`) tienen fecha **2026-08-05**,
> pero aparecen *después* del reset del 08-12. Las fechas del reflog vienen
> del committer date, que es manipulable: el orden del reflog es más
> confiable que la fecha. Lo profundiza la Parte 2.

## 2. Hallazgos

### R1 — Secreto en commit viejo

- **Comando(s) exacto(s):**

  ```bash
  git log --oneline --all
  git log --format='%h | %an <%ae> | %ad | %s' --date=iso main
  git log -p --reverse main
  ```

- **Salida relevante (diff):**

  ```diff
  commit 9333f2b4a09f7a320cb66d621c3bd53b4f694941
  Author: dev-jperez <jperez@phantomcorp.example>
  Date:   Mon Aug 10 18:47:00 2026 -0300

      hotfix: deploy roto en produccion (config temporal)

  --- /dev/null
  +++ b/config.py
  @@ -0,0 +1,4 @@
  +# Config de emergencia — arreglar el deploy roto YA (después lo pasamos a env)
  +PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"
  +REGION = "us-east-1"
  +DEBUG = True

  commit eafb81c3ec5790ce4741629458e11ab5c1a690b8
  Date:   Tue Aug 11 10:05:00 2026 -0300

      fix: sacar credenciales del codigo (ups)

  -# Config de emergencia — arreglar el deploy roto YA (después lo pasamos a env)
  -PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"
  +# Config — sin secretos, por fin
   REGION = "us-east-1"
  -DEBUG = True
  +DEBUG = False
  ```

  Salida completa: `evidencia/salidas/r1.txt`.

- **Qué secreto se expuso y qué habilita:** el `PHANTOM_API_TOKEN` de la API
  de producción (`https://api.phantomcorp.example/v2`, región `us-east-1`).
  Es el mismo token que `app.py` usa para hacer deploys: quien lo tenga
  puede **desplegar código arbitrario en la intranet de PhantomCorp** (y
  cualquier otra acción que permita la API v2). El commit "de limpieza"
  borra la línea del árbol, pero el diff del commit de limpieza **muestra
  el secreto otra vez** en la línea `-`: el propio fix lo re-publica.

- **Flag:** `FLAG{git_log_no_olvida}` ✓

### R2 — Commit "perdido"

- **Comando(s) exacto(s):**

  ```bash
  git reflog --date=iso
  git fsck --lost-found
  git fsck --unreachable --no-reflogs
  git cat-file -t bc9d0db
  git cat-file -p bc9d0db
  git show bc9d0db
  ```

- **¿Cómo llegaste del reflog/fsck al contenido del objeto?**

  1. `git reflog` muestra que HEAD estuvo en un commit que no aparece en
     `git log --all`:

     ```
     eafb81c HEAD@{2026-08-12 14:22:00 -0300}: reset: moving to HEAD~1
     bc9d0db HEAD@{2026-08-12 14:22:00 -0300}: commit: wip: notas del cluster nuevo (no mergear todavia)
     ```

  2. `git fsck` lo confirma por otro camino independiente del reflog:
     `--lost-found` lo reporta como `dangling commit bc9d0dbe…`, y
     `--unreachable --no-reflogs` muestra la cadena completa de objetos
     huérfanos: el **commit** `bc9d0db` → su **tree** `65ec201` → el
     **blob** `fc979fd`.
  3. `git cat-file -t bc9d0db` → `commit`; `git cat-file -p bc9d0db` da su
     tree y su padre (`eafb81c`, o sea, se hizo sobre el "fix").
  4. `git show bc9d0db` muestra el diff: un archivo nuevo
     `notas_investigacion.txt` (blob `fc979fd`).

  ```
  +NOTAS — pruebas de acceso al cluster nuevo (NO SUBIR)
  +====================================================
  +El equipo de infra me paso la llave del cluster de staging para probar:
  +
  +    staging_key: FLAG{git_reflog_rescata}
  +
  +Cuando este todo migrado esto se rota y estas notas se borran.
  ```

  Salida completa: `evidencia/salidas/r2.txt`.

- **Qué secreto se expuso:** la llave de acceso al **cluster de staging
  nuevo**, entregada por infra "para probar". La propia nota admite que *no
  fue rotada* ("cuando este todo migrado esto se rota"), así que hay que
  asumirla vigente.

- **Flag:** `FLAG{git_reflog_rescata}` ✓

### R3 — Rama abandonada

> **Parte 2 — completa Joaquin.**

- Comando(s) exacto(s):
- Qué secreto se expuso:

## 3. Evaluación de exposición

> **Parte 2 — completa Joaquin.**

## 4. Plan de remediación (respondiendo P4)

> **Parte 2 — completa Joaquin.**

## 5. Preguntas P1–P5

### P1 — Línea de tiempo del token de la API

| Evento | Commit | Autor | Fecha | Mensaje |
|---|---|---|---|---|
| Introducción | `9333f2b` | dev-jperez | 2026-08-10 18:47 | hotfix: deploy roto en produccion (config temporal) |
| "Remoción" | `eafb81c` | dev-jperez | 2026-08-11 10:05 | fix: sacar credenciales del codigo (ups) |

- **Tiempo expuesto en la punta de `main`:** 15 h 18 min (de 18:47 del
  10/08 a 10:05 del 11/08).
- **Tiempo expuesto en la historia:** indefinido — desde el 10/08 hasta hoy,
  y lo seguirá estando mientras `9333f2b` sea alcanzable desde alguna
  referencia (es ancestro de `main`, así que siempre).

**¿Alcanza con el commit de limpieza? No.** Un commit nuevo no modifica los
anteriores: crea un *tree* nuevo sin la línea, pero `9333f2b` y su blob de
`config.py` (`04e01ad`) siguen en el object store y son alcanzables desde
`main`. Cualquiera con `git log -p` lo ve en segundos, y peor: el diff del
propio commit de limpieza **reimprime el token en la línea eliminada**.
Además, cualquier clone, fork, caché de CI o bot que haya visto el repo
durante esas 15 h ya tiene una copia que el dev no controla. El único
remedio real es **rotar el token** (revocarlo en la API y emitir uno nuevo
que vaya por `PHANTOM_API_TOKEN` del entorno, como estaba en `de33a75`);
reescribir la historia viene después y solo evita exposiciones *futuras*.

### P2 — Por qué el `reset --hard` no borró las notas

Git es una base de datos de objetos **append-only** direccionada por
contenido (SHA-1). Un commit es un objeto inmutable que apunta a un tree
(que apunta a blobs) y a su padre. Las ramas y `HEAD` son solo
**referencias**: archivos de texto con un hash adentro.

`git reset --hard HEAD~1` hizo exactamente esto:

1. Movió la referencia `refs/heads/main` de `bc9d0db` a `eafb81c`.
2. Actualizó el índice y el working tree para que coincidan con `eafb81c`
   (por eso el archivo "desapareció" del disco).

**No tocó el object store.** Los objetos `bc9d0db` (commit), `65ec201`
(tree) y `fc979fd` (blob con la llave) siguen en `.git/objects/`; solo
dejaron de ser alcanzables desde una rama. Además, git registró el
movimiento en el **reflog** (`.git/logs/HEAD`), que conserva las entradas
inalcanzables 30 días y las alcanzables 90 por defecto. Los objetos solo se
eliminan físicamente cuando expira el reflog **y** corre `git gc --prune`.

**Dos comandos que lo demuestran:**

1. `git reflog` — muestra `bc9d0db … commit: wip: notas del cluster nuevo`
   seguido de `reset: moving to HEAD~1`: HEAD recuerda dónde estuvo.
2. `git fsck --lost-found` (o `--unreachable`) — sin depender del reflog,
   recorre el object store y reporta `dangling commit bc9d0db…`.

Y con `git show bc9d0db` (o `git cat-file -p fc979fd`) se lee el contenido
completo. Bonus: `git branch rescate bc9d0db` lo vuelve a hacer alcanzable.

### P3 — Riesgo de la rama abandonada

> **Parte 2 — completa Joaquin.**

### P4 — Plan de remediación

> **Parte 2 — completa Joaquin** (ver §4).

### P5 — Prevención

> **Parte 2 — completa Joaquin.**

## 6. Evidencia de progreso

- Estado tras la Parte 1 (2/3) — `evidencia/ctf-status-parte1.txt`:

  ```
   ✓  R1     Secreto "borrado" en un commit viejo (git log -p)
   ✓  R2     Commit "perdido" por un reset (git reflog / fsck)
   ·  R3     Secreto en una rama abandonada

  ████████████████████░░░░░░░░░░  2/3 (66%)
  ```

- Captura final con 3/3: *(Parte 2 — Joaquin)*.
- Evidencia adjunta:
  - [x] `evidencia/comandos.txt` (tramo Parte 1)
  - [x] `evidencia/salidas/r1.txt`
  - [x] `evidencia/salidas/r2.txt`
  - [ ] `evidencia/salidas/r3.txt` *(Parte 2)*
