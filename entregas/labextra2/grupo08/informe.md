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
- *Parte 2:* se usó Claude Code (Anthropic) como asistente para ejecutar los
  comandos de inspección forense en git, volcar las evidencias crudas y redactar
  el análisis de exposición, plan de remediación y research. Todas las salidas y
  evidencias adjuntas fueron reproducidas localmente sobre el caso y revisadas
  críticamente por el integrante responsable. No se consultó ninguna solución docente.

---

## 1. Línea de tiempo de la filtración

Todas las fechas en UTC-3. Autor único en toda la historia:
`dev-jperez <jperez@phantomcorp.example>`. Fuentes: `git log --all`,
`git reflog --date=iso` y `git fsck` (ver `salidas/r1.txt`, `r2.txt` y `r3.txt`).

| Fecha | Autor | Commit (hash corto) | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| 2026-08-10 09:12 | dev-jperez | `de33a75` | Commit inicial: `app.py` lee `PHANTOM_API_TOKEN` de variable de entorno; README dice "el token va por variable de entorno". | No — diseño correcto. |
| 2026-08-10 18:47 | dev-jperez | `9333f2b` | "hotfix: deploy roto en produccion (config temporal)": crea `config.py` con el token hardcodeado y `DEBUG = True`. | **Sí — R1:** `PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"`. |
| 2026-08-11 10:05 | dev-jperez | `eafb81c` | "fix: sacar credenciales del codigo (ups)": borra la línea del token y pone `DEBUG = False`. | No en el árbol nuevo, pero el token **sigue en `9333f2b`**. |
| 2026-08-12 14:22 | dev-jperez | `bc9d0db` | "wip: notas del cluster nuevo (no mergear todavia)": agrega `notas_investigacion.txt` con la llave del cluster de staging. | **Sí — R2:** `staging_key: FLAG{git_reflog_rescata}`. |
| 2026-08-12 14:22 | dev-jperez | (reflog) `eafb81c` | `reset: moving to HEAD~1` — `main` vuelve a `eafb81c`; `bc9d0db` queda colgado (dangling). | El objeto **no se borra**: sigue en reflog y object store. |
| 2026-08-05 16:30 | dev-jperez | `0abdf95` | "wip: pasarela de pagos (falta todo)": en rama `feature/pasarela-pagos` (bifurcada de `9333f2b`), crea `.env.pasarela` y `pasarela.py`. | **Sí — R3:** `PAGOS_SECRET=FLAG{git_rama_abandonada}`. Además arrastra `config.py` con el token de R1. |
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
  también lo tiene accesible en GitHub por SHA directo.
- **Secret de pasarela de pagos (R3):** introducido en `0abdf95` sobre la
  rama `feature/pasarela-pagos`. La rama nunca fue mergeada a `main` ni
  eliminada. Al estar presente en el repositorio, cualquier clon o consulta
  remota (`git branch -a`, web UI, API) la expone de forma directa y permanente.
  Sigue expuesto **hasta hoy** (exposición indefinida). Adicionalmente, al haberse
  creado a partir de `9333f2b` (previo al commit `eafb81c`), la rama mantiene
  en su propio working tree la versión vulnerable de `config.py` con el token
  de producción de R1 intacto.

> **Análisis forense de la anomalía temporal en el reflog:**
> En el reflog (`salidas/r2.txt`), se observa una aparente paradoja: las
> operaciones de checkout hacia `feature/pasarela-pagos` y el commit `0abdf95`
> muestran fecha `2026-08-05 16:30`, pero aparecen listadas *después*
> (arriba en la pila) del reset del `2026-08-12 14:22`.
> En Git, el reflog registra eventos de manera estrictamente secuencial y
> append-only: el orden de aparición refleja la cronología real de ejecución en la
> máquina. Por el contrario, los timestamps mostrados por `--date=iso` se
> obtienen de `GIT_AUTHOR_DATE` y `GIT_COMMITTER_DATE`, variables de entorno que
> cualquier usuario puede adulterar. Esto demuestra con rigor pericial que el dev
> creó la rama de pagos y commiteó el `.env` **después del reset del 12 de agosto**
> (y antes del commit de docs del 20 de agosto), intentando falsear o
> retrofechar el trabajo ("backdating"). En una pericia forense, el orden secuencial
> del reflog prevalece sobre los metadatos de fecha del commit.

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

- **Comando(s) exacto(s):**

  ```bash
  git branch -a
  git log --all --graph --decorate --oneline
  git log -p -1 feature/pasarela-pagos
  git ls-tree -r feature/pasarela-pagos
  git show feature/pasarela-pagos:.env.pasarela
  ```

- **Salida relevante (diff):**

  ```diff
  commit 0abdf953b75b214af59d0cf31e55ccbf2c9873d8
  Author: dev-jperez <jperez@phantomcorp.example>
  Date:   Wed Aug 5 16:30:00 2026 -0300

      wip: pasarela de pagos (falta todo)

  diff --git a/.env.pasarela b/.env.pasarela
  new file mode 100644
  index 0000000..4431615
  --- /dev/null
  +++ b/.env.pasarela
  @@ -0,0 +1,3 @@
  +# NO COMMITEAR ESTO (lo commitee igual, despues lo veo)
  +PAGOS_SECRET=FLAG{git_rama_abandonada}
  +PAGOS_ENDPOINT=https://pagos.phantomcorp.example
  diff --git a/pasarela.py b/pasarela.py
  new file mode 100644
  index 0000000..2da76b4
  --- /dev/null
  +++ b/pasarela.py
  @@ -0,0 +1 @@
  +"""Integracion con la pasarela de pagos (WIP, quedo a mitad de camino)."""
  ```

  Salida completa: `evidencia/salidas/r3.txt`.

- **Qué secreto se expuso y qué habilita:** la credencial de producción
  `PAGOS_SECRET` (`FLAG{git_rama_abandonada}`) y la URL base del servicio
  financiero `https://pagos.phantomcorp.example`. Quien posea esta clave puede
  **interactuar con la API de procesamiento de pagos, autorizar transacciones,
  solicitar reintegros fraudulentos, extraer balances contables o emitir webhooks
  firmados falsos**, comprometiendo la recaudación y el flujo monetario de
  PhantomCorp.
  Además, al inspeccionar el árbol con `git ls-tree -r feature/pasarela-pagos`,
  se descubrió un agravante crítico: la rama fue bifurcada desde `9333f2b`
  (el hotfix vulnerable) y no desde `main` limpio, por lo que **conserva el
  archivo `config.py` con el `PHANTOM_API_TOKEN` (R1)** en su propio estado.

- **Flag:** `FLAG{git_rama_abandonada}` ✓

## 3. Evaluación de exposición

Si este repositorio hubiera sido publicado como **público en GitHub** desde el
commit inicial:

1. **¿Cuál de los 3 secretos habría sido encontrado primero por un bot?**
   El secreto **R1 (`PHANTOM_API_TOKEN = FLAG{git_log_no_olvida}`)**.
   
   **Razones técnicas:**
   - **Flujo de ingestión de los bots:** Los escáneres automatizados (TruffleHog,
     GitGuardian, Shhgit y bots de adversarios) consumen en tiempo real la
     API de eventos públicos de GitHub (`/events`, específicamente eventos de tipo
     `PushEvent`). Estos analizadores priorizan de forma inmediata los pushes
     realizados sobre la rama por defecto (`main`/`master`).
   - **Visibilidad y nombre de archivo:** El token de R1 ingresó en el commit
     `9333f2b` directamente sobre `main` en un archivo estándar de configuración
     (`config.py`) con nombres de variables de altísima entropía y coincidencia
     de diccionario (`API_TOKEN`, `DEBUG = True`).
   - **Comparación con R2 y R3:**
     - **R2 (`staging_key`):** Fue commiteado y reseteado localmente mediante
       `git reset --hard HEAD~1`. Si el desarrollador ejecutó el reset antes de
       hacer `git push`, el commit `bc9d0db` **jamás subió al remoto**; solo
       existía en su disco local. Incluso si hubiera hecho push y force-push,
       el commit quedaría huérfano (dangling en GitHub), requiriendo conocer el
       SHA exacto o raspar eventos antiguos, lo cual no es el vector primario de
       los bots de scraping masivo.
     - **R3 (`PAGOS_SECRET`):** Aunque el archivo `.env.pasarela` tiene un nombre
       altamente sospechoso que dispara alertas inmediatas, está en una rama
       secundaria (`feature/pasarela-pagos`). Si bien muchos bots barren todas
       las ramas al detectarse un push de refs (`CreateEvent`/`PushEvent`),
       `main` siempre se indexa primero y con prioridad cero.

2. **¿Cuánto tiempo estimás que tardaría?**
   Entre **1 y 3 minutos** (en promedio menos de 120 segundos).
   Estudios académicos de la Universidad Estatal de Carolina del Norte (NCSU)
   y reportes de seguridad en la nube (Datadog, Palo Alto Unit 42) documentan
   que los escáneres maliciosos prueban credenciales de AWS o APIs corporativas
   en menos de dos minutos tras aparecer en el feed público de eventos de GitHub.
   Cualquier intento manual de remediación posterior a los 5 minutos ya llega
   tarde frente a la exfiltración automatizada.

## 4. Plan de remediación (respondiendo P4)

PhantomCorp publicó el repo y ya existen forks externos. Reescribir la historia
con `git filter-repo` **no sirve como primera respuesta** porque los atacantes,
los bots de indexación y los forks ya tienen copias inmutables de los commits
viejos en servidores que PhantomCorp no controla.

El plan debe ejecutarse de forma estricta en el siguiente **orden de prioridad**:

```
[Min 0–15]      FASE 1: Rotación y Revocación Inmediata de Secretos (Parar la hemorragia)
                    │
[Min 15–60]     FASE 2: Auditoría Forense y Contención de Daños en Infraestructura
                    │
[Hora 1–4]      FASE 3: Contención del Entorno GitHub y Red de Forks
                    │
[Hora 4–8]      FASE 4: Saneamiento del Repositorio (Reescritura de Historia)
                    │
[Día 1–7]       FASE 5: Controles Preventivos en el Ciclo de Desarrollo (SDLC)
```

### Fase 1: Rotación y Revocación Inmediata de Secretos (Prioridad Máxima)
1. **Revocar `PHANTOM_API_TOKEN` (R1):** Dar de baja el token en la consola de
   identidad / API gateway v2 de PhantomCorp. Generar una credencial nueva y
   cargarla en el gestor de secretos de producción (ej. AWS Secrets Manager,
   Vault) para inyectarla únicamente como variable de entorno.
2. **Rotar `staging_key` (R2):** Revocar certificados y tokens de acceso al
   cluster nuevo de staging. Regenerar kubeconfigs o claves SSH de acceso al
   plano de control.
3. **Revocar `PAGOS_SECRET` (R3):** En el portal de la pasarela de pagos
   (`pagos.phantomcorp.example`), invalidar el secret compartido, regenerar el
   secreto de firma de webhooks y rotar las API keys del comercio.

### Fase 2: Auditoría Forense y Contención
1. Revisar los logs de acceso de la API v2, del cluster de staging y de la
   pasarela desde el 10 de agosto hasta el momento exacto de la revocación.
2. Buscar llamadas anómalas, IPs desconocidas, transacciones no autorizadas o
   deploys de contenedores ajenos.
3. Si se constata uso indebido, congelar temporalmente las cuentas afectadas y
   activar el protocolo de respuesta a incidentes.

### Fase 3: Gestión de la Exposición en GitHub y Forks
1. Solicitar formalmente a GitHub Support el **purgado de cachés de commits**
   huérfanos del repositorio. (GitHub conserva los objetos dangling accesibles
   por hash directo en la interfaz web hasta que se ejecuta un garbage collection
   manual por parte del soporte).
2. Solicitar a GitHub la remoción de la red de forks públicos que contienen los
   secretos, amparándose en los términos de servicio sobre filtración de
   credenciales o mediante un aviso formal de remoción.

### Fase 4: Saneamiento de la Historia del Repositorio
1. Utilizar `git-filter-repo` (la herramienta oficial recomendada por Git) para
   purgar de raíz en todas las ramas y tags:
   - Los archivos `.env.pasarela` y `notas_investigacion.txt`.
   - La cadena `PHANTOM_API_TOKEN = "..."` dentro de `config.py`.
2. Eliminar en el remoto la rama abandonada:
   `git push origin --delete feature/pasarela-pagos`.
3. Forzar el push de la historia reescrita: `git push --force-with-lease --all`.
4. Notificar a los colaboradores internos que borren sus clones locales y
   vuelvan a clonar de cero (`git clone`) para evitar que un push inadvertido
   vuelva a reintroducir los objetos viejos.

> **¿Por qué reescribir la historia es la parte MENOS urgente?**
> Porque reescribir la historia solo protege contra quien clone el repositorio
> en el **futuro**. Si alguien ya lo clonó, lo forkeó o un bot lo leyó hace 10
> minutos, ya tiene los secretos en su poder. Perder horas preparando un comando
> de `git-filter-repo` mientras las claves siguen activas en producción deja la
> puerta abierta para que el atacante vacíe las cuentas bancarias o despliegue
> malware. La rotación invalida el acceso del atacante al instante; la limpieza
> de git es mera higiene cosmética posterior.

---

## 5. Preguntas P1–P5

### P1 — Línea de tiempo del token de la API

*(Completada en la Parte 1 — Lucas Leone; ver arriba).*

### P2 — Por qué el `reset --hard` no borró las notas

*(Completada en la Parte 1 — Lucas Leone; ver arriba).*

### P3 — Riesgo de la rama abandonada

1. **Si el repo fuera público:**
   Cualquier persona en Internet (incluyendo scripts de scraping ofensivo)
   puede ver todas las ramas del proyecto simplemente ejecutando `git clone` o
   mirando el selector de branches en GitHub. La rama `feature/pasarela-pagos`
   contiene un `.env` con credenciales reales para operar la pasarela financiera.
   Peor aún: al estar desatendida, nadie la audita ni actualiza, por lo que las
   claves pueden permanecer vigentes durante años sin que nadie recuerde que
   fueron expuestas.
2. **Si el repo fuera privado con 30 colaboradores:**
   Constituye una violación flagrante del **principio de menor privilegio**. No
   todos los 30 desarrolladores necesitan acceso a las claves de procesamiento
   de pagos de la empresa (un desarrollador frontend o un pasante no deberían
   conocer el secreto financiero). Al subirlo a una rama compartida, el secreto
   queda clonado en 30 laptops corporativas distintas, multiplicando por 30 la
   superficie de ataque (si roban una notebook, si una máquina se infecta con
   un infostealer o si un empleado renuncia con una copia del repo, la pasarela
   queda comprometida).

### P4 — Plan de remediación

*(Desarrollado exhaustivamente en la Sección 4; el resumen clave es: **Rotar
primero en los sistemas receptores, auditar logs inmediatamente y solo al final
limpiar la historia de git**, puesto que la reescritura no recupera lo que ya fue
copiado).*

### P5 — Prevención

Dos mecanismos técnicos concretos que habrían evitado el ingreso de estos
secretos:

1. **Lado Cliente (antes del commit): Pre-commit hooks con Gitleaks / Talisman.**
   Se instala un hook local en `.git/hooks/pre-commit` (o gestionado mediante el
   framework `pre-commit`). Cada vez que el desarrollador ejecuta `git commit`,
   el hook corre una herramienta de escaneo estático (como **Gitleaks**) sobre
   los archivos en el staging area (`git diff --staged`). Gitleaks detecta
   mediante expresiones regulares y cálculo de entropía de Shannon la presencia
   de claves de alto secreto o nombres de archivo prohibidos (como `.env*`). Si
   detecta una coincidencia, aborta el commit con código de salida distinto de cero
   antes de que el objeto commit sea creado en el object store de Git.
2. **Lado Servidor (al hacer push): GitHub Secret Scanning Push Protection / Pre-receive Hook.**
   En el servidor remoto (GitHub Enterprise o GitLab), se activa la funcionalidad
   de **Push Protection** (o un hook de tipo `pre-receive` en servidores git
   autohospedados). Cuando el dev corre `git push`, el servidor intercepta el
   paquete de objetos antes de actualizar las referencias (`refs/heads/*`). Si
   identifica un patrón de credencial o token soportado, **bloquea el push
   completamente** y devuelve un mensaje de rechazo (HTTP 403 / push rejected).
   A diferencia del hook local (que un desarrollador descuidado podría saltarse
   con `git commit --no-verify`), el control del servidor es una política
   obligatoria e invulnerable a la elusión por parte del cliente.

---

## 6. Evidencia de progreso

- Captura final con 3/3 (`evidencia/ctf-status-final.txt`):

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

- Evidencia adjunta:
  - [x] `evidencia/comandos.txt` (tramo Parte 1 y Parte 2)
  - [x] `evidencia/salidas/r1.txt`
  - [x] `evidencia/salidas/r2.txt`
  - [x] `evidencia/salidas/r3.txt`
  - [x] `evidencia/ctf-status-final.txt`
