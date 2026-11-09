# Entregable — Lab Extra 2: El repo que delata

**Grupo:** 10 · **Integrantes:** Ramello, Belén Rocío — @belramello · Corazza, Carolina Paula — @carocor1 · Kordek, Chiara Agustina — @chiarakordek · Saby, Juan Pablo — @JuanSaby

**Declaración de uso de IA:** se utilizó ChatGPT (mediante OpenCode) para asistir en la ejecución del generador de caso, comandos de terminal y redacción preliminar de las secciones R1 y P1. Se utilizó Claude para asistir en la estructuración, redacción y revisión técnica de las secciones del informe.  
*Método de verificación:* todo el contenido generado con asistencia de IA fue contrastado estrictamente contra las evidencias reales del caso. Las salidas de comandos y diffs se obtuvieron mediante ejecución efectiva en terminal y fueron redirigidas directamente a `evidencia/salidas/` sin edición manual. Las tres flags fueron validadas contra el verificador oficial `./ctf submit extra2` (registrando el progreso del 100% en `evidencia/salidas/estado-despues.txt`). Los hashes de commit, autores y timestamps se cotejaron con el grafo real de Git (`git log --all --graph`, `git reflog`, `git fsck`), y las justificaciones sobre el modelo de objetos y remediación fueron verificadas contra la documentación oficial de Git y GitHub Docs. 

---

## 1. Línea de tiempo de la filtración

Tabla cronológica de todos los eventos relevantes de la historia de `caso/repo-delata`, incluidos los commits legítimos (son el contexto en el que ocurren los otros). Las fechas y horas son las de autoría/commit registradas por git (`git log --all --format='%H|%an|%ad|%s' --date=iso`); todas usan huso `-03:00`. El orden de la tabla sigue la relación padre-hijo real de cada commit (el grafo), no un simple orden numérico de fechas — ver la nota al final, porque un commit de esta historia tiene timestamp anterior al de su propio padre.

| Fecha y hora | Autor | Commit (hash corto) | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| 10/08/2026 09:12 | dev-jperez | `de33a75` | Commit inicial: "deploy-tool con token por variable de entorno". Establece la base de `main`. | No. |
| 10/08/2026 18:47 | dev-jperez | `9333f2b` | "hotfix: deploy roto en produccion (config temporal)". Agrega a `config.py`, hardcodeado, `PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"`, con el comentario `# Config de emergencia — arreglar el deploy roto YA (después lo pasamos a env)`. | **Sí — R1.** Token en texto plano en `config.py`. |
| 11/08/2026 10:05 | dev-jperez | `eafb81c` | "fix: sacar credenciales del codigo (ups)". Reemplaza `config.py` en la copia de trabajo de `main`: quita la línea del token y el comentario. No borra el commit `9333f2b`, que sigue siendo parte de la historia. | Indirectamente: "cierra" la exposición en el árbol de trabajo actual, pero no en el historial (ver R1 e investigación en la sección 2). |
| 12/08/2026 14:22 | dev-jperez | `bc9d0db` (commit) seguido de `reset: moving to HEAD~1` sobre `main`, mismo timestamp | "wip: notas del cluster nuevo (no mergear todavia)". Agrega `notas_investigacion.txt` con `staging_key: FLAG{git_reflog_rescata}`. El propio reflog muestra que, en el mismo minuto, `main` se reseteó a `HEAD~1` (es decir, a `eafb81c`), dejando a `bc9d0db` sin ninguna rama que lo señale. | **Sí — R2.** El autor creyó haberlo "borrado" con el reset; el objeto sigue íntegro en el repositorio, solo que inalcanzable salvo por reflog/fsck. |
| 20/08/2026 11:00 | dev-jperez | `fa714bd` | "docs: estado del proyecto". Último commit de `main`, posterior al reset. No toca archivos con secretos. | No. |

**Rama separada — `feature/pasarela-pagos` (sigue existiendo, nunca se fusionó ni se borró):**

| Fecha y hora | Autor | Commit (hash corto) | Qué pasó | ¿Expone algo? |
|---|---|---|---|---|
| 05/08/2026 16:30 | dev-jperez | `0abdf95` | "wip: pasarela de pagos (falta todo)". Hijo directo de `9333f2b` en la rama `feature/pasarela-pagos` (confirmado con `git log feature/pasarela-pagos --oneline` y `git log --all --graph`). Agrega `.env.pasarela` con `PAGOS_SECRET=FLAG{git_rama_abandonada}` y `PAGOS_ENDPOINT=https://pagos.phantomcorp.example`, con el comentario `# NO COMMITEAR ESTO (lo commitee igual, despues lo veo)`. | **Sí — R3.** Secreto de pasarela de pagos en una rama que `git branch -a` todavía lista hoy. |

### Nota de precisión sobre las fechas

El commit `0abdf95` (R3) tiene fecha de autoría **05/08/2026 16:30**, anterior a la de su propio padre `9333f2b` (**10/08/2026 18:47**). Esto es posible porque la fecha de un commit la define el reloj de quien lo crea, no el orden del grafo: git garantiza la relación padre-hijo (la cadena de hashes), no que las fechas sean crecientes. Por eso esta tabla ordena los eventos de `main` por su relación causal real, confirmada con `git log --all --graph`, y trata la fecha de `0abdf95` como un dato a reportar con cautela, no como prueba de que ese commit haya ocurrido antes que los demás. No se puede deducir del repositorio por qué el reloj de ese commit está desalineado; solo se documenta la discrepancia.

### Cuánto tiempo estuvo expuesto cada secreto

- **R1 (`PHANTOM_API_TOKEN`, `9333f2b`):** en el árbol de trabajo actual de `main`, estuvo expuesto **15 horas y 18 minutos** (de `9333f2b` a `eafb81c`, ver P1 en la sección 5). En el historial, sigue expuesto desde su creación hasta hoy: `eafb81c` no eliminó el commit `9333f2b`, que `git log -p` sigue devolviendo. No hay evidencia en el caso de que el token se haya rotado.
- **R2 (`staging_key`, `bc9d0db`):** nunca estuvo señalado por una rama después del `reset` del mismo minuto (`12/08/2026 14:22`), pero el objeto existe en el repositorio de forma continua desde ese instante hasta hoy, recuperable por cualquiera con acceso al repo mediante `reflog` o `fsck --unreachable`. Por defecto, git conserva estos objetos "colgados" durante aproximadamente 90 días antes de que una recolección de basura (`git gc`) pueda liberarlos.
- **R3 (`PAGOS_SECRET`, `0abdf95`):** expuesto de forma continua desde su creación hasta hoy, sin fecha de cierre, porque la rama `feature/pasarela-pagos` nunca se fusionó ni se eliminó (sigue en `git branch -a`). A diferencia de R1 y R2, acá no hay ni siquiera un intento fallido de "limpieza": es la exposición con la ventana más larga y menos acotada de las tres.

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
- **Salida relevante:** extracto de [`evidencia/salidas/r1.txt`](evidencia/salidas/r1.txt); el archivo adjunto contiene la salida completa, redirigida directamente por Bash:
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
  ```bash
  git log --oneline --all
  git reflog
  git fsck --unreachable --no-reflogs
  git show bc9d0db
  ```
- **¿Cómo llegaste del reflog/fsck al contenido del objeto?** `git log --oneline --all` solo mostró 5 commits, sin rastro de ningún `reset`. `git reflog` reveló el movimiento real de `HEAD`: en `HEAD@{5}` hay un commit `bc9d0db` ("wip: notas del cluster nuevo (no mergear todavia)"), y en `HEAD@{4}` un `reset: moving to HEAD~1` que lo dejó sin ninguna rama apuntándolo. Para confirmar que el objeto seguía existiendo sin depender del reflog, corrí `git fsck --unreachable --no-reflogs`, que listó `bc9d0db` como *unreachable commit* (junto con su árbol y su blob). Con el hash en mano, `git show bc9d0db` mostró el diff completo de ese commit.
- **Salida relevante:** extracto de [`evidencia/salidas/r2.txt`](evidencia/salidas/r2.txt); la salida cruda redirigida del commit recuperado:
  ```diff
  commit bc9d0dbe6aca41d639a515395cc983e139979102
  Author: dev-jperez <jperez@phantomcorp.example>
  Date:   Wed Aug 12 14:22:00 2026 -0300

      wip: notas del cluster nuevo (no mergear todavia)

  diff --git a/notas_investigacion.txt b/notas_investigacion.txt
  new file mode 100644
  index 0000000..fc979fd
  --- /dev/null
  +++ b/notas_investigacion.txt
  @@ -0,0 +1,7 @@
  +NOTAS — pruebas de acceso al cluster nuevo (NO SUBIR)
  +====================================================
  +El equipo de infra me paso la llave del cluster de staging para probar:
  +
  +    staging_key: FLAG{git_reflog_rescata}
  +
  +Cuando este todo migrado esto se rota y estas notas se borran.
  ```
- **Qué secreto se expuso:** el commit agrega `notas_investigacion.txt` con el texto `staging_key: FLAG{git_reflog_rescata}`, descrito como la llave de acceso a un cluster de staging que el equipo de infra había pasado "para probar". El propio archivo aclara que la intención era rotarla y borrar las notas una vez migrado todo; el `reset --hard` reemplazó esa intención, pero el objeto siguió existiendo en el repositorio.

### R3 — Rama abandonada
- **Comando(s) exacto(s):**
  ```bash
  git branch -a
  git show feature/pasarela-pagos
  ```
- **Salida relevante:** extracto de [`evidencia/salidas/r3.txt`](evidencia/salidas/r3.txt); la salida cruda redirigida obtenida al inspeccionar el commit de la rama con `git show feature/pasarela-pagos`:
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
- **Qué secreto se expuso:** en la rama `feature/pasarela-pagos`, el commit `0abdf95` ("wip: pasarela de pagos (falta todo)") añade `pasarela.py` y `.env.pasarela`. En este último archivo se expone la variable `PAGOS_SECRET=FLAG{git_rama_abandonada}` junto con el endpoint `PAGOS_ENDPOINT=https://pagos.phantomcorp.example`. El propio archivo incluye el comentario `"NO COMMITEAR ESTO (lo commitee igual, despues lo veo)"`, evidenciando que el secreto fue subido deliberadamente a una rama de trabajo secundaria y luego quedó olvidado al continuar el desarrollo en `main`, manteniéndose accesible para cualquiera que clone el repositorio.

## 3. Evaluación de exposición

Si este repositorio hubiera estado **público en GitHub** desde el commit inicial, el primer secreto que habría sido encontrado por un bot es **R1** (`PHANTOM_API_TOKEN = "FLAG{git_log_no_olvida}"`).

### Justificación técnica y hechos del caso

1. **Rama de destino y eventos de push:** R1 fue commiteado directamente sobre la rama principal `main` en el commit `hotfix: deploy roto en produccion (config temporal)`. En GitHub y plataformas similares, las ramas por defecto son el blanco prioritario de los sistemas de escaneo y generan de forma inmediata eventos públicos en la API (`PushEvent`).
2. **Ventana temporal en HEAD:** De acuerdo con la cronología real del caso, el commit del hotfix se realizó el `2026-08-10 18:47:00 -03:00` y el commit que intentó retirarlo ("ups") no ocurrió hasta el `2026-08-11 10:05:00 -03:00`. El secreto estuvo expuesto en la punta visible (`HEAD`) de `main` durante **15 horas y 18 minutos**, un lapso masivo frente a los tiempos de respuesta de escáneres automatizados.
3. **Formato y visibilidad del secreto:** La variable fue definida explícitamente como `PHANTOM_API_TOKEN` en un archivo de configuración estándar (`config.py`), lo que activa de inmediato las firmas de expresiones regulares y entropía que utilizan los scanners de secretos (tanto defensivos como atacantes).

### Comparación de condiciones de exposición (R1 vs. R2 vs. R3)

- **R1 (Commit en `main`):** Máxima exposición. Forma parte del historial lineal de la rama principal. Cualquier clon estándar lo descarga y cualquier escáner conectado al feed de eventos de GitHub lo procesa de manera inmediata.
- **R2 (Commit descartado por `reset --hard`):** El commit `bc9d0db` que contenía `staging_key: FLAG{git_reflog_rescata}` fue revertido localmente con `git reset --hard HEAD~1` inmediatamente después de crearse. Si no se hizo push entre el commit y el reset, el objeto jamás subió al servidor remoto. Incluso si hubiera subido antes del reset y luego se hubiera forzado la actualización, en GitHub quedaría como un commit huérfano (accesible vía API o eventos históricos si se conoce el hash exacto), pero no en el recorrido estándar de ramas.
- **R3 (Rama secundaria `feature/pasarela-pagos`):** El secreto `PAGOS_SECRET` reside en una rama secundaria que quedó abandonada. Aunque un `git clone` descarga todas las referencias remotas, su visibilidad pública depende de si el desarrollador ejecutó `git push origin feature/pasarela-pagos` (o `git push --all`). Además, muchos bots simples priorizan la rama por defecto y procesan ramas secundarias con menor frecuencia o sólo bajo clonado completo.

### Estimación razonada de tiempo de detección y limitaciones

- **Hecho comprobado del caso:** Los eventos de push en repositorios públicos quedan registrados y expuestos en la API de GitHub al instante.
- **Estimación razonada de la industria:** Basado en reportes de seguridad del sector (como los informes anuales *State of Secrets Sprawl* de GitGuardian e investigaciones de Truffle Security), los bots automatizados detectan credenciales y API keys en commits públicos en una mediana de **menos de 5 minutos** (frecuentemente entre 30 segundos y 2 minutos tras el push), y los primeros intentos de abuso automatizado suelen ocurrir en menos de 10 a 30 minutos.
- **Limitaciones de la hipótesis:** Esta estimación es un cálculo razonado basado en el comportamiento empírico reportado por la industria y no una garantía fija: el tiempo exacto de detección varía según la tasa de eventos de GitHub, el patrón del secreto (si encaja con firmas de proveedores conocidos como AWS/Stripe o es un token genérico/corporativo) y la arquitectura de sondeo de cada bot en particular.

## 4. Plan de remediación (respondiendo P4)

1. **Contener el acceso:** revocar de inmediato cada credencial expuesta y emitir reemplazos nuevos. La rotación va primero porque invalida el valor comprometido sin depender de que el historial o sus copias desaparezcan.
2. **Investigar el posible uso:** revisar los registros del proveedor y de los sistemas afectados desde la primera exposición hasta la revocación; buscar accesos, cambios o consumos anómalos. Revocar sesiones y permisos asociados que ya no sean necesarios, y reducir el alcance de las credenciales nuevas.
3. **Coordinar las copias:** avisar a quienes mantienen forks o clones y pedir que detengan los pushes basados en la historia antigua. Acordar cómo actualizarse para no volver a publicar los commits originales.
4. **Limpiar el historial compartido:** en un clon nuevo y coordinando al equipo, usar `git-filter-repo` para quitar el archivo o reemplazar el valor filtrado en todas las referencias afectadas. Revisar ramas, etiquetas y resultados antes de actualizar el remoto; la reescritura cambia hashes y puede afectar pull requests ([GitHub Docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository); [git-filter-repo](https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt)).
5. **Verificar y prevenir:** volver a buscar el valor en el historial y las referencias remotas, gestionar con GitHub la eliminación de referencias cuando corresponda, y agregar controles pre-commit y al hacer push. Registrar el incidente y sus medidas correctivas.

La reescritura queda después de revocar porque solo modifica el historial que controla el equipo. En el Ejemplo B de la consigna, los clones y forks ya conservaban la versión antigua; un force-push no puede retirar esas copias ni volver inocua una clave activa. `git-filter-repo` también recomienda rotar o revocar antes de purgar el historial ([documentación de git-filter-repo](https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt)).

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

### P3 — Riesgos de la rama abandonada (público vs. privado)

La existencia de una rama abandonada con credenciales (`feature/pasarela-pagos`) plantea riesgos graves, pero con vectores y alcances diferenciados según la visibilidad del repositorio:

#### 1. Repositorio Público

- **Mecanismo de exposición en Git:** Cuando un repositorio es público, un clon habitual (`git clone <url>`) descarga los objetos alcanzables desde las referencias anunciadas por el servidor, incluyendo las ramas disponibles (`refs/remotes/origin/*`). Por lo tanto, no es necesario que una rama esté fusionada con `main` para que su contenido quede disponible en el clon. Los objetos inalcanzables que no estén referenciados no se descargan necesariamente mediante un clon estándar. Cualquier usuario tiene acceso local inmediato al contenido mediante `git checkout feature/pasarela-pagos` o inspeccionando directamente el commit con `git show origin/feature/pasarela-pagos`. En la interfaz web de plataformas como GitHub o GitLab, la rama permanece visible en la pestaña de ramas y es accesible vía API REST/GraphQL.
- **Alcance del acceso y actores de amenaza:** Acceso irrestricto y anónimo a nivel mundial. Escáneres automatizados (bots tanto de servicios de seguridad como de cibercriminales) barren continuamente las ramas expuestas.
- **Riesgo concreto:** Filtración inmediata de `PAGOS_SECRET` y del endpoint `https://pagos.phantomcorp.example`. Al tratarse de una credencial de pasarela de pagos, un atacante externo puede interceptar o falsificar transacciones financieras, desviar pagos, sustraer fondos o comprometer la identidad comercial de PhantomCorp, con impacto económico directo y sanciones regulatorias.

#### 2. Repositorio Privado con 30 Colaboradores

- **Mecanismo de exposición y modelo de permisos:** Git maneja los permisos de lectura de forma monolítica a nivel de repositorio. Si un colaborador cuenta con permiso de clonado/lectura (`read/clone`), tiene acceso a **todos los objetos, commits y ramas** del repositorio. No existen permisos de lectura granulares por rama en Git estándar: las restricciones de rama (Branch Protection Rules) regulan la escritura (*push* o merge), pero no ocultan ramas a quienes ya pueden clonar el repo.
- **Alcance del acceso:** La historia completa, incluyendo la rama abandonada, reside replicada en al menos 30 estaciones de trabajo distintas de desarrolladores, testers o contratistas.
- **Riesgos concretos:**
  1. **Violación del principio de menor privilegio:** Los 30 integrantes de la organización acceden a credenciales críticas de pagos, aun cuando su función no guarde relación con el procesamiento financiero (por ejemplo, diseñadores frontend o pasantes).
  2. **Ampliación sustancial de la superficie de ataque (Blast Radius):** La seguridad del secreto depende de la postura defensiva del eslabón más débil de los 30 colaboradores. Si una sola laptop es sustraída, infectada por malware o carece de cifrado de disco y backups seguros, la credencial queda comprometida.
  3. **Riesgo de persistencia post-desvinculación (Offboarding deficiente):** Cuando un colaborador abandona la empresa, conserva los clones locales en sus equipos. Como las ramas secundarias rara vez se auditan formalmente, la existencia de este secreto suele pasar desapercibida y nunca se rota, permitiendo que ex-empleados mantengan acceso latente.
  4. **Reactivación o merge accidental:** Al no haber sido eliminada, cualquier desarrollador puede hacer un checkout inadvertido de la rama, rebasarla sobre `main` o incluirla en un Pull Request, propagando el secreto a entornos de producción o pipelines de integración continua.

### P4 — Orden de remediación

El orden y la justificación están desarrollados en la sección 4: primero se revocan/rotan los secretos comprometidos; después se investigan accesos y se ajustan permisos, se coordina la limpieza con quienes tienen clones o forks y, al final, se reescribe y verifica la historia. Cambiar el historial no invalida una credencial ni elimina las copias que ya salieron del repositorio ([GitHub Docs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository); [git-filter-repo](https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt)).

### P5 — Prevención de nuevos secretos

1. **Hook pre-commit local:** configurar Gitleaks para revisar los cambios preparados antes de aceptar el commit. Así se da aviso en la computadora del desarrollador antes de crear la entrada del historial. El equipo debe instalar y mantener el hook en cada entorno, ya que es un control local que puede omitirse ([Gitleaks](https://github.com/gitleaks/gitleaks)).
2. **Protección al hacer push:** habilitar GitHub Push Protection para que el servidor bloquee pushes con credenciales compatibles. Revisar y resolver cada bloqueo, sin autorizar el bypass por rutina; la cobertura depende de los patrones admitidos ([GitHub Docs](https://docs.github.com/en/code-security/concepts/secret-security/push-protection)).

Los dos controles se complementan: el hook detecta antes del commit y el servidor aplica una barrera común cuando el cambio sale del equipo. Ninguno reemplaza la rotación si una credencial ya se filtró.

## 6. Evidencia de progreso

Las tres flags fueron aceptadas por el motor oficial. R2 se validó durante el trabajo de Belén sobre el hallazgo; R1 y R3 se validaron al cerrar el informe, una vez integrado el trabajo de Carolina y de Juan. Salida real de `./ctf status extra2`, después de entregar las tres:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB extra2                   │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Secreto "borrado" en un commit viejo (git log -p)
   ✓  R2     Commit "perdido" por un reset (git reflog / fsck)
   ✓  R3     Secreto en una rama abandonada

  ██████████████████████████████  3/3 (100%)

[ OK ] ¡Lab extra2 COMPLETO! Ponete las pilas con la próxima unidad.
```

El estado anterior (`1/3`, solo R2) y las entregas de R1 y R3 están en `evidencia/salidas/estado-antes.txt`, `ctf-submit-R1.txt`, `ctf-submit-R3.txt` y `estado-despues.txt`.

Todos los comandos ejecutados por el grupo están consolidados, en orden y separados por integrante, en [`evidencia/comandos.txt`](evidencia/comandos.txt). Las salidas crudas de cada hallazgo están en `evidencia/salidas/`.
