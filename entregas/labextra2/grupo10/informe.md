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
- **Comando(s) exacto(s):**
  ```bash
  git branch -a
  git show feature/pasarela-pagos
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

Ordená y justificá: rotación de secretos, reescritura de historia, contacto a
quienes forkearon/clonaron, revocación de accesos, lecciones aprendidas.

## 5. Preguntas P1–P5

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

## 6. Evidencia de progreso

- Captura de `./ctf status extra2` con los 3 ✓.
- Confirmá que adjuntaste `evidencia/comandos.txt` y `evidencia/salidas/`
  (ver README § Reporte y evidencia).
