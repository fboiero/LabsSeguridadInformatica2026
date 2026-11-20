# Informe técnico — Desafío PTaaS · Grupo 10

**Práctico Final, variante capstone** · Seguridad Informática 2026 · UTN FRVM

| Integrante | Turno | Aporte principal |
|---|---|---|
| Carolina Paula Corazza | 1 | Preparación del kit, red team del guard, mutación, reporting defensivo |
| Chiara Agustina Kordek | 2 | Bitácora sin datos sensibles, controles de `asset-discovery`, requisitos nuevos |
| Juan Pablo Saby | 3 | Change `004-recon-loop-a`: adaptadores, loop A, corrida en el lab, selección de herramientas |
| Belén Rocío Ramello | 4 | Integración de resultados, informe técnico y retrospectiva |

---

## 0. Declaración de uso de IA

Se utilizó Claude, a través de Claude Code, como asistente. Se usó para redactar un primer borrador de este informe a partir de los commits, las revisiones de seguridad y la evidencia ya registrada en el repositorio por los turnos 1 a 3. El grupo revisó el borrador y contrastó cada dato con los archivos de origen (openspec/reviews/, openspec/changes/guard-turno-1/tasks.md y evidencia/ptaas/). La retrospectiva y las conclusiones las escribió el grupo. Los demás integrantes utilizaron ChatGpt y Gemini. 
## 1. Resumen

Partimos del kit de la cátedra (`labs/labfinal-practico-integrador/ptaas-kit`, base
`a1abb79`), lo copiamos a `entregas/labfinal/grupo10/ptaas-kit/` y lo extendimos en
tres turnos de trabajo. El resultado es un núcleo determinista endurecido, con un
**loop agéntico funcionando (loop A, reconocimiento)** que corrió contra el
laboratorio aislado y dejó una bitácora verificable.

| Indicador | Valor |
|---|---|
| Tests (`python -m pytest -q`) | **113 pasan** (el kit original traía 77) |
| Evals golden (`evals/run_evals.py --mode golden`) | **10/10** |
| Scenarios en `openspec/specs/` | **57** en 11 capabilities (el kit traía 54) |
| `tools/progress.py` | código de salida 0 |
| Change `004-recon-loop-a` | 14/15 tasks (falta archivar deltas al mergear) |
| Loop A contra el lab | `grafo estabilizado` en 2 iteraciones, `audit_verify=OK` |

El foco no fue romper sino **diseñar el control**: que ninguna acción ocurra fuera de
`Harness.invoke`, sin token de alcance vivo o sin quedar en la bitácora.

Además, Carolina desarrolló una aplicación ejecutable más amplia en
[`ptaas-app/`](ptaas-app/README.md): panel local "Relevo", bitácora SQLite (change 002),
RoE y tokens (003), catálogo de verificaciones contra Juice Shop y gate de informe. Su
documentación propia, con el informe técnico de esa parte, está en `ptaas-app/docs/`.

---

## 2. Arquitectura

```
 Agentes de runtime (prompts/ + harness/models.yaml)
        │  proponen acciones como JSON con schema
        ▼
 Harness.invoke(token, capability, target, params)
        │
        ├─► Guard ── ¿token vivo? ¿fase autorizada? ¿target en alcance?
        │      │ no → BLOCKED en bitácora, el adaptador nunca se llama
        │      ▼ sí
        ├─► Adaptador tipado (argv fijo, shell=False, timeout, RateLimiter)
        │      │
        │      ▼
        └─► AuditLog (hash encadenado; guarda sha256 de la evidencia, no el contenido)

 Loops: decide_recon (A) · decide_detection (B) · decide_validation (C)
 Gates humanos: PENDING_HITL antes de validar y antes de entregar
```

- **Determinismo donde importa.** El Scope Guard, el token, la bitácora y los gates son
  código Python, no decisiones de un modelo. Los agentes solo proponen.
- **Adaptadores como única puerta a las herramientas.** Cada uno fija su `argv`, valida
  el target y rechaza metacaracteres y argumentos prohibidos (`harness/profiles.yaml`).
- **Bitácora íntegra y sin datos sensibles.** Cada registro encadena el hash del anterior
  y guarda una referencia `sha256:` de la evidencia (turno 2). `AuditLog.verify_chain()`
  detecta alteraciones (turno 3).

### Loop A (reconocimiento)

`harness/loop_a.py` orquesta `subfinder.enum` (pasivo) y después `httpx.probe` (activo),
siempre a través de `Harness.invoke`:

1. `ordered_recon` / `passive_before_active` fuerzan el orden pasivo → activo.
2. Cada host descubierto se normaliza y se evalúa contra el alcance. Lo que queda fuera
   va a `AssetGraph.out_of_scope` con un evento `BLOCKED` y **nunca** se sondea.
3. `dedupe_assets` evita re-sondear activos repetidos.
4. Cada iteración guarda un `GraphSnapshot` con su digest. Si el grafo no cambia,
   `decide_recon` detiene el loop por "grafo estabilizado"; si no, por tope.

---

## 3. Qué se hizo, por turno

### Turno 1 — Endurecer el guard (Caro)

- Copia del kit a la carpeta del grupo e instalación verificada (77 tests, evals 10/10).
- Laboratorio levantado con Docker (DVWA, Juice Shop y `runner`) en una red interna sin
  puertos publicados (`10.253.219.0/28`, verificada como `internal`).
- **Red team del guard:** cinco tests adversariales del bloque A de
  `docs/desafios-extension.md` en `tests/authorization/test_guard_boundaries.py`.
  Cada rechazo exige `BLOCKED` en la bitácora y cero llamadas al adaptador.
- Reporting defensivo (change `009`): informe de Bandit con revisión humana y
  exportación a DefectDojo bloqueada sin aprobación ligada al SHA-256 del informe.

### Turno 2 — Bitácora y descubrimiento de activos (Chiara)

- La bitácora pasa a guardar una **referencia** de la evidencia (`sha256`) en vez del
  contenido: cubre el Scenario de `audit-log` "sin datos sensibles", que el enunciado
  marcaba como faltante.
- `asset-discovery`: `RateLimiter` (5 rps por target, desde `policy.yaml`), orden
  pasivo → activo y deduplicación de activos, cada uno con su test.
- Tres Requirements nuevos, cada uno con su Scenario negativo y su test.
- Revisión de seguridad registrada en `openspec/reviews/20261119-chiara-turno2.md`.

### Turno 3 — Change 004, loop A (Juan)

- `design.md` y deltas de `asset-discovery` y `tool-adapters`.
- Adaptadores `subfinder_adapter.py` y `httpx_adapter.py` con `argv` fijo, rate limit y
  manejo de errores tipado (`AdapterOutputError`, `ToolExecutionError`,
  `RateLimitExceeded`).
- `AssetGraph`, versionado por digest y orquestación con `decide_recon`.
- Corrida real desde el contenedor `runner` contra `dvwa.lab.test` y
  `juiceshop.lab.test`, más una corrida reproducible con fixtures.
- Selección de herramientas justificada (`ptaas-kit/docs/tool-selection.md`) y revisión
  de seguridad en `openspec/reviews/20261120-juan-turno3.md`, que además cablea los
  controles que el turno 2 había dejado sin conectar.

### Turno 4 — Integración e informe (Belén)

- Verificación conjunta de la rama: tests, evals y `progress.py`.
- Este informe y la retrospectiva.

---

## 4. Resultados

### Corrida del loop A contra el laboratorio

Evidencia en `entregas/labfinal/grupo10/evidencia/ptaas/`.

| Campo | Valor |
|---|---|
| Engagement | `eng-labfinal-grupo10`, fase `recon` |
| Orden de capabilities | `subfinder.enum` → `httpx.probe` |
| Motivo de parada | `grafo estabilizado` |
| Iteraciones | 2 (la segunda sin activos nuevos; mismo digest) |
| Activos | `dvwa.lab.test` (Apache/2.4.25 Debian) y `juiceshop.lab.test` |
| Fuera de alcance | ninguno en esta corrida |
| Bitácora | 4 entradas, `audit_verify=OK` |

La corrida con fixtures (`evidencia/ptaas/fixture/`) sí incluye descubrimientos fuera de
alcance, y los tests verifican que se bloquean sin llegar al adaptador
(`cdn.tercero.org`, `evil-dvwa.lab.test`).

### Red team del guard

| Caso | Idea probada | Resultado antes | Acción |
|---|---|---|---|
| A1 | Hostname con mayúsculas y punto final | Se normaliza y se decide igual | Test agregado |
| A2 | El dominio no es un sufijo arbitrario | Bloqueado | Test agregado |
| A3 | IPv6 fuera del prefijo autorizado | Bloqueado | Test agregado |
| A6 | Token reutilizado en otra fase | Bloqueado | Test agregado |
| A9 | Nombre con espacio interno en una etiqueta | **Aceptado (bypass)** | Corregido en `harness/contracts.py` + delta `guard-turno-1` |

**Mutación manual.** Se reemplazó `Guard.is_allowed` por una función que devolvía
`True`. Fallaron A2, A3 y A9, o sea que esos tests detectan la rotura del guard. A1 y
A6 siguieron pasando: no dependen solo de `is_allowed`, así que no alcanzan para
probarlo solos.

### Revisiones de seguridad

| Turno | Hallazgo | Severidad | Estado |
|---|---|---|---|
| 2 | Rate limit, orden y dedupe existían y tenían test, pero no estaban cableados en el adaptador ni en el loop | Baja | Cerrado en el turno 3 |
| 2 | La referencia `sha256` de la evidencia es verificable pero no confidencial: con evidencia de baja entropía podría revertirse | Info | Aclarado en el docstring |
| 2 | Una capability desconocida se trata como activa | Info | Correcto (fail-safe) |
| 3 | Sin caminos que eviten `Harness.invoke`, sin `shell=True`, todo resultado en bitácora | — | Sin hallazgos |

---

## 5. Decisiones de diseño

1. **Orden pasivo → activo obligatorio.** Reduce el tráfico hacia el objetivo y asegura
   que el alcance se evalúe antes de cualquier sondeo activo.
2. **Runner stdlib como respaldo.** La imagen `python:3.12-slim` del `runner` no trae los
   binarios de `subfinder` ni `httpx`. El adaptador conserva el `argv` del binario oficial
   y suma un runner HTTP de la biblioteca estándar sin redirecciones automáticas, más un
   modo fixture reproducible.
3. **Nuclei solo con templates curados** y sin OAST (`-ni`), para que no haya tráfico
   saliente fuera del laboratorio.
4. **Exportación fail-closed.** DefectDojo no recibe nada si falta la aprobación humana o
   si el hash del informe no coincide con el aprobado.
5. **Herramientas descartadas:** masscan (AGPL y tasa agresiva) y Nikto (ruido alto frente
   a ZAP baseline + Nuclei curado). El detalle está en `tool-selection.md`.

---

## 6. Riesgos y limitaciones

- **Resolución DNS (A4) no probada.** Un hostname autorizado que resuelve a una IP fuera
  de alcance no se vuelve a validar después de resolverlo.
- **Bitácora en memoria en el kit.** `audit verify` comprueba la cadena de cada corrida,
  pero la persistencia SQLite del change `002` no está integrada en esta carpeta.
- **Referencia `sha256` no es cifrado** (hallazgo H2 del turno 2).
- **Herramientas reales parciales.** El loop A usó el runner stdlib dentro del lab; ZAP y
  Nuclei no tienen corrida archivada en esta carpeta.
- **Versión de Python.** El CI del kit usa 3.12. Las dos carpetas se verificaron en un
  contenedor `python:3.12-slim`: `ptaas-kit/` con 113 tests y evals 10/10, y `ptaas-app/`
  con 183 tests, evals 21/21 y la demo de defensa. `ptaas-app/` no corre en 3.10
  porque usa `typing.Self`.

---

## 7. Retrospectiva del trabajo con IA

La guía del kit pide al menos tres casos en que la IA se equivocó y cómo se detectó.
Los tres son del turno 4 y quedaron registrados en la historia de la rama.

| # | Qué propuso la IA | Cómo lo detectamos | Qué se corrigió |
|---|---|---|---|
| 1 | En la tabla del red team describió A1 como "mayúsculas, punto final **o espacios**" y A3 como "IPv6 **e IPv4 mapeada a IPv6**". Copió las ideas de `desafios-extension.md` en vez de lo que prueban nuestros tests. | Contrastamos la tabla con los nombres de los tests en `tests/authorization/test_guard_boundaries.py` (`test_a1_dns_case_and_root_dot`, `test_a3_ipv6_outside_authorized_prefix`). | Se reescribieron las filas A1 a A3 según lo que verifica cada test. |
| 2 | En "Cómo reproducir" propuso `python tools/run_loop_a.py --mode fixture` sin `--output`. | Leímos `tools/run_loop_a.py`: sin `--output`, escribe en `evidencia/ptaas/` y pisa la evidencia de la corrida real contra el lab. | Se agregó `--output` a un directorio temporal y una advertencia en el informe. |
| 3 | Para dejar la rama al día propuso mergear el `main` del fork, como dice el paso 3 del `CONTRIBUTING.md`. Ese `main` estaba divergido de `upstream/main` y el merge dio un conflicto en `labs/labfinal-practico-integrador/start.sh`. | El conflicto apareció en un archivo de `labs/`, que el grupo nunca modifica. Comparamos `main` con `upstream/main` y vimos que le faltaban commits de la cátedra. | Se abortó el merge y se mergeó `upstream/main` directo, sin conflictos. |

**Qué funcionó:** trabajar spec → test que falla → código; los tests adversariales y la
mutación manual mostraron qué tests detectaban roturas reales. Simular en local las
reglas del CI de la cátedra antes de pushear detectó que la aplicación estaba en
`entregas/final/grupo10/`, una ruta que el CI rechaza; se movió a `ptaas-app/`.

**Qué no funcionó:** el orden de los turnos cambió durante el día y quedaron dos
carpetas de PTaaS con alcances distintos (`ptaas-kit/` y `ptaas-app/`), con
documentación que se superpone. Además, la máquina del turno 4 solo tenía Python 3.10:
hubo que usar Docker para verificar con la 3.12 del CI.

---

## 8. Trabajo futuro

- Changes `002`, `003` y `005` a `007` completos dentro del kit (`progress.py` los muestra
  en 0 %).
- Validar de nuevo los hosts después de resolver DNS (A4) y probar A5, A7, A8 y A10.
- Sandbox efímero real que implemente `Sender` (loop C) y corridas de ZAP y Nuclei.
- Evals en vivo (`--mode live`) y ampliar los casos a 20 o más.
- Archivar los deltas de `004` en `openspec/specs/` al cerrar el PR.

---

## 9. Cómo reproducir

Desde `entregas/labfinal/grupo10/ptaas-kit/`:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python evals/run_evals.py --mode golden
python tools/progress.py
python tools/run_loop_a.py --mode fixture --output /tmp/loop-a-prueba
```

Sin `--output`, el script escribe en `evidencia/ptaas/` y pisa la evidencia archivada.

La corrida contra el laboratorio se hace dentro del contenedor `runner`:

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml exec runner bash
```
