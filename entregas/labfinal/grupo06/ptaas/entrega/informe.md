# Informe técnico — PTaaS · Grupo 06

**Práctico final, variante PTaaS.** Laboratorio: DVWA y Juice Shop del kit, en red
Docker interna sin salida. Fecha de integración: 19/11/2026. Integró: P5, a partir de
la evidencia del repositorio y de los textos de cada integrante; las secciones de P1 y
P2 se transcriben sin cambios.

## 0. Declaración de uso de IA

### P1
*Declaración original de P1 (11/11). El change 002 se completó después: ver §9.*

**Herramienta:** Claude Code, modelo Haiku 5.5.

**Finalidad y partes asistidas (bitácora y auditoría):**

- Borrador de la firma del contrato de bitácora (`harness/audit.py`), del test que la cubre (`tests/test_audit_persistence.py`) y de la ayuda para corregir un orden de imports con ruff.
- Borrador de `openspec/changes/002-audit-persistence/design.md` y del delta `specs/audit-log/spec.md`.
- Redacción de la nota de traspaso `handoffs/2026-11-11_p1-a-todos_contrato-audit.md`.

**Verificación humana y comprobaciones realizadas:**

- Corrida de la línea base del kit: `pytest -q` (77 passed), `evals/run_evals.py --mode golden` (10/10) y `tools/progress.py`. Salidas crudas en `entrega/evidencia/salidas/arranque-p1.txt`.
- `pytest` del contrato nuevo (5 passed), `mypy --strict harness/audit.py` (sin errores) y `ruff check` (limpio tras corregir imports).

**Límites de la verificación:**

- Las pruebas se corrieron con Python 3.14; el kit y el CI apuntan a Python 3.12. No se probó en 3.12.
- No se levantó el laboratorio `lab/` (Docker): no hay evidencia de funcionamiento contra DVWA ni Juice Shop.
- El diseño y el delta todavía no fueron revisados por otro integrante (tarea 1.3 abierta).
- Los requisitos de `design.md` (triggers, ancla, concurrencia) son decisiones propuestas; no están implementadas ni probadas en SQLite todavía.

### P2

**Herramientas utilizadas:** opencode con DeepSeek V4.1 Flash en la
implementación inicial y GPT-6 Luna en la revisión posterior.

**Finalidad y partes asistidas (autorización y red team):**

- Asistencia en el parser de RoE, la emisión de tokens, los controles del Guard,
  los tests adversariales y la revisión de selección de herramientas.

**Verificación humana y comprobaciones realizadas:**

- Corrida de `pytest` (162 passed), `evals/run_evals.py --mode golden` (10/10),
  `tools/progress.py`, `ruff` y el chequeo focal de `mypy`. Salidas crudas en
  `entrega/evidencia/salidas/`.
- Registro de los errores detectados y sus correcciones en `ia-errores.md` y
  `entrega/retrospectiva.md`.

**Límites de la verificación:**

- Las pruebas se corrieron con Python 3.13; el kit y el CI apuntan a Python 3.12.
  No se probó en 3.12 ni se ejecutaron escaneos contra DVWA o Juice Shop.

### P3

**Herramienta:** Codex, basado en GPT-6.

**Finalidad y partes asistidas (relevamiento y apoyo al informe):**

- Asistencia en la redacción de specs, implementación y corrección del loop A,
  los adaptadores subfinder/httpx y la persistencia del grafo de activos.
- Elaboración de tests y fixtures, apoyo en la ejecución del laboratorio y en la
  documentación de evidencias; validación de CVSS v4/EPSS y estructura PTES para
  las tareas 007 · 2.3–2.4.

**Verificación humana y comprobaciones realizadas:**

- P3 ejecutó la comprobación local de tests, evals, progreso y auditoría; P2
  revisó y aceptó el trabajo del change 004.
- Al cierre de P3 (13/11): 251 tests aprobados, 10/10 evals golden y auditoría
  correcta. Estos valores corresponden a esa etapa, no a la integración final.
  Referencias: `openspec/changes/004-recon-loop-a/archive.md` y
  `entrega/evidencia/salidas/P3-real-04/`.
- Los errores detectados y sus correcciones se registran en `ia-errores.md`
  y `entrega/retrospectiva.md`.

**Límites de la verificación:**

- Subfinder se ejecutó realmente, pero quedó `UNAVAILABLE` al no disponer de
  fuentes locales: no descubrió subdominios. httpx sondeó las semillas autorizadas
  de DVWA y Juice Shop dentro de la red aislada.
- El procesamiento de subdominios, las exclusiones y la enumeración exitosa vacía
  se comprobaron con fixtures simulados, identificados como tales.
- La auditoría de P3 verificó el snapshot exportado mediante el verificador de P1;
  esa comprobación no demuestra resistencia a una reescritura completa sin ancla
  externa ni sustituye las pruebas de integración posteriores.

### P4

**Herramienta:** ChatGPT, modelo GPT-6.

**Finalidad y partes asistidas (Change 005 — correlación y análisis):**

- Asistencia en el diseño OpenSpec, clientes offline de NVD y EPSS, mapeo CWE/ATT&CK y correlador con evidencia.
- Apoyo en los adaptadores ZAP y Nuclei, la orquestación del loop B, tests y evaluaciones golden.
- Preparación de comandos de PowerShell, corrección de errores y documentación de evidencias.

**Verificación humana y comprobaciones realizadas:**

- Ejecut? las pruebas automatizadas: 432 aprobadas y 1 omitida en mi rama P4.
- Ejecut? las evaluaciones golden: 32/32 casos aprobados.
- Revis? estáticamente cinco templates Nuclei y valid? su sintaxis con Nuclei v3.11.1, sin conexión de red.
- Ejecut? ZAP baseline contra DVWA dentro de la red Docker interna: 11 alertas no validadas y 0 fallos reportados.
- Revis? las salidas, correg? problemas de ejecución y guard? la evidencia en GitHub.

**Límites de la verificación:**

- Las evaluaciones golden no equivalen a evaluaciones live con un modelo.
- Las alertas de ZAP no demuestran por s? solas que una vulnerabilidad sea explotable.
- La corrida inicial de ZAP de P4 us? una aprobación local sin registrar la identidad del aprobador; las corridas integradas posteriores usan la CLI.
- La integración final y la segunda aprobación de Nuclei fueron completadas posteriormente por P5, según la evidencia grupal.

### P5

**Herramienta:** Claude Code, modelo Opus 5.5.

**Finalidad:** diseño, deltas, tests y código de los changes 006, 007, 008 y 009; la
bitácora SQLite del 002 (sobre el diseño de P1) y el cierre técnico del 005; mutaciones
M10–M44; integración de este informe.

**Verificación humana:** P5 aprobó cada diseño y delta antes de los tests, firmó la tabla
de vectores CVSS y la segunda aprobación de los templates de Nuclei, y ejecutó en persona
las corridas reales y los tests con Docker, aprobando cada gate con la CLI. En
`P5-recorrido-03` detectó dos errores de la IA al revisar el informe antes de la entrega
y no lo entregó (§6). Errores registrados en `ia-errores.md`.

**Límites:** `mypy --strict` se corrió solo sobre los módulos de P5.

## 1. Resumen ejecutivo

El grupo construyó una plataforma de pentest autorizado cuyo eje es el **control**:
ninguna acción toca un activo sin token de alcance vigente, sin pasar por
`Harness.invoke` y sin quedar en una bitácora verificable; las decisiones de riesgo
las toma una persona en gates explícitos. Un comando
(`python -m harness.pipeline run`) recorre RoE → recon → análisis → validación →
informe → entrega contra el laboratorio.

En la corrida entregada (`P5-recorrido-04`) el sistema relevó los dos objetivos,
ejecutó ZAP baseline, validó en un sandbox efímero 5 de 8 hallazgos con verificaciones
inertes del catálogo, generó el informe desde la bitácora y lo exportó a DefectDojo
tras la aprobación registrada de su hash. Los hallazgos son debilidades de
configuración (encabezados de seguridad y cookies), no vulnerabilidades explotadas.

Estado verificable: 483 tests en verde (2 omitidos sin Docker, corridos aparte con
Docker real), 221 Scenarios en 11 specs, los 9 changes al 100 %, 44 mutaciones
registradas, matriz de invariantes I1–I8 y red team A1–A10 y B1–B4 con historia de
commits.

## 2. Arquitectura

```
RoE firmado --> tokens.issue (por fase, TTL) --> ScopeToken
                                                    |
 orquestador (harness/pipeline.py, determinista)    v
  recon (loop A) ---------+                Harness.invoke --> Guard (sin LLM):
  análisis (loop B, ZAP) -+- cada acción -->   kill switch, token vivo, fase,
  validación (loop C) ----+                    alcance, DNS, gate humano
                                                    |
                       adaptador (argv fijo) / sandbox efímero
                                                    |
               bitácora SQLite append-only (hash encadenado + ancla)
                                                    |
         informe desde la bitácora --> gate de entrega (hash) --> DefectDojo
```

Gates humanos, todos por la CLI `harness.validation_cli`: primera acción activa,
análisis activo, cada hallazgo antes de validarlo y entrega del informe (ligada a su
hash). El orquestador espera la decisión; nunca aprueba.

## 3. Decisiones de diseño

| Decisión | Alternativa | Costo asumido | Dónde |
|---|---|---|---|
| Orquestación propia y determinista | LangGraph (propuesto por el kit, "a confirmar por cada equipo") | Sin pausa/reanudación de gates; sin agentes LLM en runtime | change 009 |
| Validación solo con verificaciones inertes, un contenedor por verificación | Exploits o sandbox compartido | Confirma menos; ~1 s por contenedor | 006 |
| Aprobación ligada a hallazgo + verificación + hash de parámetros | Aprobación por hallazgo | Reaprobar si cambia un parámetro | 006 |
| Estado del informe tomado de la bitácora | Confiar en lo que declara el hallazgo | Ninguno relevante | 007 |
| Vectores CVSS de hallazgos sin CVE asignados por el analista en una tabla firmada | Inventarlos o dejar el gate sin CVSS | Evaluación humana a mantener | 008 |
| Datos sensibles: rechazar, no redactar | Redacción automática | Falla visible en vez de silenciosa | 002, 007 |
| Bitácora SQLite por engagement con triggers, `UNIQUE(prev)` y ancla externa | Solo convención | Un `.db` por corrida | 002 |

## 4. Controles y cómo se verificaron

- **Harness e invariantes:** Guard determinista, token por fase con TTL, kill switch,
  bitácora de toda decisión (incluidos bloqueos). Specs `authorization` (23 Scenarios)
  y `audit-log` (14).
- **Red team:** A1–A10 sobre el guard (P2) y B1–B4 sobre el catálogo de validación
  (P5), cada uno con commit del test en rojo y commit de la corrección
  (`entrega/red-team.md`).
- **Mutaciones:** 44 controles rotos a propósito (M1–M44, `entrega/mutaciones.md`);
  todos rompieron al menos un test. M33 sobrevivió en su primera corrida y obligó a
  corregir un test débil.
- **Bitácora verificable:** `python -m harness.audit verify` detecta una fila
  alterada, una fila intermedia borrada y, con el ancla, el borrado de la última
  (`P5-002-audit-verify-demo.txt`).
- **Aislamiento del sandbox:** desde su red, `1.1.1.1:80` no es alcanzable y
  `dvwa.lab.test:80` sí (`P5-006-sandbox-sin-salida.txt`).
- **Herramientas reales contra el lab:** httpx/subfinder (P3), ZAP (P4 y recorrido),
  Nuclei con 5 templates aprobados por dos personas (`templates/allowlist/MANIFEST.md`,
  verificado por hash antes de cada corrida) y el sandbox (P5).
- **Adaptadores propios:** el kit traía solo nmap y Nuclei. El grupo agregó **subfinder y
  httpx** (P3, change 004), **ZAP baseline** (P4, change 005) y el **sandbox de
  validación** (P5, change 006). Cada uno tiene tests de bloqueo (objetivo fuera del lab,
  redirección externa, fase incorrecta, aprobación faltante), revisión cruzada y su change
  archivado; además se corrigió el adaptador de Nuclei para que pase por el harness.
- **Matriz de invariantes:** cada invariante I1–I8 con sus tests, mutaciones y evidencia
  en `entrega/matriz-invariantes.md`.

## 5. Evals

32 casos golden, todos aprobados: 10 de correlación y 10 de análisis (P4), 10 de
validación (3 del kit y 7 de P5 donde la respuesta correcta es no actuar) y 2 del
orquestador. Para los 7 casos de P5 se comprobó además que la rúbrica **rechaza** la
respuesta incorrecta de cada uno (`P5-006-evals-validacion.txt`).

**Análisis:** el modo golden verifica que la rúbrica acepta la salida esperada y
rechaza las prohibidas; no mide la capacidad del modelo. El modo `--mode live` no se
ejecutó, por lo que no hay datos para comparar prompts o modelos ni para justificar el
ruteo de `harness/models.yaml`. Es coherente con la decisión del change 009: los
agentes LLM no participan de las corridas.

## 6. Resultados de la corrida entregada

Corrida `P5-recorrido-04` (19/11/2026), informe v1 `f4ef94d4…`, entregado con
aprobación registrada y exportado a DefectDojo. Recon, análisis (ZAP) y validación
reales; vectores CVSS asignados por el analista; EPSS `unknown` (sin CVE).

| Hallazgo | Activo | CWE | Estado |
|---|---|---|---|
| Cookie sin `HttpOnly` | DVWA | CWE-1004 | Validado en sandbox |
| Cookie sin `SameSite` | DVWA | CWE-1275 | Validado en sandbox |
| Falta protección contra clickjacking | DVWA | CWE-1021 | Validado en sandbox |
| Falta `Content-Security-Policy` | DVWA | CWE-693 | Validado en sandbox |
| Falta `Content-Security-Policy` | Juice Shop | CWE-693 | Validado en sandbox (también Nuclei) |
| Banner con versión del servidor | DVWA | CWE-497 | No validado: sin verificación en el catálogo |
| Encabezado `Server` con versión | DVWA | CWE-497 | No validado: sin verificación en el catálogo |
| Falta `X-Content-Type-Options` | DVWA | CWE-693 | No validado: sin verificación en el catálogo |

La corrida anterior, `P5-recorrido-03`, **no se entregó**: al revisar el informe antes
de aprobar, P5 encontró dos hallazgos distintos unificados por error y una
verificación inexistente mostrada como real. Se corrigió con test y mutación (M35).

## 7. Riesgos y límites

- **Correlación por CVE sin efecto práctico:** no hay snapshot de NVD en el
  repositorio y el correlador espera `producto/versión` mientras el recon informa
  `producto:versión`.
- **Sin agentes LLM en runtime** y evals live no ejecutadas (§5, change 009).
- **`ScopeToken` es una clase pública:** cualquier código del harness puede
  construirlo sin el emisor; la restricción probada es estática (revisión del 003).
- **`deliver(report, True)`** con booleano sigue existiendo por compatibilidad; el
  recorrido usa solo la entrega con aprobación registrada.
- **Reescritura completa de la bitácora** por alguien con acceso al disco: solo el
  ancla guardada fuera del archivo la hace visible.
- **ZAP varía entre corridas** (la alerta 10023 apareció en `-03` y no en `-04`).
- La corrida real de ZAP de P4 aprobó su gate con `--approved`, sin registrar quién;
  las corridas posteriores usan la CLI de aprobación.

## 8. Retrospectiva del trabajo con IA

Los errores de la IA detectados y corregidos, con su commit, están en `ia-errores.md`
y `entrega/retrospectiva.md`. Casos representativos: tests que fallaban por un
fixture y no por el control (P2, P5), un token válido en el instante exacto de
expiración (P2), un test débil revelado por una mutación (P5, M33) y un informe con
hallazgos unificados por error que frenó el gate de entrega (P5).
**Pendiente:** filas de P1 y P4.

**Controles adicionales propuestos (change 010):** siete controles de gobernanza
justificados con ISO/IEC 29147 (divulgación coordinada), ISO/IEC 30111 (ciclo del
hallazgo hasta el cierre con retest) y NIST SP 800-115 (tratamiento y destrucción de la
evidencia, limpieza al cerrar, detención por el contacto de emergencia), con su delta y
la plantilla de divulgación completada con un hallazgo real
(`docs/plantilla-divulgacion-29147.md`). Propuestos, no implementados.

## 9. Aporte por integrante

| Integrante | Changes | Aporte principal |
|---|---|---|
| P1 | 002 (diseño, delta, contrato) | Contrato de la bitácora y diseño de persistencia, integridad y concurrencia |
| P2 | 003, gates del 007 | RoE, tokens, red team A1–A10, mutaciones M1–M9, revisión de `tool-selection.md` |
| P3 | 004, 007 · 2.3–2.4 | Loop A real (subfinder/httpx en runner aislado), grafo de activos, CVSS v4 estricto, estructura PTES |
| P4 | 005 | Clientes NVD/EPSS offline, mapeo CWE, correlador, adaptador y corrida real de ZAP, loop B, 20 evals, templates de Nuclei |
| P5 | 006, 007, 008, 009; cierre de 002 y 005 | Sandbox y loop C, informe y entrega, recorrido de un comando, análisis real; implementación del 002 (diseño de P1) y cierre técnico del 005 |

El detalle técnico de P2 y P5 está en `entrega/anexo-integrantes.md`, sin cambios.
