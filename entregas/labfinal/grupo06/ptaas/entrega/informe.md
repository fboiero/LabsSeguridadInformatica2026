# Informe técnico — PTaaS · Grupo 06

**Práctico Final Integrador — Seguridad Informática 2026 (UTN FRVM).**  
**Docente:** Ing. Fernando Boiero  
**Repositorio:** [AlejoDM/LabsSeguridadInformatica2026](https://github.com/AlejoDM/LabsSeguridadInformatica2026) (rama `labfinal-ptaas-grupo06`)  
**Laboratorio:** DVWA (`dvwa.lab.test`) y OWASP Juice Shop (`juiceshop.lab.test`), en red Docker interna sin salida a Internet.  
**Fecha de integración:** 19/11/2026.

## Integrantes — Grupo 06

| Nombre y apellido  | Legajo | Usuario de GitHub |
| ------------------ | ------ | ----------------- |
| Martín Beccereca   | 15154  | @martinbeccereca  |
| María Belén Benito | 14625  | @belubenito603    |
| Alejo De Miguel    | 15138  | @AlejoDM          |
| Tomás Giudici      | 14977  | @TomasGiudici     |
| Carolina Suppo     | 15057  | @carosuppo        |

---

## 0. Declaración de uso de IA

### Alejo De Miguel
*Declaración inicial (11/11). La persistencia del change 002 se completó posteriormente en la integración.*

**Herramienta:** Claude Code, modelo Haiku 5.5.

**Finalidad y partes asistidas (bitácora y auditoría):**
- Borrador de la firma del contrato de bitácora (`harness/audit.py`), del test que la cubre (`tests/test_audit_persistence.py`) y corrección de orden de imports con `ruff`.
- Borrador de `openspec/changes/002-audit-persistence/design.md` y del delta `specs/audit-log/spec.md`.
- Redacción de la nota de traspaso inicial sobre el contrato de auditoría.

**Verificación humana y comprobaciones realizadas:**
- Corrida de la línea base del kit: `pytest -q` (77 passed), `evals/run_evals.py --mode golden` (10/10) y `tools/progress.py`.
- `pytest` del contrato nuevo (5 passed), `mypy --strict harness/audit.py` (sin errores) y `ruff check` (limpio tras corregir imports).

**Límites de la verificación en esa etapa:**
- Las pruebas iniciales se corrieron con Python 3.14; el kit y el CI apuntan a Python 3.12.
- En esa etapa inicial no se levantó el laboratorio Docker (`lab/`) y los requisitos de SQLite (`design.md`) se implementaron y verificaron en la integración final.

### María Belén Benito

**Herramientas utilizadas:** opencode con DeepSeek V4.1 Flash en la implementación inicial y GPT-6 Luna en la revisión posterior.

**Finalidad y partes asistidas (autorización y red team):**
- Asistencia en el parser de RoE, la emisión de tokens, los controles del Guard, los tests adversariales (A1–A10) y la revisión de selección de herramientas.

**Verificación humana y comprobaciones realizadas:**
- Corrida de `pytest` (162 passed en esa etapa), `evals/run_evals.py --mode golden` (10/10), `tools/progress.py`, `ruff` y chequeo focal de `mypy`. Salidas crudas en `entrega/evidencia/salidas/`.
- Registro de los errores detectados y sus correcciones en `ia-errores.md` y `entrega/retrospectiva.md`.

**Límites de la verificación en esa etapa:**
- Las pruebas se corrieron con Python 3.13 (el kit apunta a Python 3.12) y sin ejecutar escaneos activos contra DVWA o Juice Shop.

### Tomás Giudici

**Herramienta:** Codex, basado en GPT-6.

**Finalidad y partes asistidas (relevamiento y apoyo al informe):**
- Asistencia en la redacción de specs, implementación y corrección del loop A, los adaptadores `subfinder`/`httpx` y la persistencia del grafo de activos.
- Elaboración de tests y fixtures, apoyo en la ejecución del laboratorio y en la documentación de evidencias; validación de CVSS v4/EPSS y estructura PTES para el informe (tareas 007 · 2.3–2.4).

**Verificación humana y comprobaciones realizadas:**
- Ejecución local de tests, evals, progreso y auditoría; revisión cruzada y aceptación del change 004 junto a María Belén Benito.
- Al cierre del change 004 (13/11): 251 tests aprobados, 10/10 evals golden y auditoría correcta (`openspec/changes/004-recon-loop-a/archive.md`).
- Errores detectados y correcciones registrados en `ia-errores.md` y `entrega/retrospectiva.md`.

**Límites de la verificación:**
- `subfinder` se ejecutó en el entorno real pero quedó `UNAVAILABLE` al no disponer de fuentes locales; `httpx` sondeó las semillas autorizadas de DVWA y Juice Shop dentro de la red aislada.
- El procesamiento de subdominios, exclusiones y enumeración vacía se comprobaron con fixtures simulados identificados explícitamente.

### Carolina Suppo

**Herramienta:** ChatGPT, modelo GPT-6.

**Finalidad y partes asistidas (Change 005 — correlación y análisis):**
- Asistencia en el diseño OpenSpec, clientes offline de NVD y EPSS, mapeo CWE/ATT&CK y correlador con evidencia.
- Apoyo en los adaptadores ZAP y Nuclei, la orquestación del loop B, tests y evaluaciones golden.
- Preparación de comandos de PowerShell, corrección de errores (como la decodificación `cp1252` en Windows) y documentación de evidencias.

**Verificación humana y comprobaciones realizadas:**
- Ejecutó las pruebas automatizadas: 432 aprobadas y 1 omitida en su rama de trabajo.
- Ejecutó las evaluaciones golden: 32/32 casos aprobados.
- Revisó estáticamente cinco templates Nuclei y validó su sintaxis con Nuclei v3.11.1 sin conexión de red.
- Ejecutó ZAP baseline contra DVWA dentro de la red Docker interna: 11 alertas no validadas y 0 fallos reportados.
- Revisó las salidas, corrigió problemas de ejecución y subió la evidencia al repositorio.

**Límites de la verificación:**
- Las evaluaciones golden no equivalen a evaluaciones live con un modelo.
- Las alertas de ZAP no demuestran por sí solas que una vulnerabilidad sea explotable.
- La corrida inicial de ZAP utilizó una aprobación local sin registrar identidad; las corridas integradas posteriores usan la CLI de aprobación.

### Martín Beccereca

**Herramienta:** Claude Code, modelo Opus 5.5.

**Finalidad y partes asistidas:**
- Diseño, deltas, tests y código de los changes 006, 007, 008 y 009; implementación de la bitácora SQLite del change 002 (sobre el diseño de Alejo De Miguel) y cierre técnico del change 005; mutaciones M10–M44 e integración final.

**Verificación humana y comprobaciones realizadas:**
- Revisó y aprobó cada diseño y delta antes de los tests, firmó la tabla de vectores CVSS y la segunda aprobación de los templates de Nuclei, y ejecutó en persona las corridas reales y los tests con Docker, aprobando cada gate con la CLI.
- En la corrida `P5-recorrido-03` detectó dos errores introducidos por la IA al revisar el informe antes del gate de entrega y rechazó la autorización (§6). Errores registrados en `ia-errores.md`.

**Límites de la verificación:**
- `mypy --strict` se corrió de forma focal sobre los módulos trabajados en esta etapa.

---

## 1. Introducción y resumen ejecutivo

Para este trabajo final integrador desarrollamos una plataforma de auditoría de seguridad automatizada (PTaaS) cuyo eje es el **control determinista**. Trabajamos bajo una premisa central: **el agente propone, pero el harness dispone**. Ningún modelo de lenguaje toma decisiones de seguridad; todo lo referido al alcance permitido, reglas de engagement (RoE), bitácora forense y compuertas de autorización está resuelto en código Python tradicional diseñado para fallar cerrado.

Un único comando (`python -m harness.pipeline run`) recorre el flujo completo contra el laboratorio: RoE → reconocimiento → análisis → validación inerte en sandbox → informe desde la bitácora → entrega y exportación.

En la corrida final entregada (`P5-recorrido-04`, 19/11/2026), el sistema relevó `dvwa.lab.test` y `juiceshop.lab.test`, ejecutó ZAP baseline, validó en contenedores efímeros 5 de los 8 hallazgos mediante verificaciones inertes del catálogo, generó el informe leyendo la bitácora y lo exportó a DefectDojo tras firmar su hash SHA-256. Los hallazgos corresponden a debilidades de configuración (encabezados HTTP y cookies), no a vulnerabilidades explotadas.

**Estado verificable del proyecto:**
- **Suite de tests:** 483 tests en verde (485 recolectados; 2 omitidos sin Docker real, corridos aparte con `PTAAS_SANDBOX_DOCKER=1`).
- **OpenSpec:** 10/10 changes al 100 % en `python tools/progress.py` y 221 Scenarios cubiertos en 11 specs.
- **Evaluaciones:** 32/32 casos golden aprobados (`python evals/run_evals.py --mode golden`).
- **Seguridad y robustez:** 44 pruebas de mutación (M1–M44), matriz de invariantes I1–I8 y 14 vectores de Red Team (A1–A10 y B1–B4) con historial de commits rojo/verde.

---

## 2. Arquitectura y control humano (HITL)

Separamos los agentes que proponen acciones del código que las ejecuta. Todas las invocaciones pasan obligatoriamente por `Harness.invoke`, que actúa como único punto de control determinista:

```text
[RoE Firmado] ---> [Emisor de Tokens: TTL corto, ventana UTC, acotado a fase y CIDR]
                           |
                           v  (ScopeToken)
[Orquestador / Swarm] ---> [Harness.invoke: PUNTO UNICO DE CONTROL DETERMINISTA]
                           |-- Kill Switch global: congela la ejecucion si esta activo.
                           |-- ScopeToken: valida vigencia temporal y correspondencia de fase.
                           |-- Scope Guard: chequeo de CIDR y dominios (sin comodines).
                           |-- Revalidacion DNS: previene rebote hacia IPs publicas fuera de lab.
                           |-- Gate Humano (HITL): espera token de aprobacion firmado por CLI.
                           v
            +--------------+--------------+
            |                             |
            v                             v
   [Adaptadores de Red]          [Sandbox Efimero]
   - subfinder / httpx           - Contenedor Docker de un solo uso
   - ZAP Baseline Scanner        - Red interna sin gateway hacia Internet
   - Nuclei (Allowlist)          - Solo ejecuta PoCs inertes del catalogo
            |                             |
            +--------------+--------------+
                           v
             [Bitacora SQLite Append-Only] (SHA-256 encadenado + Ancla Externa)
                           v
             [Informe Forense] ---> [Gate Entrega (Hash)] ---> [Exportacion DefectDojo]
```

Implementamos cuatro compuertas humanas obligatorias gestionadas desde la CLI `harness.validation_cli`:
1. **Primera acción activa:** frena la ejecución antes de enviar el primer paquete hacia el objetivo (`httpx`).
2. **Análisis activo:** requiere aprobación previa a los escaneos automáticos con ZAP o Nuclei.
3. **Validación por hallazgo:** exige autorización antes de levantar el contenedor efímero; está ligada criptográficamente al hash de los parámetros (si cambia un parámetro, la firma se anula).
4. **Entrega del informe:** exige firmar el hash SHA-256 exacto del documento antes de remitirlo y exportarlo a DefectDojo.

---

## 3. Decisiones de diseño

| Decisión | Alternativa | Costo asumido | Change |
|---|---|---|---|
| Orquestación propia y determinista | LangGraph (propuesto en el kit, "a confirmar por cada equipo") | Sin pausa/reanudación de gates; sin agentes LLM en runtime | 009 |
| Validación solo con verificaciones inertes, un contenedor por verificación | Exploits o sandbox compartido | Confirma menos; ~1 s por contenedor | 006 |
| Aprobación ligada a hallazgo + verificación + hash de parámetros | Aprobación simple por hallazgo | Reaprobar si cambia un parámetro | 006 |
| Estado del informe tomado directamente de la bitácora | Confiar en lo que declara el hallazgo | Ninguno relevante | 007 |
| Vectores CVSS de hallazgos sin CVE asignados por el analista en tabla firmada | Inventarlos o dejar el gate sin CVSS | Evaluación humana a mantener | 008 |
| Datos sensibles: rechazar, no redactar | Redacción automática | Falla visible en vez de silenciosa | 002, 007 |
| Bitácora SQLite por engagement con triggers, `UNIQUE(prev)` y ancla externa | Solo convención | Un archivo `.db` por corrida | 002 |

---

## 4. Controles y cómo se verificaron

- **Harness e invariantes (I1–I8):** Guard determinista, token por fase con TTL, kill switch y bitácora de toda decisión (`OK`, `BLOCKED`, `PENDING_HITL`, `ABORTED`). Specs `authorization` (23 Scenarios) y `audit-log` (14 Scenarios). Matriz completa en `entrega/matriz-invariantes.md`.
- **Bitácora SQLite verificable:** transacciones `BEGIN IMMEDIATE`, `UNIQUE(prev)`, triggers contra `UPDATE`/`DELETE` y ancla externa. Tanto `python -m harness.pipeline verify` como `python -m harness.audit verify` detectan filas alteradas, filas borradas y truncado al final (`entrega/evidencia/salidas/P5-002-audit-verify-demo.txt`).
- **Red team (A1–A10 y B1–B4):** 14 vectores adversariales desarrollados primero en rojo y luego mitigados en verde (`98e85f4` → `1b9392e`, `9a76691` → `937a234`, `cfdd3a0` → `77bc330`), con 41 tests pasando en `tests/test_redteam_guard.py`. Detalle en `entrega/red-team.md`.
- **Pruebas de mutación (M1–M44):** 44 controles rotos intencionalmente (`entrega/mutaciones.md`); todos hicieron fallar al menos un test. En el caso de **M33** (filtro de alertas informativas de riesgo 0 en ZAP), la mutación sobrevivió inicialmente porque el test usaba una alerta sin CWE descartada por otra regla; se corrigió usando la alerta ZAP 10027 (CWE-615 válido) y la mutación pasó a ser detectada de inmediato.
- **Aislamiento del sandbox:** desde la red interna del laboratorio, `probe_egress` confirma que `1.1.1.1:80` está bloqueado (`False`) mientras que `dvwa.lab.test:80` es alcanzable (`True`).
- **Adaptadores propios y herramientas reales:** además de corregir el adaptador de Nuclei para que pase por el harness (con 5 templates curados en `templates/allowlist/MANIFEST.md` y doble firma humana), desarrollamos los adaptadores de **`subfinder` y `httpx`** (change 004), **`zap.baseline`** (change 005) y el **sandbox de validación** (change 006), cada uno con tests de bloqueo y revisión cruzada.

---

## 5. Evaluaciones (Evals)

Ejecutamos `python evals/run_evals.py --mode golden` con **32/32 casos aprobados**: 10 de correlación, 10 de análisis, 10 de validación (incluyendo 7 casos donde la respuesta correcta es no actuar) y 2 del orquestador. Para los casos de validación se verificó además que la rúbrica rechaza explícitamente la respuesta incorrecta.

**Límite del modo golden:** verifica que la rúbrica acepta la salida esperada y rechaza salidas prohibidas, pero no mide capacidades de un modelo en vivo. El modo `--mode live` no se ejecutó, lo cual es coherente con la decisión del change 009 de mantener la orquestación determinista sin agentes LLM en runtime.

---

## 6. Resultados de la corrida entregada

Corrida final `P5-recorrido-04` (19/11/2026), informe v1 `f4ef94d4…`, aprobado en el gate de entrega y exportado a DefectDojo (`defectdojo.json`).

| Identificador | Activo | Debilidad detectada | CWE | Estado de validación |
|---|---|---|---|---|
| `DVWA-ZAP-10010` | `dvwa.lab.test` | Cookie sin flag `HttpOnly` | CWE-1004 | Validado en sandbox (`POC-COOKIE-001`) |
| `DVWA-ZAP-10054` | `dvwa.lab.test` | Cookie sin atributo `SameSite` | CWE-1275 | Validado en sandbox (`POC-COOKIE-001`) |
| `DVWA-ZAP-10020` | `dvwa.lab.test` | Falta protección Anti-Clickjacking | CWE-1021 | Validado en sandbox (`POC-HDR-001`) |
| `DVWA-ZAP-10038` | `dvwa.lab.test` | Falta `Content-Security-Policy` (CSP) | CWE-693 | Validado en sandbox (`POC-CSP-001`) |
| `JUICESHOP-ZAP-10038` | `juiceshop.lab.test` | Falta `Content-Security-Policy` (CSP) | CWE-693 | Validado en sandbox (`POC-CSP-001`) |
| `DVWA-ZAP-10009` | `dvwa.lab.test` | Fuga de versión en banner HTML | CWE-497 | Observado por ZAP (sin PoC inerte) |
| `DVWA-ZAP-10036` | `dvwa.lab.test` | Fuga de versión en encabezado `Server` | CWE-497 | Observado por ZAP (sin PoC inerte) |
| `DVWA-ZAP-10021` | `dvwa.lab.test` | Falta encabezado `X-Content-Type-Options` | CWE-693 | Observado por ZAP (sin PoC inerte) |

**Caso real en el gate de entrega (corrida `P5-recorrido-03`):** en la prueba previa, la IA unificó por error dos alertas distintas (`10009` y `10036`, ambas con CWE-497) y les inventó una verificación inexistente (`NINGUNA vNone`). Ningún test automático atrapó el defecto. Al revisar el borrador antes de aprobar, Martín Beccereca detectó el error y rechazó la entrega. Se agregó un test de regresión y la mutación M35, y recién se autorizó y exportó la corrida `P5-recorrido-04`.

---

## 7. Riesgos y límites

- **Correlación por CVE sin efecto práctico:** no hay snapshot de NVD en el repositorio y el correlador espera formato `producto/versión` mientras que el recon informa `producto:versión`.
- **Sin agentes LLM en runtime** y evaluaciones `--mode live` no ejecutadas (§5, change 009).
- **`ScopeToken` es una clase pública:** cualquier código del harness podría construirlo sin el emisor; la restricción comprobada es estática (revisión del change 003).
- **`deliver(report, True)`** con booleano sigue existiendo por compatibilidad; el pipeline usa exclusivamente la entrega con aprobación registrada por hash.
- **Reescritura completa de la bitácora** por alguien con acceso físico al disco: solo el ancla externa guardada fuera del archivo permite detectarlo.
- **Variabilidad de ZAP entre corridas:** la alerta 10023 apareció en la corrida 03 y no en la 04.
- La corrida inicial de ZAP durante el desarrollo del change 005 aprobó su gate con `--approved` sin registrar identidad; todas las corridas integradas posteriores usan `harness.validation_cli`.

---

## 8. Retrospectiva del trabajo con IA y gobernanza

Todos los integrantes documentaron en `ia-errores.md` y `entrega/retrospectiva.md` los errores introducidos por los modelos de IA durante el desarrollo:

- **Alejo De Miguel (Claude Code / Haiku 5.5):** la IA commiteó el contrato de bitácora sin consensuar la firma con el grupo; se frenó y formalizó primero en `design.md`.
- **María Belén Benito (opencode / DeepSeek V4.1):** escribió el test A1 con un host incompatible con el token y dejó `is_live()` inclusivo en `window_end`; se corrigió pasando a intervalos semiabiertos $[start, end)$.
- **Tomás Giudici (Codex / GPT-6):** el adaptador `httpx` interpretaba stdout vacío como éxito (`OK`); se ajustó para exigir respuesta HTTP verificable.
- **Carolina Suppo (ChatGPT / GPT-6):** las llamadas a Docker en Windows leían con codificación ANSI (`cp1252`), generando `UnicodeDecodeError`; se forzó decodificación UTF-8 con reemplazo seguro.
- **Martín Beccereca (Claude Code / Opus 5.5):** generó un test de alertas informativas que pasaba por una regla no relacionada; se detectó con la mutación M33 y se reescribió con la alerta ZAP 10027.

**Propuesta de controles de gobernanza (Change 010):** propusimos siete controles formales (detallados en el repositorio) apoyados en tres normas de la industria:
- **ISO/IEC 29147 (Divulgación responsable):** procedimiento de divulgación coordinada y plantilla completada con un hallazgo real del laboratorio (`docs/plantilla-divulgacion-29147.md`).
- **ISO/IEC 30111 (Gestión de vulnerabilidades):** trazabilidad completa del hallazgo desde su detección hasta el retest posterior a la corrección.
- **NIST SP 800-115 (Aislamiento y cadena de custodia):** destrucción inmediata de contenedores efímeros, preservación de hashes de evidencia y detención ante contacto de emergencia.

---

## 9. Aporte por integrante

| Integrante | Changes | Aporte principal |
|---|---|---|
| Alejo De Miguel | 002 (diseño, delta, contrato) | Contrato de la bitácora y diseño de persistencia, integridad y concurrencia |
| María Belén Benito | 003, gates del 007 | RoE, emisión de tokens, red team A1–A10, mutaciones M1–M9, revisión de `tool-selection.md` |
| Tomás Giudici | 004, 007 · 2.3–2.4 | Loop A real (`subfinder`/`httpx` en runner aislado), grafo de activos, CVSS v4 estricto y estructura PTES |
| Carolina Suppo | 005 | Clientes NVD/EPSS offline, mapeo CWE, correlador, adaptador y corrida real de ZAP, loop B, 20 evals y templates de Nuclei |
| Martín Beccereca | 006, 007, 008, 009; cierre de 002 y 005 | Sandbox y loop C, informe y entrega, pipeline de un comando, corrida real integrada; implementación SQLite del 002 y cierre técnico del 005 |

El detalle técnico complementario se encuentra en `entrega/anexo-integrantes.md`. La versión consolidada en LaTeX para generación del PDF final (con capturas y comandos de verificación) está en `entrega/informe-final-grupo06.tex`.
