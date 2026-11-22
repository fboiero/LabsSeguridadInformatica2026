# Selección de herramientas — PTaaS (Grupo 10)

## Resumen
El Grupo 10 adopta para el MVP **7 herramientas/fuentes** con salida estructurada y operación no destructiva, todas encapsuladas como adaptadores tipados invocados exclusivamente mediante `Harness.invoke`: **subfinder, httpx, nmap, feeds NVD/EPSS/CWE, OWASP ZAP, Nuclei y DefectDojo**, junto al **catálogo interno de verificaciones inertes (`poc_catalog`)**. Ningún agente ejecuta binarios directamente ni recibe acceso libre de shell.

## Criterios de selección del grupo
1. **Licencia compatible con plataforma de servicio / proceso externo:** priorizamos licencias permisivas (MIT, BSD-3-Clause, Apache-2.0) y aislamos herramientas con restricciones de redistribución (como `nmap` bajo NPSL) como procesos externos no embebidos.
2. **Salida determinista y parseable:** JSON/JSONL/XML validado por schema antes de circular entre agentes o entrar al `AssetGraph`.
3. **Control de impacto y modo no destructivo:** posibilidad de fijar `rate_limit_rps_per_target` (`5 rps`), desactivar OAST/fuzzing y prohibir argumentos agresivos desde `harness/profiles.yaml`.
4. **Cobertura de estándares de la materia:** mapeo explícito a PTES, NIST SP 800-115, OWASP WSTG, OSSTMM, CVE/CWE, EPSS, CVSS v4.0 e ISO/IEC 29147/30111.
5. **Trazabilidad e invariantes del harness:** argv fijo con `shell=False`, timeout acotado, validación previa en `Guard` y bitácora SHA-256 sin datos sensibles en claro.

## Matriz por fase (evaluación y estado en Grupo 10)

| Fase PTES | Capability | Herramienta | Licencia verificada | Salida | Estándar / guía | Estado en Grupo 10 |
|---|---|---|---|---|---|---|
| Intelligence Gathering (pasivo) | `subfinder.enum` | ProjectDiscovery subfinder | MIT | JSONL | PTES §2, OSSTMM | Adaptador + Loop A implementado (`fixtures` / `lab`) |
| Intelligence Gathering (activo) | `httpx.probe` | ProjectDiscovery httpx | MIT | JSONL | PTES §2 | Adaptador + `RateLimiter` + Loop A implementado |
| Intelligence Gathering (activo) | `nmap.service_scan` | Nmap | NPSL (uso como proceso externo) | XML | PTES §2, NIST 800-115 | Adaptador acotado + tests de `forbidden_args` |
| Threat Modeling / correlación | `cve.lookup` | Feed NVD | Datos públicos (NIST) | JSON | CVE, CWE | Definido en `tools.yaml` + schemas (change 005 pendiente) |
| Threat Modeling / correlación | `epss.lookup` | Feed FIRST EPSS | Datos públicos | JSON | EPSS | Definido en `tools.yaml` + `priority_score` determinista |
| Threat Modeling / correlación | `cwe.map` | Catálogo MITRE CWE | Datos públicos | JSON | CWE | Validado en schemas y `reporting.py` |
| Vulnerability Analysis (web) | `zap.baseline_scan` | OWASP ZAP | Apache-2.0 | JSON | OWASP WSTG | Definido en MVP (integración viva pendiente post-MVP) |
| Vulnerability Analysis (web/red) | `nuclei.safe_templates` | ProjectDiscovery Nuclei | MIT | JSONL | NIST 800-115 | Adaptador acotado + exclusión de tags intrusivos y `-ni` |
| Validation | `poc_catalog.run_parametrized` | Catálogo interno curado | Propia del proyecto | JSON | PTES §5 | 6 verificaciones inertes + gate HITL obligatorio |
| Reporting / gestión | `defectdojo.export` | OWASP DefectDojo | BSD-3-Clause | JSON (API) | ISO/IEC 29147 / 30111 | Exportador fail-closed con hash de aprobación (`runtime/defectdojo.py`) |
| Reporting local | `report.render` | Renderizador interno | Propia del proyecto | Markdown + JSON | PTES §7, CVSS v4.0 | Implementado y verificado por tests |
| Recon pasivo ampliado | `amass.passive` | OWASP Amass | Apache-2.0 | JSON | OSSTMM | Diferido (post-MVP) |
| Supply chain / contenedores | `trivy.scan` | Aqua Trivy | Apache-2.0 | JSON | NIST SSDF | Diferido (post-MVP) |
| Infraestructura | `greenbone.scan` | OpenVAS / Greenbone | GPL | XML | NIST 800-115 | Diferido por peso operativo (post-MVP) |
| Web secundario | `wapiti.scan` | Wapiti | GPL-2.0 | JSON | OWASP WSTG | Diferido (post-MVP) |
| Recon masivo | — | masscan | AGPL-3.0 | — | — | **Descartada:** licencia AGPL y tasa agresiva incompatible con entorno controlado |
| Web legacy | — | Nikto | GPL-2.0 | — | — | **Descartada:** alto ruido frente a ZAP baseline + Nuclei curado |

## Decisiones justificadas del Grupo 10
1. **Orden pasivo → activo obligatorio en Loop A (`harness/recon_order.py` + `harness/loop_a.py`):** ejecutamos `subfinder.enum` antes que `httpx.probe` y bloqueamos todo dominio fuera de `ScopeToken` antes de llegar al adaptador activo. Además, `dedupe_assets` evita re-sondear el mismo `(tipo, dirección)` entre iteraciones.
2. **Runner Python stdlib como respaldo dentro de `runner` (`python:3.12-slim`):** el contenedor `runner` definido en `lab/docker-compose.yml` no incluye los binarios Go de `subfinder`/`httpx` por defecto; por eso `httpx_adapter.py` conserva el `build_argv` fijo para el binario oficial `httpx` y suma `stdlib_http_runner` (sin redirecciones automáticas ni shell) y un modo `--mode fixture` en `tools/run_loop_a.py` para verificación reproducible sin dependencias externas.
3. **Nmap acotado como proceso externo (NPSL):** `nmap_adapter.py` fija `-sV -T3 --open --top-ports 100 --max-rate 100` y prohíbe `--script`, `-sC`, `-A`, `-O`, `-sU`, `-iL`, `--proxies`. Por su licencia NPSL no se redistribuye dentro de la plataforma.
4. **Nuclei estrictamente curado:** `nuclei_adapter.py` obliga `-t templates/allowlist`, excluye `intrusive`, `dos`, `fuzz`, `bruteforce`, `rce`, `sqli`, `xss`, `oast`, `cve`, `kev`, y exige `-ni` (sin Interactsh/OAST) y `-duc` para impedir tráfico saliente fuera del laboratorio.
5. **ZAP en baseline y DefectDojo fail-closed:** ZAP queda acotado a `baseline_scan` (no intrusivo) y `runtime/defectdojo.py` bloquea cualquier publicación si falta instancia/token o si el SHA-256 del informe no coincide con la aprobación humana (`PENDING_HITL`).
6. **Validación sin generación de exploits:** el agente solo selecciona y parametriza verificaciones inertes del catálogo (`poc_catalog`), siempre tras aprobación HITL.

## Coherencia verificada
- `harness/policy_loader.py:inconsistencies()` valida automáticamente en `pytest` que todas las capabilities habilitadas en `harness/policy.yaml` coincidan 1:1 con las declaradas en `harness/tools.yaml`.
- `tests/test_adapters.py` y `tests/test_subfinder_httpx_adapters.py` verifican argv fijo, rechazo de credenciales/metacaracteres, `RateLimiter`, salida JSON/JSONL válida y manejo controlado de errores de ejecución.
