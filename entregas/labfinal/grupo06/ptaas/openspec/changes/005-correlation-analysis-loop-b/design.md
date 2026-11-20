# Diseño — Change 005: correlación, análisis y Loop B

**Estado:** propuesta de P4 para revisión cruzada; no constituye aprobación ni implementación.

## 1. Alcance y decisiones de seguridad

El Change 005 integra correlación de datos offline con análisis no destructivo y un Loop B acotado. La correlación no inicia conexiones a activos. Los análisis activos solo se dirigen a DVWA o Juice Shop del laboratorio aislado, mediante capacidades autorizadas por `Harness.invoke`, con un `ScopeToken` válido y registro de resultados y bloqueos en auditoría. Los agentes no ejecutan herramientas directamente.

Se mantienen los contratos presentes en `harness/schemas.py`: `CandidateFinding` exige `evidence_refs`, admite `cve=None`, `epss=None`, `cwe="unknown"`; `PrioritizedVuln` exige `rationale` y `status` entre `confirmed`, `discarded` e `inconclusive`. Los resultados no respaldados no se presentan como confirmaciones.

## 2. Snapshots NVD y EPSS (lectura offline)

**Formato propuesto:** archivos JSON UTF-8 versionados para los datos de correlación, acompañados por un manifiesto de procedencia con `source`, `retrieved_at` (UTC), `snapshot_date`, `schema_version`, `sha256`, `record_count` y referencia de la descarga oficial. La fecha, los hashes y las entradas se obtienen de archivos reales: no se generan registros ficticios como si fueran NVD/EPSS. Los fixtures sintéticos de tests se etiquetan explícitamente como tales y no se usan en informes de hallazgos reales.

**NVD:** cada registro conserva el ID de CVE y su fuente, las coincidencias con producto/versión y, si la fuente los incluye, CWE y métricas CVSS v4.0. La correlación por tecnología y versión exige una coincidencia justificada: identificar un nombre de producto no demuestra por sí solo vulnerabilidad. Si la versión o la correspondencia es ambigua, el resultado es de baja confianza, nunca `confirmed`.

**EPSS:** se vincula por ID de CVE y fecha del snapshot. Un valor disponible se valida dentro de `[0,1]`. Ausencia del CVE o dato inválido produce `epss=None`, con motivo registrado; no se infiere un EPSS de otros atributos.

**Desactualización e integridad:** el lector valida esquema, hash y fecha. Snapshot corrupto o de origen no verificable: se rechaza y se registra el error. Si está ausente o desactualizado, se declara su estado como `missing`/`stale`, se evita presentar datos como actuales y se continúa solo en modo degradado si los datos disponibles siguen permitiendo trazabilidad; de lo contrario se devuelve `inconclusive`/sin candidato, sin sondear la red para compensar. El umbral de antigüedad se define y aprueba antes de implementarlo (propuesta inicial: NVD 30 días y EPSS 7 días, configurables; no son requisitos confirmados).

**Pruebas:** fixtures offline de entradas válidas, faltantes, dañadas, hashes incorrectos, fechas inválidas y datos obsoletos. Ningún test necesita consultar Internet.

## 3. Correlación, evidencia, deduplicación y confianza

**Insumos:** `AssetGraph` persistido entregado por P3 y snapshots validados. Una evidencia conserva referencia al activo, tecnología, versión (si se observó), herramienta/fuente y origen del feed. Los identificadores de evidencia deben ser resolubles por el sistema de auditoría o por archivos de evidencia trazables, no cadenas inventadas.

**Regla de candidato:** solo se crea `CandidateFinding` con al menos una referencia de evidencia real. Para candidatos basados en CVE, deben estar justificadas la identidad de producto y la versión afectada; sin CVE en snapshot no se inventa uno ni se genera un candidato *por CVE*. Los hallazgos de configuración independientes de CVE requieren evidencia propia. `cwe="unknown"` y `attack_technique=None` cuando el mapeo no tiene sustento.

**Confianza (política propuesta):** `high` cuando versión y producto coinciden de forma inequívoca con entrada oficial y existe evidencia de detección reproducible; `medium` si hay datos coherentes pero falta comprobación independiente; `low` si la versión o fuente es parcial/ambigua. La confianza es una clasificación de evidencia, no una confirmación de explotabilidad. Se debe especificar en el delta cómo se calculan estos valores y probarlo.

**Deduplicación:** reutilizar `dedupe()` de `harness/schemas.py`, que agrupa por `(asset_id, cve or cwe)` y une `evidence_refs`. Revisar en tests colisiones con `cwe="unknown"` (dos hallazgos sin CVE no relacionados podrían fusionarse): no modificar este archivo sin aprobación del dueño o delta correspondiente.

**Normalización:** el mapeo CWE se toma de un catálogo identificable; una técnica MITRE ATT&CK solo se asocia con una correspondencia explícita y documentada. Si no hay mapeo, queda `unknown`/`None` sin fabricar equivalencias.

## 4. Priorización reproducible

Respetar la función existente `priority_score(cvss_v4, epss, asset_criticality)` con pesos `0.6 * CVSS_v4 + 2.5 * EPSS + 0.25 * criticidad`, redondeada a dos decimales, mientras el grupo no apruebe una modificación de spec. La función usa `0` internamente cuando `epss is None`; esto **no** significa que la probabilidad EPSS observada sea cero: conservar `None` en los datos y marcar el puntaje como calculado con EPSS faltante. La función exige CVSS numérico; si no hay CVSS v4.0 válido, no inventar 0 ni usar automáticamente una versión distinta: declarar la prioridad cuantitativa no calculable hasta que exista una política aprobada.

## 5. Análisis no destructivo: ZAP baseline y Nuclei

**ZAP:** perfil baseline pasivo, opciones y tiempo de ejecución fijos, sin escaneo activo, fuzzing, explotación ni seguimiento de destinos fuera del alcance. Su ejecución atraviesa `Harness.invoke` como `zap.baseline_scan`; el adaptador solo prepara parámetros seguros, delega en un runner controlado y devuelve resultados estructurados. Probar primero con runner simulado y fixtures; ejecutar contra el lab solo con token y autorizaciones válidas.

**Nuclei:** `nuclei.safe_templates` ya existe pero actualmente construye `argv` con el directorio `templates/allowlist` y filtra tags; **eso por sí solo no demuestra que cada archivo tenga revisión humana**. Implementar un control determinista que compruebe, antes de invocar el runner, que cada template ejecutable figura en `MANIFEST.md` (o su representación verificable) con ruta, hash SHA-256, propósito, tags, fecha, aprobación de P4 y de otro integrante, y estado aprobado. Bloquear y auditar archivos no registrados, modificados tras aprobación o con acciones intrusivas. Evitar patrones comodín y cargas desde directorios externos.

**Selección de templates:** al menos cinco templates *inertes* distintos, revisados individualmente por P4 y otra persona del grupo. No se incorporan de forma automática ni se da aprobación en nombre de nadie. La allow-list y el manifiesto se preparan para revisión, pero los templates no se consideran habilitados hasta contar con las aprobaciones reales. Mantener los flags no interactivos y sin actualizaciones de `profiles.yaml` salvo cambio revisado.

**Resultados contradictorios:** ZAP y Nuclei pueden diferir. No sumar ambas salidas como confirmación por simple coincidencia textual. Conservar ambas evidencias, versiones de herramientas y alcance, identificar posibles falsos positivos y decidir `confirmed` solo con evidencia suficiente y verificable bajo las reglas acordadas; si falta certeza, `inconclusive` con `rationale`. `discarded` requiere justificación explícita (por ejemplo, evidencia que contradiga de manera verificable la hipótesis). Una coincidencia negativa de una herramienta no invalida por sí sola la evidencia positiva de otra.

**Falsos positivos conocidos del lab:** se documentan por identificador, condición observada y evidencia de descarte; no se agregan excepciones globales por nombre de herramienta ni se ocultan de la auditoría.

## 6. Loop B: estados, parada y errores

El orquestador consume candidatos con evidencia y solicita análisis mediante `Harness.invoke` en fase `ANALYZE`. Reutiliza `decide_detection(history_new_evidence, max_iterations, resolved=...)` y evita reanalizar indefinidamente sin cambios. Estados finales por candidato: `confirmed`, `discarded`, `inconclusive`, con justificación y referencias.

- Si hay evidencia suficiente y resolución justificada, detener con estado resuelto.
- Tras dos iteraciones consecutivas con cero evidencias nuevas, detener con `inconclusive`.
- Si se alcanza el tope sin resolución, detener con `inconclusive`.
- Ante dos salidas inválidas consecutivas, registrar y escalar a `PENDING_HITL`, sin autoaprobar.
- La interrupción de kill switch o autorización bloquea el trabajo, se audita y no debe transformarse en `confirmed`.

**Observación para revisión con P3:** la función `decide_detection()` actualmente revisa el tope de iteraciones **antes** de detectar dos ceros consecutivos. Si el tope coincide con la segunda vuelta sin novedad, el motivo será `tope de iteraciones alcanzado`, no `sin ganancia de información`. Definir precedencia con P3 y agregar tests para el caso de empate; cambiar `harness/loops.py` solamente mediante PR autorizado por su dueño.

## 7. Tests, evals y evidencia

Crear `tests/test_correlation_loop_b.py`, sin modificar tests existentes salvo revisión explícita. Cubrir: ausencia y corrupción de snapshots, no invención de CVE/EPSS/CWE, candidato sin evidencia, correlación sin sondeos (también bloqueo y auditoría de invocaciones indebidas), dedupe y contradicciones, allow-list con hash/aprobación, dos vueltas sin evidencia, tope de iteraciones y escalado HITL. Vincular nuevos tests desde los `Tests:` de las specs modificadas.

Añadir casos a `evals/cases/correlation.json` y `evals/cases/vuln_analysis.json` hasta llegar a **20 casos totales en el proyecto como mínimo**, con al menos **10 casos nuevos o ampliados de correlación/análisis**, según `tasks.md`. Los resultados actuales de partida son **17/17 golden**; no confundir cantidad de casos con cantidad de tests de pytest. Guardar resultados antes/después y analizar errores. La corrida `--mode live` requiere un modelo y credenciales provistas localmente por una persona, nunca en Git.

Por cada control: delta de spec con Scenario negativo → test que falla por la razón correcta y commit independiente → corrección mínima → tests y lint/tipos → mutación manual que demuestra que el test detecta una regresión → registro de evidencia y PR revisado.

## 8. Contratos y coordinación

- **P3:** contrato de `AssetGraph` persistido y revisión de cualquier cambio a `harness/loops.py` o `harness/profiles.yaml`.
- **P2:** contrato de RoE, tokens y autorización para pruebas integradas.
- **P5:** fixtures/estado del laboratorio y del runner para ejecutar ZAP/Nuclei dentro del alcance.
- **P4 y otro integrante:** aprobación de cada template de allow-list.
- **P3 revisa los PR de P4**, según el ciclo de revisión cruzada acordado.

## 9. Preguntas pendientes de revisión humana

1. ¿Qué umbrales y política de caducidad se aprueban para NVD y EPSS? ¿Se permite operar con un snapshot marcado `stale` y bajo qué restricciones?
2. ¿Qué evidencia exacta alcanza para marcar un hallazgo como `confirmed`, y cómo registrar falsos positivos conocidos del lab?
3. ¿Qué formato operativo se utilizará para verificar `MANIFEST.md` sin confiar solo en texto libre?
4. ¿Cuál es la precedencia entre parada por tope y parada por dos iteraciones sin novedad cuando ocurren a la vez?
5. ¿Cómo se identifican de forma estable las evidencias y el `AssetGraph` de P3?

**Estado final de esta tarea:** borrador de diseño listo para revisión, **task 1.1 aún sin marcar**; todavía no se ejecutaron nuevos tests de P4 ni se aprobó ningún template.
