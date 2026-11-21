# Change 005 — Solicitud de revisión y cierre (Persona 4)

> **Actualización 2026-11-19: revisión cruzada realizada por Martin Beccereca (P5): APROBADO CON OBSERVACIONES — ver `openspec/changes/005-correlation-analysis-loop-b/archive.md`.**
>
> Estado original: revisión pendiente. Este registro NO constituye autorización, aprobación de seguridad ni prueba de ejecución de escáneres.

## Estado conocido (19/11/2026)

- Rama P4 `labfinal-ptaas-p4-grupo06`, último commit confirmado `254dfb4`.
- Tests completos: 423 passed, 1 skipped; golden: 32/32.
- 10 casos correlation y 10 vuln_analysis en los golden; **live no ejecutado**.
- NVD/EPSS, mapeo CWE, correlador, adaptador ZAP, política e integración simulada de Loop B implementados con cobertura inicial.
- 5 propuestas Nuclei en `templates/proposed_p4/`, **todavía fuera de** `templates/allowlist/`.
- Evidencia ZAP: `PENDING_HITL`, **no constituye un escaneo**.
- No constan corridas reales ZAP/Nuclei ni aprobación del primer sondeo.

## Revisión cruzada 1.3 — la realiza P3

El plan del equipo fija el ciclo **P1 → P2 → P3 → P4 → P5 → P1**: P3 revisa P4 y P4 revisa P5. El revisor debe registrar aprobación o cambios solicitados por escrito. P4 no se autoaprueba.

| Control de revisión | Resultado | Revisor | Fecha / evidencia |
|---|---|---|---|
| 1.1 design.md: datos offline, antigüedad, confianza, conflictos | APROBADO (con observaciones) | Martin Beccereca (P5) | 2026-11-19 · archive.md |
| 1.2 specs correlation y vuln-analysis | APROBADO (con observaciones) | Martin Beccereca (P5) | 2026-11-19 · archive.md |
| Tests negativos y trazabilidad de escenarios | APROBADO (con observaciones) | Martin Beccereca (P5) | 2026-11-19 · archive.md |
| Acciones activas vía Harness.invoke y audit | APROBADO (con observaciones) | Martin Beccereca (P5) | 2026-11-19 · archive.md |
| Loop B: dos rondas sin evidencia, anomalías | APROBADO (con observaciones) | Martin Beccereca (P5) | 2026-11-19 · archive.md |

## Revisión de los cinco templates — tarea 3.2

Las huellas SHA-256 se generan desde **los archivos reales de la rama local** con:

`python -m tools.p4_preflight_005`

Informe generado: `entrega/evidencia/salidas/p4-template-preflight.json`.

| Archivo | Método / ruta | Estado de aprobación | Revisor y fecha |
|---|---|---|---|
| p4-security-header-csp.yaml | GET / | PROPUESTO | |
| p4-security-header-x-content-type-options.yaml | GET / | PROPUESTO | |
| p4-security-header-x-frame-options.yaml | GET / | PROPUESTO | |
| p4-server-header-present.yaml | GET / | PROPUESTO | |
| p4-login-form-visible.yaml | GET /login.php | PROPUESTO | |

**Revisión humana obligatoria antes de mover archivos:** comprobar contenido YAML y hash, sintaxis con versión real Nuclei, alcance DVWA/Juice Shop, aislamiento, no redirecciones, no OAST, no mutaciones ni fuzzing; firmar aprobador/fecha/versión y decisión por cada archivo. El chequeo automatizado solo valida cinco estructuras predefinidas. No prueba el comportamiento de la herramienta.

## Autorizaciones de escaneo — tareas 3.1 y 3.3

| Requisito | Estado | Quién da el visto bueno | Evidencia |
|---|---|---|---|
| RoE y token válidos para targets del lab | POR CONFIRMAR | Responsable RoE/P2 | |
| Gate HITL de primera acción activa | POR CONFIRMAR | Revisor autorizado | |
| Ejecutar ZAP baseline en la red interna | NO EJECUTADO | Revisor autorizado | |
| Ejecutar Nuclei con allow-list ya aprobada | NO EJECUTADO | Revisor autorizado | |
| Reportes y logs reproducibles dentro del alcance | NO DISPONIBLE | P4 | |

**Precaución:** el script local `tools/run_zap_lab_p4.py` contiene `--approved`, que NO valida por sí mismo una firma del revisor. No usar esa opción sin aprobación documentada y sin revisar el control de redirecciones; un reporte inspeccionado al terminar no impide que el spider haya intentado salir del objetivo.

## Cierre — tarea 4.6

No archivar las deltas ni marcar 1.3, 3.1, 3.2, 3.3 o 4.6 como completadas hasta disponer de sus evidencias. Tras revisión aprobada, archivar según el flujo OpenSpec del proyecto y actualizar tests, tasks y `entrega`.

## Verificación adicional sugerida

El plan P4 requiere al menos una corrida `evals/run_evals.py --mode live` (API key configurada localmente) y un análisis escrito de desvíos. El `--mode golden` verifica que la rúbrica acepta outputs esperados, no la capacidad del modelo. **No subir API keys ni respuestas con datos sensibles.**
