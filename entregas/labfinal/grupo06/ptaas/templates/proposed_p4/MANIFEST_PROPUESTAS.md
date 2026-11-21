# MANIFEST — Propuestas Nuclei P4 (NO APROBADAS)

Estos cinco templates son **borradores**. No mover a `templates/allowlist/` ni ejecutar hasta revisión explícita por `security-reviewer`, registro del aprobador, fecha, versión, SHA-256 y autorización de primera acción activa conforme al proyecto. No se ha realizado revisión humana ni ejecución real.

| Template | Alcance | Riesgo residual | Revisor | Fecha | Estado |
|---|---|---|---|---|---|
| `p4-security-header-x-content-type-options.yaml` | GET `/`, informativo | Posibles redirecciones, falsos positivos y enlaces externos; sin seguir redirecciones configuradas | Pendiente | Pendiente | PROPUESTO |
| `p4-security-header-x-frame-options.yaml` | GET `/`, informativo | Posibles redirecciones, falsos positivos y enlaces externos; sin seguir redirecciones configuradas | Pendiente | Pendiente | PROPUESTO |
| `p4-security-header-csp.yaml` | GET `/`, informativo | Posibles redirecciones, falsos positivos y enlaces externos; sin seguir redirecciones configuradas | Pendiente | Pendiente | PROPUESTO |
| `p4-server-header-present.yaml` | GET `/`, informativo | Posibles redirecciones, falsos positivos y enlaces externos; sin seguir redirecciones configuradas | Pendiente | Pendiente | PROPUESTO |
| `p4-login-form-visible.yaml` | GET `/login.php`, informativo | Posibles redirecciones, falsos positivos y enlaces externos; sin seguir redirecciones configuradas | Pendiente | Pendiente | PROPUESTO |

Antes de aprobar: inspeccionar YAML línea por línea; verificar sintaxis con la versión local de Nuclei; fijar hashes SHA-256 y versión; comprobar límites por template y URL; confirmar DNS/red aislada, scope y HITL; validar sin OAST ni auto-actualizaciones; inspeccionar salidas. Las cabeceras ausentes y paneles visibles NO implican vulnerabilidad explotable.
