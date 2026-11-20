# Revisión de seguridad — Turno 2 (Chiara)

Fecha: 2026-11-19 · Revisión del diff contra el checklist de seguridad del proyecto
(invariantes del harness I1–I8 y alcance autorizado). Alcance: cambios del Turno 2 en
`harness/` y specs.

## Diff revisado
- `harness/contracts.py` — `AuditLog.record(..., evidence=None)`, `evidence_ref`, `evidence_matches`.
- `harness/schemas.py` — `Asset.address` obligatoria, `dedupe_assets`.
- `harness/adapters/common.py` — `RateLimiter`, `rate_limiter_from_policy`.
- `harness/recon_order.py` — orden pasivo→activo (nuevo).
- `tests/audit_log/`, `tests/asset_discovery/` — tests por Scenario (nuevos).
- `openspec/specs/audit-log/spec.md`, `openspec/specs/asset-discovery/spec.md`.

## Checklist

1. **¿Algún camino evita `Harness.invoke` o el Guard?** No. Los helpers agregados
   (`RateLimiter`, `recon_order`, `dedupe_assets`, `evidence_ref`) son deterministas y
   puros: no ejecutan herramientas, no usan `subprocess` ni tocan activos. No hay bypass.
2. **¿Falta bitácora en algún resultado?** No. `record()` conserva OK/BLOCKED/PENDING_HITL/
   ABORTED y la cadena de hash; `evidence_ref` se incluye en el `body` antes del hash, así
   que la verificación de integridad sigue cubriendo la referencia.
3. **¿Adaptadores con `shell=True` o interpolación sin validar?** No se agregó ejecución.
   `RateLimiter`/`recon_order` reciben strings y no construyen comandos.
4. **¿La validación genera código ofensivo?** N/A — el Turno 2 no toca la fase de validación.
5. **¿Cada Scenario con test y cada requisito de seguridad con caso negativo?** Sí:
   - audit-log "evidencia grande" → `tests/audit_log/test_no_sensitive_data.py`.
   - asset-discovery "ráfaga de sondeos" y "orden de técnicas" → tests nuevos.
   - 3 Requirements nuevos, cada uno con Scenario negativo y test.

## Hallazgos

| # | Sev | Archivo | Qué | Acción |
|---|-----|---------|-----|--------|
| H1 | LOW | harness/adapters/common.py (`RateLimiter`), harness/recon_order.py, harness/schemas.py (`dedupe_assets`) | Los controles existen y están testeados, pero todavía **no están cableados** en el adaptador de recon ni en el loop A; son capability + test, no enforcement en los call sites. | Cablearlos al implementar `004-recon-loop-a`. Documentado como deuda, no como control activo. |
| H2 | INFO | harness/contracts.py (`evidence_ref`) | La referencia es `sha256(contenido)`. Es una **referencia verificable, no un control de confidencialidad**: con evidencia de baja entropía el hash podría revertirse. Correcto para el requisito (no guardar contenido), pero no debe presentarse como cifrado. | Sin acción; aclarado en el docstring. |
| H3 | INFO | harness/recon_order.py (`is_passive`) | Una capability desconocida se trata como **activa** (fail-safe conservador): ante la duda no se asume pasiva. | Sin acción; es el sentido seguro. |

## Veredicto
Sin hallazgos de severidad media o alta. Los invariantes I1–I8 se mantienen.
Tests 103/103, evals golden 10/10, `progress.py` exit 0.
