# Traspaso P3 → P4/P5 — 2026-11-13

**Tasks:** 004 (implementación y tests locales), 007 · 2.3 y 2.4.

**Qué entrego:** AssetGraph versionado y persistido, run_recon, SubfinderEnum, HttpxProbe, render_report de P3, fixtures sintéticos y pruebas. Evidencia: entrega/evidencia/salidas/P3-ejecucion.md y P3-final.txt.

**Cómo se usa:**

```python
from harness.asset_graph import AssetGraph
from harness.loops import run_recon
from harness.reporting_p3 import render_report
from harness.reporting import deliver

graph = AssetGraph(token.engagement_id)
# harness ya configurado por el llamador con Guard, token y aprobaciones humanas reales.
# run_recon(harness, token, seeds, graph, checkpoint=path, correlate=propose_hosts)
# graph.save(path); graph = AssetGraph.load(path, token.engagement_id)
# report = render_report(token.engagement_id, findings, scope=scope_metadata)
# deliver conserva la exigencia de aprobación del Reviewer.
```

AssetGraph JSON usa schema_version=1, engagement_id, revision, iteration, status, stop_reason, schema_failures, frontier, assets, excluded y evidence_refs. Cada activo tiene id determinista, type=host, address, source_tool y technologies. Los estados STOPPED, ABORTED y PENDING_HITL se conservan. La frontera se recupera; el presupuesto no se reinicia. Los casos ejecutables completos están en tests/test_recon_loop_a.py y tests/test_reporting_p3.py.

**Procedencia:** fixtures sintéticos; sin corrida real en esta sesión. Subfinder sin runner local falla cerrado. HTTP no sigue Location automáticamente. El módulo de informe mantiene el formato contenedor del componente P5 sin editarlo.
