# Recorrido real con decisiones explícitas de prueba — 20/11/2026

Comando desde el kit:

```powershell
python -m harness.run --roe roe/roe-lab.example.yaml --output .demo-output-live-approved-lorenzo --approvals .demo-output-live-approved-lorenzo/approvals.json --tools-mode docker --validation-mode sandbox --approve F-CSP-001 --approve delivery --reviewer "Codex prueba automatizada" --reason "Verificacion tecnica del recorrido local autorizada por Lorenzo; no revision academica humana"
```

Resultado real:

- Loop A: grafo estabilizado, subfinder y HTTPX Docker, red internal lab_lab.
- Correlación: 0 coincidencias CVE exactas en snapshots offline.
- Loop B: ZAP y Nuclei reales, inconclusive por falta de nueva evidencia.
- CSP: candidato manual, diferenciado de las alertas de herramientas.
- Loop C: validated con POC-CSP-001, worker Docker de catálogo inerte.
- Entrega: exported_local_json tras decisión explícita de prueba.
- Cadena SQLite y audit.json: OK; ver audit-verify.txt y audit.db.

Las aprobaciones se identifican como prueba automatizada. No se atribuye una
aprobación humana a los compañeros. No se importó nada en DefectDojo remoto.
Sin flags de aprobación el recorrido conserva PENDING_HITL: la evidencia de la
primera corrida se conserva en ../integracion-real-pending/.

Archivos: tool-calls.json registra argv/exit/stdout/stderr reales; asset-graph.json,
pipeline-evidence.json y validation-evidence.json describen las fases;
bundle-draft.json y published/ contienen el informe y JSON locales;
audit.db es el backup SQLite y audit.json su exportación compatible.
