# Recorrido real sin aprobación — 20/11/2026

Comando desde el kit:

```powershell
python -m harness.run --roe roe/roe-lab.example.yaml --output .demo-output-live-lorenzo --approvals .demo-output-live-lorenzo/approvals.json --tools-mode docker --validation-mode sandbox
python -m harness.audit verify .demo-output-live-lorenzo/audit-68e223eab0423b8c836cc6b1c3eb605c751f835d22fd00fad3fd7af9de41d933.db
```

- Subfinder y HTTPX reales mediante Harness.invoke; grafo estabilizado.
- Subfinder sin salida a internet no obtiene hosts de fuentes públicas; su salida
  vacía no se sustituye por fixtures. HTTPX obtiene la tecnología real de DVWA.
- Correlación offline: cero coincidencias exactas de CVE.
- ZAP/Nuclei reales en el loop B: inconcluso, sin ganancia de información.
- Candidato CSP manual, sin atribuirle confirmación automática por las alertas.
- Gates de validación y entrega: PENDING_HITL. No se publicó ningún informe.
- `audit.db` es backup SQLite de la corrida; `audit-verify.txt` registra CLI OK
  sobre ella y CORRUPTA sobre una copia con una fila alterada evadiendo el trigger.
- `tool-calls.json` registra cada ejecución real en red lab_lab internal.

No se modificó Canva ni se actualizaron documentos externos en este cierre.
