# Checkpoint 3 — evidencia defensiva, entrega parcial

Se generó un borrador desde `runs/bandit-local.json`, informe de análisis
estático ya recolectado sobre el código propio. Docker corrió como usuario no
privilegiado, sin red y con entrada de solo lectura. No se ejecutó Bandit de
nuevo. Las cuatro alertas son preliminares; no hay hallazgos confirmados.

El borrador quedó en `PENDING_HITL`. Para exportar luego de revisarlo, desde
`ptaas` indicá manualmente el SHA-256 del borrador cuyos bytes aprobaste:

```powershell
.\.venv\Scripts\python.exe -B -m runtime.defensive_report export runs/bandit-local.json <borrador.json> <destino-nuevo.json> --approved-sha256 <hash-aprobado>
```

Los nombres entre `<>` se reemplazan por valores reales. El hash confirma qué
bytes se revisaron, no la identidad de la persona. Si cambia el borrador o el
artefacto original, se rechaza la exportación. La ruta positiva se probó solo
con fixtures; el borrador real no se aprobó ni se exportó. El formato es JSON
local, no DefectDojo. Esto no sustituye la validación de laboratorio de `006`
ni el informe final de `007`.
