# Demo documental y exportación local

Desde `ptaas`, con Docker Desktop, la imagen base fijada ya disponible por digest
y el entorno Python local instalado:

```powershell
.\tools\defensive-delivery.ps1 -Output runs/mi-entrega -Bandit runs/bandit-local.json
```

Genera `LEEME.md`, `decisiones.json` y `sandbox-receipt.json`. Docker ejecuta la
validación documental sin red, como usuario no privilegiado, con solo tres
archivos montados en lectura. No monta credenciales, Git o el socket de Docker.

Solo después de revisar las decisiones y el Markdown, copiar manualmente el
valor `review_sha256` del recibo y aprobar esa versión:

```powershell
.\tools\defensive-delivery.ps1 -Output runs/mi-entrega -ApprovedSha256 '<hash revisado>'
```

Vuelve a validar en el sandbox, no confía en un recibo editable. Si cambió el
borrador o las decisiones, falla. Produce `defectdojo-generic.json`, con
`findings: []`: no hay hallazgos técnicos confirmados por este flujo. No se hace
importación en vivo, ni se debe usar este archivo para cerrar hallazgos previos.
El hash vincula bytes, no autentica al revisor. No sustituye la prueba docente
de validación contra un activo en el laboratorio.
