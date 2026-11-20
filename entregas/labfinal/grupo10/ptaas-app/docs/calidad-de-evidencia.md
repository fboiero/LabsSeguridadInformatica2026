# Paquete de revisión de evidencia

Desde `ptaas`, con un destino nuevo:

```powershell
.\.venv\Scripts\python.exe -B -m runtime.evidence_quality --bandit runs/bandit-local.json --output runs/mi-revision
```

Genera `LEEME.md` y `decisiones.json`. El modo predeterminado es offline.
`--live` agrega una llamada al analista Astra con categorías cerradas. `--live
--compare` agrega tres llamadas con el mismo lote sintético de veinte casos,
una por modelo. Se registra latencia de extremo a extremo y aciertos por caso;
el costo queda como no medido. Los casos prueban abstención, fidelidad de
referencias y formato, no descubrimiento de hallazgos ni detección. No se
reenvían archivos, rutas, hashes, comandos ni secretos a los modelos.

El flujo coteja el estado histórico con un comprobante por hito del commit
local fijado. Las referencias a blobs y sus hashes permiten revisar lo archivado.
El informe original se indexa, pero no se analiza técnicamente: no se valida
explotabilidad ni se vuelve a ejecutar el laboratorio.

Para adjuntar contexto aprobado de Bandit, usá `--context ruta.json`. El archivo
debe ser de la forma `{"report_sha256":"<sha256>","labels":{"bandit-1":"audit_internal_assertion"}}`.
Solo se aceptan etiquetas cerradas (aserción de pruebas, aserción interna de
auditoría, importación de procesos o frontera stateless). Las recomendaciones
asociadas son deterministas, no confirmaciones de vulnerabilidad. Una etiqueta
es una anotación del revisor, no un hecho validado sobre el código.

La revisión automática rechaza referencias ajenas, campos extra, duplicados y
conclusiones no respaldadas. No sustituye la checklist de revisión humana.
