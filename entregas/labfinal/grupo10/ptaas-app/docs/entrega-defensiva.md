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

## Prueba manual de importación en DefectDojo

Con una sesión iniciada en una instancia donde tengas permiso de importación,
abrí un engagement exclusivo de prueba. Elegí **Import Scan Results** y el tipo
**Generic Findings Import**. Subí el [JSON sintético](../tests/fixtures/defectdojo-generic-smoke.json).
Si hay un filtro de severidad mínima, seleccioná **Info**. Dejá desmarcados
**Active**, **Verified** y **Close Old Findings**, y no habilites integraciones
externas. Verificá que el test nuevo muestre el registro informativo sintético
(puede ser necesario incluir registros inactivos en el filtro).

Registrá fecha, versión de DefectDojo si está visible y resultado, sin credenciales
ni datos privados. Esta prueba confirma el importador de la interfaz para un
fixture; no acredita el publicador por API ni la importación del archivo real del
proyecto. Para verificar este último, repetí en el engagement de prueba con el
`defectdojo-generic.json` generado arriba: el resultado esperado es un test sin
hallazgos, si la instancia acepta importaciones vacías.

## Resultado de la validación local — 2026-11-21

DefectDojo Open Source **3.5.202**, en un entorno Docker local y un engagement
exclusivo de prueba (ID local `1`). Se probaron dos cargas multipart en
`/api/v2/import-scan/` con `scan_type=Generic Findings Import`, mediante el
cliente de pruebas de Django REST Framework dentro de la instancia y con la
base persistente real. No se usaron credenciales del portal ni datos reales.

| Archivo | HTTP | Test local | Hallazgos persistidos |
|---|---|---|---|
| JSON sintético de prueba | `201` | `1` | 1, informativo, inactivo y no verificado |
| JSON del exportador `runtime.delivery.validate`, generado con el paquete sintético de `tests/test_delivery.py` | `201` | `2` | 0, como se esperaba |

Esto verifica la compatibilidad del **archivo exportado** con esa versión de
DefectDojo. Es una prueba distinta de la publicación por HTTP.

## Publicador por API: prueba HTTP local

`runtime.defectdojo.publish` requiere la URL, el token, el ID numérico del
engagement (`DEFECTDOJO_ENGAGEMENT_ID` o `engagement_id`) y el hash aprobado
del informe. Usa HTTPS, salvo HTTP sobre loopback, y no sigue redirecciones.
Envía `Generic Findings Import` como multipart. Si el informe tiene entradas,
se importan como `Info`, inactivas y no verificadas: el publicador no calcula
severidad a partir del vector CVSS. No solicita cerrar hallazgos previos.

En la misma instancia local se ejecutó el publicador por HTTP con un token
temporal y un informe de prueba sin hallazgos: respondió `201`, creó el test
local `3` en el engagement `1` y se verificaron cero hallazgos persistidos.
Se retiraron la cuenta de prueba y su token. No se publicó el recibo real de
Juice Shop ni se contactó una instancia de la cátedra.
