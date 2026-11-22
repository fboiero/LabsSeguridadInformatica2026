# Recorrido activo de PhantomCorp

El PTaaS ahora puede ejecutar el recorrido sobre la imagen local del laboratorio.
No usa la imagen `cyberlab-phantomcorp-intra:latest` preexistente si no coincide
con el código: la imagen reproducible se construye desde
`labs/labfinal-practico-integrador/entorno/phantomcorp`.

## Levantar el objetivo

Desde la raíz del repositorio:

```powershell
docker rm -f cyberlab-phantomcorp 2>$null
docker build -t ptaas-phantomcorp:grupo10 labs/labfinal-practico-integrador/entorno/phantomcorp
docker run -d --name cyberlab-phantomcorp --hostname phantomcorp -p 127.0.0.1:18080:80 --network bridge ptaas-phantomcorp:grupo10
```

## Ejecutar el PTaaS

```powershell
cd entregas/labfinal/grupo10/ptaas-app
$run = "runs/phantomcorp-active-$(Get-Date -Format yyyyMMdd-HHmmss)"
.\.venv\Scripts\python.exe -B -m runtime.active_phantomcorp --base-url http://127.0.0.1:18080 --approve-lab --output $run
```

`--approve-lab` es el gate humano de inicio. El adaptador no permite cambiar el
objetivo, los endpoints, la inyección del fixture ni el comando de R4 desde la
CLI o un agente. El recorrido terminó con cuatro marcadores y cuatro requests;
la salida se guarda en `result.json` y la bitácora en `audit.db`.

La evidencia es un resumen: R1 portal localizado; R2 acceso administrativo del
fixture; R3 configuración accesible; R4 resumen de 48.210 registros. Los hashes
permiten cotejar respuestas de la corrida, pero no se guardan flags, tokens,
credenciales ni cuerpos HTTP. Se trata de un laboratorio deliberadamente
vulnerable y el comando de R4 está fijado por código para minimizar el impacto.

El resultado siempre queda `PENDING_HITL`. La corrida activa demuestra que el
PTaaS recolectó evidencia del contenedor, no que los hallazgos estén confirmados
ni que el informe pueda entregarse sin revisión. Detené el contenedor cuando
termines:

```powershell
docker rm -f cyberlab-phantomcorp
```
