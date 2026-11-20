# Corridas reales de Lorenzo — 20/11/2026

## Actualización de cierre
Las herramientas reales ya están conectadas al recorrido completo por
`python -m harness.run --tools-mode docker --validation-mode sandbox`.
Ver `integracion-real-pending/` (sin aprobación, gates pendientes),
`integracion-real-approved/` (aprobaciones explícitas identificadas como prueba,
validación real y JSON local) y `cierre/` (170 tests, 20/20 evals, lint y avance).
Ambas corridas usan SQLite del 002 y `audit verify`. Las revisiones documentales
se cerraron a pedido de Lorenzo, identificadas en `docs/revisiones-cierre.md`.
El candidato CSP sigue manual; la correlación no fabricó CVE y el loop B
concluyó inconcluso. La nota histórica de abajo describe la primera corrida
independiente, anterior a esta integración.

Red Docker `lab_lab`, `internal: true`, sin puertos publicados.
DVWA en 10.99.0.2, Juice Shop en 10.99.0.3; preflight HTTP 200 para ambos.
Las herramientas se ejecutaron contra `dvwa.lab.test` por `Harness.invoke`,
con token emitido por `TokenIssuer` desde el RoE vigente del lab.

## Evidencia

- `20261120T143854Z`: HTTPX real, 302, Apache HTTP Server 2.4.25, Debian y PHP.
- `20261120T144215Z`: Nuclei v3.11.1 con los cinco templates del manifiesto;
  coincidencia informativa de robots.txt. No confirma los CVE de los snapshots.
- `20261120T144633Z`: ZAP baseline real, 11 tipos de alerta; CSP y protección
  contra clickjacking ausentes, cookies sin atributos y divulgación informativa.
  Exit 2 es el resultado de warnings del baseline, con reporte JSON válido.

Cada carpeta contiene argumentos y stdout/stderr (`calls.json`), salida del
adaptador (`results.json`) y cadena de bitácora (`audit.json`). La cadena JSON
se verificó con `harness.run.verify_entries`. Esto no sustituye `audit verify`
SQLite del change 002, que sigue pendiente.

## Repetir

Desde la raíz del kit, con Docker Desktop iniciado y RoE vigente:

```powershell
docker compose -f lab/docker-compose.yml up -d
python tools/run_live_004_005.py --tools httpx nuclei zap
```

El ejecutor comprueba la red interna y traduce rutas Windows a rutas Linux.
No usa fixtures ni aprueba gates humanos. Estas son corridas de adaptadores;
no demuestran el recorrido integrado de los loops A/B con herramientas reales.
La revisión cruzada de Fernando sigue pendiente.

## Imágenes usadas

- HTTPX: `sha256:f8275a7c6aaec187249df9eaf4ad9196f4677adfc6a51a47b4aaa1d4db4f8ffc`
- Nuclei: `sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb`
- ZAP: `sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af`

Las etiquetas latest/stable pueden cambiar; los digests identifican este corte.
