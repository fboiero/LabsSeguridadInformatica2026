# Guion de defensa — Grupo 10 (10 minutos)

Ejecutar desde `entregas/final/grupo10/ptaas` con el entorno Python del proyecto.
La demo lee recibos de corridas reales previas. No levanta Docker, no contacta el
laboratorio y no reemplaza la corrida integrada en vivo exigida por la rúbrica.

| Minutos | Mostrar | Mensaje |
|---|---|---|
| 0–1 | Alcance y reglas de engagement | Juice Shop es la opción del kit; PhantomCorp es el clásico previo, separado. |
| 1–3 | `python -m runtime.evidence_demo` | Cinco recibos, hashes de los archivos, HTTP 200, dos rondas, recorrido integrado y limpieza. |
| 3–5 | Resultados y límites | CSP ausente es una observación; Nuclei produjo salida, ZAP falló y no hay correlación CVE acreditada. |
| 5–7 | Gate de informe | Mostrar `PENDING_HITL` y un hash incorrecto rechazado. Si el revisor aprueba, usar el hash del borrador exacto. |
| 7–9 | Evals y retrospectiva | Ejecutar ambos modos; explicar qué controles detectan los casos y qué no miden. |
| 9–10 | Cierre | Separar comprobación de control, explotabilidad no evaluada y requisitos pendientes. |

```powershell
python -m runtime.evidence_demo
python -m evals.run_evals --mode golden
python -m evals.run_evals --mode mutation
```

Solo después de revisión humana, reemplazar `HASH_REVISADO` por el digest
mostrado en el borrador y elegir un archivo nuevo:

```powershell
python -m runtime.evidence_demo --approve-sha256 HASH_REVISADO --export-empty revision-local.json
```

La exportación contiene cero hallazgos y no se publica. No importarla como
un nuevo escaneo sobre una evaluación existente. No se verificó en una
instancia de DefectDojo. Aprobar por hash liga el contenido, no autentica la
identidad de la persona ni certifica los recibos originales.

El borrador incluye un inventario de snapshots NVD/EPSS y comprueba que sus
datos coincidan con el SHA-256 declarado por el descargador. Esto comprueba
consistencia local, no autenticidad externa ni aplicabilidad a Juice Shop.

## Para la revisión independiente

- Identificar la copia revisada y registrar revisor, fecha, pruebas y decisión.
- Verificar que modificar un recibo invalida la aprobación anterior.
- Distinguir resúmenes de bitácora de un SQLite persistente verificable.
- Registrar las brechas restantes y no archivar como aprobado sin firma.
- Consultar si el PTaaS acompaña o reemplaza al clásico. El informe histórico es
  `entregas/labfinal/grupo10/informe.md` en `bf8f681`; no es una corrida de esta demo.
