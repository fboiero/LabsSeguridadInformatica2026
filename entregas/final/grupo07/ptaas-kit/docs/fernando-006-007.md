# Fernando — validación, informe e integración

Corte del 20/11/2026. Trabajo sobre `final-grupo07`, solo dentro de la entrega.

## Qué quedó implementado
- 006: loop C con catálogo inerte, aprobación por contenido y TTL, CLI de decisiones,
  Sender restringido y worker Docker efímero sobre red interna. Validación real de
  POC-CSP-001 en DVWA `/login.php`, sin CSP. No se siguió la redirección de `/`.
- 007: reporte PTES con referencias al audit, vector base CVSS v4, EPSS opcional,
  detección de patrones de secretos, versión por hash, gate de entrega y JSON
  Generic Findings Import para DefectDojo. No se probó una instancia DefectDojo.
- Integración: `python -m harness.run`; recon/correlación/análisis son adaptadores
  sintéticos explícitos hasta recibir e integrar 004/005. Audit en memoria exportado
  a JSON con verificación de cadena; no sustituye la persistencia SQLite de 002.

## Preparación (PowerShell, desde esta carpeta del kit)
```powershell
.\.venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING='utf-8'
python -m pytest -q
python evals/run_evals.py --mode golden
python tools/progress.py
docker compose -f lab/docker-compose.yml up -d
```
Si falta el entorno: `python -m venv .venv`, activarlo e instalar `pyyaml pytest`.
La red Docker es `lab_lab`, internal, 10.99.0.0/28; objetivos .2 y .3, runner .4.
El RoE de ejemplo vence el 20/11 a las 23:00 de Argentina. Para otro día el
Reviewer debe aprobar una nueva ventana; no se modifica automáticamente.

## Demo en tres pasos
1. Mostrar que sin aprobación no se envía la validación ni se publica:
```powershell
python -m harness.run --roe roe/roe-lab.example.yaml --output .demo-output-pending --approvals .demo-output-pending/approvals.json
```
2. El Reviewer decide explícitamente validar el hallazgo F-CSP-001 en el lab:
```powershell
python -m harness.run --roe roe/roe-lab.example.yaml --validation-mode sandbox --approve F-CSP-001 --reviewer "Nombre del Reviewer" --reason "Validar ausencia de CSP en DVWA" --output .demo-output-manual --approvals .demo-output-manual/approvals.json
```
Este paso valida pero deja la entrega pendiente. Consultar el borrador y evidencia
locales de esa carpeta antes de aprobar la entrega.
3. Aprobar por separado la versión exacta del informe:
```powershell
python -m harness.approvals --store .demo-output-manual/approvals.json list
python -m harness.run --roe roe/roe-lab.example.yaml --deliver-bundle .demo-output-manual/bundle-draft.json --approve delivery --reviewer "Nombre del Reviewer" --reason "Revisé esta versión del informe" --output .demo-output-manual --approvals .demo-output-manual/approvals.json
```
Se generan `published/informe.md` y `published/defectdojo.json`. Esto publica solo
archivos locales; no envía nada a servicios externos. La CLI registra la identidad
declarada del Reviewer, sin autenticación criptográfica.

Las aprobaciones en `evidencia/fernando/` son de pruebas automatizadas, identificadas
como tales; no equivalen a la revisión cruzada ni a la aprobación académica final.

## Resultados del primer corte (antes de integrar 004/005)
- 131 tests aprobados: 103 recibidos + 28 incorporados.
- 15/15 golden: verifican casos y rúbrica, no razonamiento de un LLM vivo.
- Ruff pasa para los seis módulos nuevos. Mypy general tiene 46 errores heredados
  en 10 archivos; no reporta errores en los módulos nuevos. No se afirma verde global.
- Dos mutation checks detectados (quitar gate de validación; quitar gate de entrega).
- 006: 13/15. 007: 12/15. Total 002–007 en esta copia: 38/90 (42,2 %).
- Evidencia cruda y reporte de prueba: `evidencia/fernando/`.

## Lo que falta coordinar
Lautaro revisa 1.3 de 006/007; después se archivan los deltas (3.6). No se marcó
una revisión ajena como propia. Falta recibir 002/004/005 en la rama remota para
conectar SQLite, recon y análisis reales de los compañeros. Los 004/005 no estaban
en origin/final-grupo07 al último fetch; no se marcaron sus revisiones 1.3.
007 3.5 queda pendiente porque la primera mitad de la demo usa fixtures.
Actualizar los números de informe y Canva después de integrar esos aportes.

## Para explicar oralmente tu parte
“Mi parte comienza con un hallazgo candidato. Antes de comprobarlo, el sistema
requiere una aprobación ligada a ese hallazgo y a los parámetros exactos. El agente
elige una verificación ya aprobada del catálogo; no genera un exploit. El worker
se ejecuta en una red Docker interna y se elimina al terminar. Después el informe
vincula el resultado con la bitácora y exige una segunda aprobación para entregar.
Probamos esa validación contra DVWA. En este corte la primera mitad del recorrido
usa fixtures, y la exportación a DefectDojo se genera como JSON local.”

## Referencias del formato
- CVSS v4: https://www.first.org/cvss/v4.0/specification-document
- Generic Findings Import: https://docs.defectdojo.com/supported_tools/parsers/generic_findings_import/

## Actualización tras recibir los cambios de Lorenzo
Se incorporó origin/final-grupo07@2e55625. El comando ahora llama a ReconLoop,
Correlator y DetectionLoop de 004/005, usando sus adaptadores con runners de fixtures.
La correlación devuelve 0 CVE porque la fixture HTTPX no trae versión exacta;
no se inventa una coincidencia. El candidato CSP de 006 es una semilla manual de
la demo y queda identificado como tal: las alertas genéricas de 005 no lo confirman.
El loop B termina inconcluso y el loop C puede comprobarlo en DVWA con gate explícito.

Resultados actualizados: 152 tests, 20/20 evals golden y 65/90 tasks (72,2 %).
006 sigue 13/15 y 007 12/15: no se marca como recorrido enteramente real al usar
fixtures en A/B. Solo 002 continúa sin recibir. Ya no corresponde decir que faltan
los códigos de 004/005; faltan sus corridas reales y las revisiones humanas.
Comandos de demo: se conservan los anteriores, ahora conectados con 004/005.

Frase simple para exponer: “Ahora el comando ejecuta los loops de Lorenzo y
continúa con mi validación e informe. La primera parte usa datos de ejemplo;
la comprobación de CSP se probó realmente en DVWA. Si no hay una coincidencia
exacta o evidencia suficiente, lo muestra como desconocido o inconcluso.”
