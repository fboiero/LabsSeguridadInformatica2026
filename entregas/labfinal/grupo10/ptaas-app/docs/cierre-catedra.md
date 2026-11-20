# Cierre docente: cobertura, diferencias y revisión

Fuentes: enunciado, plan de 15 días y rúbrica del kit de la cátedra. El kit
indica **DVWA o Juice Shop**; no pide los dos. Los fixtures por nombre no
equivalen a una corrida contra ese laboratorio. PhantomCorp tiene evidencia
histórica separada y no se presume equivalente sin acuerdo del docente.

**Puesta en marcha comprobada:** `tools/juiceshop-smoke.ps1` ejecutó la imagen
real de Juice Shop, fijada por digest, en una red Docker interna sin puertos
publicados. Un contenedor auxiliar en esa red recibió HTTP 200 de la raíz
pública. Se registraron el digest, el ID de imagen y la eliminación del objetivo
y de la red en `runs/juiceshop-real-20261118-203231.json`. Esto acredita la
puesta en marcha, no un pentest ni una validación de explotabilidad.

| Capability docente | Evidencia local y brecha |
|---|---|
| authorization | RoE, expiración y emisión local en 003; revisión formal pendiente. |
| engagement-lifecycle | Estados de la demo y escalado del loop documental; no se acredita todo el ciclo del kit. |
| audit-log | SQLite, cadena verificable y políticas de saneamiento en 002; sin anclaje externo. |
| tool-adapters | Contratos y tests del harness inerte. La revisión documental no invoca herramientas de reconocimiento. |
| asset-discovery | Loop A local con `AssetGraph`, parser de subfinder y `httpx.probe`; falta una corrida docente archivada con binarios oficiales. |
| correlation | Snapshots offline, evidencia obligatoria y datos ausentes como `null`; falta alimentar snapshots oficiales del curso. |
| vuln-analysis | Allowlist local de cinco templates y loop B determinista; ZAP/Nuclei reales quedan sujetos a disponibilidad del kit. |
| validation | Sender real, gate HITL y sandbox efímero ejecutados contra Juice Shop. |
| poc-catalog | Catálogo curado y Sender real conectados; corrida `POC-CSP-001` archivada. |
| reporting | Informe defensivo, revisión humana y formato Generic Findings Import; sin hallazgos nuevos confirmados. |
| agent-contracts | Schemas/validadores, tres modelos evaluados en lote cerrado y loop de revisión acotado; no acredita tres loops docentes. |

Los escenarios que sí pertenecen al perfil local están indexados en
`openspec/specs/scenario-tests.tsv`. No se renombran componentes defensivos a
004–007 para aparentar equivalencia. Los módulos locales de 004, 005, 006 y 007
están separados y trazados; la equivalencia final queda sujeta a revisión docente.

El catálogo cubre la base de `poc-catalog` y ya se demostró una corrida real de
`POC-CSP-001` aprobada contra Juice Shop, enlazada al sandbox `006`. El recibo
es `runs/juice-poc-real-20261118-204806-csp.json`. La comprobación quedó
`validated` con HTTP 200; esto valida la condición declarativa (CSP ausente),
no una explotación confirmada.

El Loop A también se ejecutó contra Juice Shop real: `httpx.probe` obtuvo HTTP
200, el grafo se estabilizó en dos rondas y la bitácora registró cuatro eventos.
El recibo es `runs/juice-recon-real-20261118-210744.json`; la red y el objetivo
fueron eliminados al finalizar.

Las imágenes oficiales quedaron fijadas por digest en `runtime/official_tools.py`.
Subfinder, httpx y Nuclei se ejecutaron mediante `Harness.invoke` en la red
interna. ZAP también fue invocado, pero terminó con código 3 por un problema de
acceso al resumen de la imagen; no se lo acredita como scan exitoso. El detalle
está en `docs/revision-tecnica-20261119.md`.
El recibo reproducible de la última corrida es
`runs/juice-official-scans-final-20261118-212810.json`.

## Revisión y archivo

La [demo de defensa](guion-entrega.md) reúne cinco recibos reales previos
sin acceso a red. El gate recalcula el hash del informe antes de exportar y
las evals aplican tres mutaciones dirigidas. Esto no sustituye la ejecución
conjunta de A/B/C, una bitácora persistente de esas corridas ni una prueba de
importación en DefectDojo.

El usuario informó una revisión favorable de sus compañeros. Falta asociarla a
un commit o snapshot, anotar los tests ejecutados y registrar observaciones o
ausencia de ellas. `002` y `003` se mantienen abiertos hasta esa confirmación e
integración; la copia previa no constituye el archivo formal de OpenSpec.

**Por confirmar con el docente:** si acepta el loop y el sandbox documental
además de la evidencia histórica, y qué adaptadores y checkpoints exige para
considerar completo el trabajo. La demo y la defensa se preparan al final.
