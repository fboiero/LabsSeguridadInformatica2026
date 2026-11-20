# Informe técnico PTES §7

## Resumen ejecutivo
Engagement eng-lab-001: 1 hallazgos. Procedencia: sandbox.
La severidad requiere revisión humana; no se calcula score CVSS numérico.

## Alcance y metodología
Solo laboratorio autorizado; tokens por fase, catálogo inerte y gate humano.
## Límites
Fixture: sin tráfico. Sender restringido: sin aislamiento por contenedor. No se evalúa un LLM en vivo.

## Hallazgos
### F-CSP-001 — Ausencia de CSP (candidato fixture; validación sandbox)
Activo: dvwa.lab.test
Ausencia de CSP (candidato fixture; validación sandbox). Estado: validado en sandbox. Procedencia: sandbox. CWE-693. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N. EPSS: unknown. Referencias: b048519b64132b9cd728d9320326f61d4fafa18078aef9fbe10d0d8ff77c4356. Severidad Info provisional hasta valoración humana.
Remediación: Definir y verificar Content-Security-Policy según la aplicación.

## Conclusión y divulgación
Priorizar revisión humana de los hallazgos. Divulgar únicamente al responsable del laboratorio; sin datos crudos ni secretos.