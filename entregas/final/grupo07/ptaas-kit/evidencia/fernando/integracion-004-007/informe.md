# Informe técnico PTES §7

## Resumen ejecutivo
Engagement eng-lab-001: 1 hallazgos. Procedencia: sandbox.
La severidad requiere revisión humana; no se calcula score CVSS numérico.

## Alcance y metodología
Solo laboratorio autorizado; tokens por fase, catálogo inerte y gate humano.
## Límites
Fixture: sin tráfico. Sender restringido: sin aislamiento por contenedor. No se evalúa un LLM en vivo.

## Hallazgos
## Procedencia por fase
- recon: fixtures sintéticas con ReconLoop (004)
- correlation: snapshots offline con Correlator (005)
- analysis: fixtures sintéticas con DetectionLoop (005)
- validation_seed: candidato CSP manual para demo, sin CVE inferida
- audit: memoria + export JSON; SQLite 002 pendiente
- correlation_result: 0 coincidencias CVE
- analysis_result: inconclusive
### F-CSP-001 — Ausencia de CSP (candidato manual; validación sandbox)
Activo: dvwa.lab.test
Ausencia de CSP (candidato manual; validación sandbox). Estado: validado en sandbox. Procedencia: sandbox. CWE-693. CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N. EPSS: unknown. Referencias: 83db7822fe3a1ec7c3f52af1ab20e4b9a633aef8a8ff265f9249d76a1db0d09c. Severidad Info provisional hasta valoración humana.
Remediación: Definir y verificar Content-Security-Policy según la aplicación.

## Conclusión y divulgación
Priorizar revisión humana de los hallazgos. Divulgar únicamente al responsable del laboratorio; sin datos crudos ni secretos.