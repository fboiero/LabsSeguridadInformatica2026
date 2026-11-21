# MANIFEST — allow-list de templates de Nuclei

Única fuente de templates de `nuclei.safe_templates`. `harness/nuclei_allowlist.py`
verifica este archivo antes de cada corrida: cada template de esta carpeta tiene que
figurar acá con su SHA-256 (con finales de línea normalizados a LF) y la **segunda
aprobación** de una persona distinta de quien lo propuso. Sin eso, Nuclei no se ejecuta.

Origen: propuestas de P4 (`templates/proposed_p4/`, change 005). Sintaxis validada
por P4 con Nuclei v3.11.1 en una red sin salida (`p4-nuclei-validacion.txt`).
Revisión de cada template: un único GET, `redirects: false`, sin payloads, sin
fuzzing, sin OAST; solo compara encabezados o el cuerpo de la respuesta (inerte).
Un encabezado ausente o un formulario visible NO es por sí solo una vulnerabilidad.

| Archivo | SHA-256 | Propuso | Segunda aprobación | Fecha | Qué hace |
|---|---|---|---|---|---|
| p4-login-form-visible.yaml | c755b285d7af33267df97c0304bf885ef092080e71f8d73d19caca0f491d4be7 | Maria Belen Benito (P4) | Martin Beccereca (P5) | 2026-11-19 | GET `/login.php`; coincide si responde 200 con un `<form` |
| p4-security-header-csp.yaml | d3edb3b8ffef3f328336e870de669fa32a84fb2e3fe6acde9f087551e0f0dba3 | Maria Belen Benito (P4) | Martin Beccereca (P5) | 2026-11-19 | GET `/`; coincide si responde 200 sin `Content-Security-Policy` |
| p4-security-header-x-content-type-options.yaml | af938535c8839f62076632844a2dd07cbdcc7248a485622418f622edf5a8f29d | Maria Belen Benito (P4) | Martin Beccereca (P5) | 2026-11-19 | GET `/`; coincide si responde 200 sin `X-Content-Type-Options` |
| p4-security-header-x-frame-options.yaml | 31e02c05b0506a7d4bc265afae94cf461e00d422251930d4f3a029ad9a273993 | Maria Belen Benito (P4) | Martin Beccereca (P5) | 2026-11-19 | GET `/`; coincide si responde 200 sin `X-Frame-Options` |
| p4-server-header-present.yaml | ab17ff8ea112cc96deb025162061095022121077b349a8c9b350f66de0a86b84 | Maria Belen Benito (P4) | Martin Beccereca (P5) | 2026-11-19 | GET `/`; coincide si responde 200 con encabezado `Server` |
