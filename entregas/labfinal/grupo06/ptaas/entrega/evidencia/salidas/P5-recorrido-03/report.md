# Informe de pentest — lab-p5-20261119-01

- Versión: 1
- Hash del informe: 0a7387dd5be51077965676d40a213c50004da08ec9013618520ae057927b85b6
- Cabeza de la bitácora: e065b4392f43b985bfae579e3df225794b715d85624024f57fc5fb925c9e8b22
- Procedencia de las etapas: analysis=real, recon=real, validation=real

## Resumen ejecutivo
Se documentan 8 hallazgos: 5 validados en sandbox y 3 no validados, según la bitácora del engagement.
Este inventario no demuestra ausencia de vulnerabilidades fuera de la evidencia registrada.

## Alcance y RoE
- Activos: dvwa.lab.test, juiceshop.lab.test
- Ventana: 2026-11-19T12:00:00+00:00 – 2026-11-20T02:00:00+00:00
- Exclusiones: ninguna
- Referencia RoE: Acta de autorización, Villa María, 18/11/2026

## Metodología
Estructura de presentación PTES §7. El estado de validación de cada hallazgo se toma de la bitácora del loop C; la estructura no acredita por sí sola ejecución completa de PTES, NIST SP 800-115 u OWASP WSTG.
Vectores CVSS v4.0: asignado por el analista: tabla zap\_mapping.yaml aprobada por Martin Beccereca el 2026-11-19; no proviene de NVD (sin CVE).

## Hallazgos priorizados
Orden: EPSS conocido descendente; unknown al final. No se infiere puntaje CVSS.

### DVWA-ZAP-10009 — In Page Banner Information Leak
- Activo: dvwa.lab.test
- CWE-497 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: no validado — fuera del catálogo
- Verificación: NINGUNA vNone
- Unificado con: DVWA-ZAP-10036
- Remediación: Configure the server to prevent such information leaks. For example: Under Tomcat this is done via the &quot;server&quot; directive and implementation of custom error pages. Under Apache this is done via the &quot;ServerSignature&quot; and &quot;ServerTokens&quot; directives.
- Evidencia (bitácora): 4b1a9b1aef66ddcb593b8295a693ca1c2a21d7b1c7f3d70619b8f5aa190ce2fd, 0288c8a0ba600db2c703aeab827f0403fafc3a5be4fad78252c7bba29d7bfa47

### DVWA-ZAP-10010 — Cookie No HttpOnly Flag
- Activo: dvwa.lab.test
- CWE-1004 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-COOKIE-001 v1.0.0
- Remediación: Ensure that the HttpOnly flag is set for all cookies.
- Evidencia (bitácora): 9e379b5d6719d22485cec1e8a9381ed38c1d8811774cb11478f22a8d2bda3e40, 6f7ed1a6f4c167fab6046d2bd6b3ff4947c42df0e06f63495e18aabc3979dd1d, e401cff08b00d1d3e1ebe315f6dde45c55eacb500924c291c99e00b1fa5260cd

### DVWA-ZAP-10020 — Missing Anti-clickjacking Header
- Activo: dvwa.lab.test
- CWE-1021 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-HDR-001 v1.0.0
- Remediación: Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app. If you expect the page to be framed only by pages on your server (e.g. it&\#x27;s part of a FRAMESET) then you&\#x27;ll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy&\#x27;s &quot;frame-ancestors&quot; directive.
- Evidencia (bitácora): 12c606dd648fd035f7b52016a1008d97e00110f733f04a2482de1e87cce5ccba, ccdca42e319ad6b3ec76554da01be7e28671256eebe01451bcec70a5bb3b64cf, 3015a6f9959cdc0102b9210663be823dcea593f288faed8f47c6499f9af562b5

### DVWA-ZAP-10021 — X-Content-Type-Options Header Missing
- Activo: dvwa.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: no validado — fuera del catálogo
- Verificación: NINGUNA vNone
- Remediación: Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to &\#x27;nosniff&\#x27; for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
- Evidencia (bitácora): d0e80446679f21265844dac1c249a4d26e645f40f99cf2a839a50e1de2eb37dd

### DVWA-ZAP-10023 — Information Disclosure - Debug Error Messages
- Activo: dvwa.lab.test
- CWE-1295 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: no validado — no se observó la debilidad
- Verificación: POC-ERRDISC-001 v1.0.0
- Remediación: Disable debugging messages before pushing to production.
- Evidencia (bitácora): 1e5724dfd4440e985690a1585254196564102c4f367baeecdb3949dabd273701, 539fca847a48596d629ea2244655d68f56ad8365fb84e09c1ff6ce363bc26834, 3198bd33f3d286aa4b292a117d178038e521fecd8865f3f47fce32d9a071617a

### DVWA-ZAP-10038 — Content Security Policy (CSP) Header Not Set
- Activo: dvwa.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-CSP-001 v1.0.0
- Remediación: Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
- Evidencia (bitácora): 65b3a8323f61022c48b5b7279832d39d8468a7cdbafe64710978530166030256, 05ff870312a7ef10536b4d93fd7cd9dc49aed38c82a5385e3bb22786376663d3, 9bee61fcfbe168f9e0e875060df99df9d2201a8ecaef8c205c5a9740ed1ef888

### DVWA-ZAP-10054 — Cookie without SameSite Attribute
- Activo: dvwa.lab.test
- CWE-1275 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-COOKIE-001 v1.0.0
- Remediación: Ensure that the SameSite attribute is set to either &\#x27;lax&\#x27; or ideally &\#x27;strict&\#x27; for all cookies.
- Evidencia (bitácora): 776b4e3ea22037a0ff8f4d7e70dc53fb76625855c9f1b327ed682cb1f76d03ce, fdb1b017248f8c559468743a27c2b7f5e6c0d62750e49700b0c1d85d53d5d820, 6d98c464b48142f7187fe3d0b1b1057bb1b667eab5b39920c97e5637d62b2c7c

### JUICESHOP-ZAP-10038 — Content Security Policy (CSP) Header Not Set
- Activo: juiceshop.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-CSP-001 v1.0.0
- Remediación: Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
- Evidencia (bitácora): 362820082727e940d27fa217040ee2e0ce5c748083049f0aa443b1d3280f95ca, ae676ff86f64889c09a7681d1e2fc227c5a308028bd90d3663c29fb72aefd711, e065b4392f43b985bfae579e3df225794b715d85624024f57fc5fb925c9e8b22

## Divulgación
Manejo según ISO/IEC 29147; los datos ausentes en el RoE figuran como unknown.
- Receptor: Responsable del laboratorio (grupo 06)
- Canal: unknown
- Fecha de entrega: unknown
- Plazo de remediación: unknown

## Anexos
- Inventario de activos: dvwa.lab.test, juiceshop.lab.test
- Cabeza de la bitácora: e065b4392f43b985bfae579e3df225794b715d85624024f57fc5fb925c9e8b22
