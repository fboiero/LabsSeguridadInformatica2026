# Informe de pentest — lab-p5-20261119-01

- Versión: 1
- Hash del informe: f4ef94d4893947131ab01dcda490fcd8f0d05d3a1ae05e6c123ed6e0ea82c3af
- Cabeza de la bitácora: 5fe1b16fbb5f87d02813cd7d38574ee33b2f2eeea431fa86d60ba58db62ec5ef
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
- Remediación: Configure the server to prevent such information leaks. For example: Under Tomcat this is done via the &quot;server&quot; directive and implementation of custom error pages. Under Apache this is done via the &quot;ServerSignature&quot; and &quot;ServerTokens&quot; directives.
- Evidencia (bitácora): 5cb9b686d443603f96ceddcdf698def36bf153f770bd5631e1c5cc918157811a

### DVWA-ZAP-10010 — Cookie No HttpOnly Flag
- Activo: dvwa.lab.test
- CWE-1004 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-COOKIE-001 v1.0.0
- Remediación: Ensure that the HttpOnly flag is set for all cookies.
- Evidencia (bitácora): 197ad2b0e081960cbaa5e70e0de4d46de357381d77ca0881f08fec7af2d086ca, 8923c0ca91d9648f9ef1ac5134fc0c665e8dbdf992018bd4de5d3241645ed3a8, 8768f4c925611cc71f7eb1e8e6fd7533bc1542729676a95b65add046c747194b

### DVWA-ZAP-10020 — Missing Anti-clickjacking Header
- Activo: dvwa.lab.test
- CWE-1021 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-HDR-001 v1.0.0
- Remediación: Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app. If you expect the page to be framed only by pages on your server (e.g. it&\#x27;s part of a FRAMESET) then you&\#x27;ll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy&\#x27;s &quot;frame-ancestors&quot; directive.
- Evidencia (bitácora): cff82fdb331c61d8d0f36fd505004692a13c06d3e6dae08ddd131dcf469ae22b, 6d3ee626258a910f3259c13d3b39f68f1604ad8a4f7f43e018a163e2c5d34766, 7b99075e7a6e294e75630bd55b59f0cacea9f7be8ac618dc6cdf69bea3fcd83b

### DVWA-ZAP-10021 — X-Content-Type-Options Header Missing
- Activo: dvwa.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: no validado — fuera del catálogo
- Remediación: Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to &\#x27;nosniff&\#x27; for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.
- Evidencia (bitácora): a705860e357dd59f36805623bb0cd7551d82f2091fef5a8411d08903aa24c8f0

### DVWA-ZAP-10036 — Server Leaks Version Information via &quot;Server&quot; HTTP Response Header Field
- Activo: dvwa.lab.test
- CWE-497 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: no validado — fuera del catálogo
- Remediación: Ensure that your web server, application server, load balancer, etc. is configured to suppress the &quot;Server&quot; header or provide generic details.
- Evidencia (bitácora): 7899b6f12ca4dbe1567f3b4e1ac2c7b31272f3aeb1825b6309bcd7389df852a5

### DVWA-ZAP-10038 — Content Security Policy (CSP) Header Not Set
- Activo: dvwa.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-CSP-001 v1.0.0
- Remediación: Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
- Evidencia (bitácora): ef7f66a332360156179604eaf5d92c27cd0ddcd27f2de32d6593abb3648bea63, 5ab3fa54e50e371d2d37e42206971884a71b6df5d045de4c6669a42581de87ce, af3fe5d65231842471d090fa40976f54093e4d1dc43a33b0612cafa516c3312a

### DVWA-ZAP-10054 — Cookie without SameSite Attribute
- Activo: dvwa.lab.test
- CWE-1275 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-COOKIE-001 v1.0.0
- Remediación: Ensure that the SameSite attribute is set to either &\#x27;lax&\#x27; or ideally &\#x27;strict&\#x27; for all cookies.
- Evidencia (bitácora): 8d76aabd5957158c535fa8e05381e3d5985daf08ae8d6ef2e7bf8c15c00e41c3, a6fa942d041ea181a9ee444c5c00228e2cfa6e04bd9c0beca0e7ab8e03aa3dd5, dad3623d93acc823955057d035ee2f95ce9eb8f507f3c9a861801f6bd79df10e

### JUICESHOP-ZAP-10038 — Content Security Policy (CSP) Header Not Set
- Activo: juiceshop.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-CSP-001 v1.0.0
- Remediación: Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.
- Evidencia (bitácora): cc8a694563af30abab384f728a39a482ee03ea8c2cb7c030e3a1d33573aa55ce, 073c7634dc6cb52cf37441ee6045e5f19c6529bd9c0343114e233dae39603ecd, 5fe1b16fbb5f87d02813cd7d38574ee33b2f2eeea431fa86d60ba58db62ec5ef

## Divulgación
Manejo según ISO/IEC 29147; los datos ausentes en el RoE figuran como unknown.
- Receptor: Responsable del laboratorio (grupo 06)
- Canal: unknown
- Fecha de entrega: unknown
- Plazo de remediación: unknown

## Anexos
- Inventario de activos: dvwa.lab.test, juiceshop.lab.test
- Cabeza de la bitácora: 5fe1b16fbb5f87d02813cd7d38574ee33b2f2eeea431fa86d60ba58db62ec5ef
