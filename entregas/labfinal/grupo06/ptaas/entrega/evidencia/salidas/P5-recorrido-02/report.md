# Informe de pentest — lab-p5-20261118-01

> **DEMO** — contiene etapas simuladas (analysis). No es un resultado de pentest y no se puede entregar ni exportar.

- Versión: 1
- Hash del informe: 02cc4153e9c155769cd84d20576d9b74685ca8db5b253578364e6320cf0ec1fe
- Cabeza de la bitácora: 7b8f1c008e5df51018f81ec8f9b3151be504ab54533f2718108ab1c20fd319c6
- Procedencia de las etapas: analysis=fixture, recon=real, validation=real

## Resumen ejecutivo
Se documentan 4 hallazgos: 3 validados en sandbox y 1 no validados, según la bitácora del engagement.
Este inventario no demuestra ausencia de vulnerabilidades fuera de la evidencia registrada.

## Alcance y RoE
- Activos: dvwa.lab.test, juiceshop.lab.test
- Ventana: 2026-11-18T12:00:00+00:00 – 2026-11-19T02:00:00+00:00
- Exclusiones: ninguna
- Referencia RoE: Acta de autorización, Villa María, 18/11/2026

## Metodología
Estructura de presentación PTES §7. El estado de validación de cada hallazgo se toma de la bitácora del loop C; la estructura no acredita por sí sola ejecución completa de PTES, NIST SP 800-115 u OWASP WSTG.

## Hallazgos priorizados
Orden: EPSS conocido descendente; unknown al final. No se infiere puntaje CVSS.

### DVWA-COOKIE — Cookie de sesión sin flags Secure / HttpOnly / SameSite
- Activo: dvwa.lab.test
- CWE-614 · CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-COOKIE-001 v1.0.0
- Remediación: Emitir la cookie de sesión con Secure, HttpOnly y SameSite=Strict
- Evidencia (bitácora): 4b30445db3172e4ce07dda1f1888d34ee0fc236f8ef2497ed23c3a6841203768, 14cfb4f592e2ca207cbc0fa631d3b619f9c8bef589554f23e2e1f9e1dea1c8a4, ad26500927bc4c912e8fba3e95cea4f59a05409f004c5a607034605f36db2cac

### DVWA-CSP — Ausencia de Content-Security-Policy
- Activo: dvwa.lab.test
- CWE-693 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-CSP-001 v1.0.0
- Remediación: Definir una Content-Security-Policy restrictiva
- Evidencia (bitácora): 430df5cfc2983937c110475117d9563506721fba421c58050f7e607a81a7b947, 3825baa6082971fd0679c5ed4f024e2ec7e6423530628a3d20725e042e3a90e0, b8c7dd320a0f194798cebdec0a8bc220b2d9c68cfb6b2732e33fe1295e3de4e7

### DVWA-HDR — Falta de protección contra clickjacking
- Activo: dvwa.lab.test
- CWE-1021 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: validado en sandbox
- Verificación: POC-HDR-001 v1.0.0
- Remediación: Enviar X-Frame-Options: DENY o CSP frame-ancestors &\#x27;none&\#x27;
- Evidencia (bitácora): 22630a5b701c41e96e2eae9818a7d3eec055e7eb93c1bc4b3230a2e73cde8897, d6def8590a9dd90332944bd0e639d29e94af47c044f5bbabf264b92b3e7f84f7, 8a92fba6e02e21222db8ae189e187e4a420b75892d3956406cb33a91c486b246

### JUICE-HDR — Falta de protección contra clickjacking
- Activo: juiceshop.lab.test
- CWE-1021 · CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N · EPSS: unknown
- Puntaje CVSS: unknown (no aportado por el contrato Finding)
- Estado: no validado — no se observó la debilidad
- Verificación: POC-HDR-001 v1.0.0
- Remediación: Enviar X-Frame-Options: DENY o CSP frame-ancestors &\#x27;none&\#x27;
- Evidencia (bitácora): a312bab15133e54f6cbe0bd4567c7b1e920e9ec11e0e6f27afc027a5624e897c, 02028632e3fe4ff7bcd97c4ad770a68dcd6cecdf779c6456c4ac977f14b1d36a, 7b8f1c008e5df51018f81ec8f9b3151be504ab54533f2718108ab1c20fd319c6

## Divulgación
Manejo según ISO/IEC 29147; los datos ausentes en el RoE figuran como unknown.
- Receptor: Responsable del laboratorio (grupo 06)
- Canal: unknown
- Fecha de entrega: unknown
- Plazo de remediación: unknown

## Anexos
- Inventario de activos: dvwa.lab.test, juiceshop.lab.test
- Cabeza de la bitácora: 7b8f1c008e5df51018f81ec8f9b3151be504ab54533f2718108ab1c20fd319c6
