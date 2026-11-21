# Plantilla de divulgación coordinada (ISO/IEC 29147) — desafío D2

Change 010 (propuesto). La plantilla ordena lo que un aviso de vulnerabilidad debe
comunicar al receptor y cuándo. Abajo, completada con un hallazgo **real** de la corrida
entregada `P5-recorrido-04`. Los datos que el laboratorio no tiene (proveedor real,
canal seguro, plazos acordados) figuran como **a definir**; no se inventan.

## Plantilla

| Campo | Contenido esperado |
|---|---|
| Identificador del aviso | Único y estable entre corridas (se usa el identificador estable del hallazgo) |
| Receptor | Responsable del activo, identificado en el RoE |
| Canal | Canal acordado y confidencial; nunca un canal público |
| Activo afectado | Host, servicio y versión observados |
| Descripción | Qué se observó, sin detalles que faciliten explotarlo antes de la corrección |
| Clasificación | CWE; vector CVSS v4.0 y quién lo evaluó; EPSS si hay CVE |
| Estado de validación | Validado en sandbox / no validado, con la verificación usada |
| Impacto | Consecuencia para el negocio, en lenguaje no técnico |
| Remediación | Acción concreta y verificable |
| Evidencia | Referencias a la bitácora (hashes), nunca contenido del objetivo |
| Cronograma | Fecha de comunicación, acuse de recibo, plazo de remediación, fecha de retest y fecha de publicación (siempre posterior al plazo) |
| Contacto de seguimiento | Quién responde consultas del receptor |

## Ejemplo completado — cookie de sesión sin `HttpOnly` en DVWA

| Campo | Contenido |
|---|---|
| Identificador del aviso | `PTAAS-G06-fdb64fd3b57a711d` (identificador estable del hallazgo `DVWA-ZAP-10010`) |
| Receptor | Responsable del laboratorio (grupo 06), según el RoE `lab-p5-20261119-01` |
| Canal | **A definir** con el receptor (el laboratorio no tiene canal seguro configurado) |
| Activo afectado | `dvwa.lab.test` (DVWA del kit), servidor Apache HTTP Server 2.4.25 informado por httpx |
| Descripción | La cookie de sesión se emite sin el atributo `HttpOnly`, así que puede leerla código que corra en la página |
| Clasificación | CWE-1004 · `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`, asignado por el analista (tabla `harness/zap_mapping.yaml`, aprobada por Martin Beccereca el 2026-11-19) · EPSS: no aplica (sin CVE) |
| Estado de validación | Validado en sandbox con `POC-COOKIE-001` v1.0.0, en dos intentos consistentes |
| Impacto | Si la aplicación tuviera además una falla de inyección de scripts, un atacante podría robar sesiones activas de usuarios |
| Remediación | Emitir la cookie de sesión con `HttpOnly` (y `Secure` y `SameSite`); verificarlo con la misma verificación del catálogo |
| Evidencia | Informe `f4ef94d4…` v1; referencias de bitácora `197ad2b0…`, `8923c0ca…`, `8768f4c9…` |
| Cronograma | Comunicación: 2026-11-19 (entrega del informe). Acuse, plazo de remediación, retest y publicación: **a definir** con el receptor |
| Contacto de seguimiento | P5, coordinador de la entrega del grupo 06 |

> Lo que este ejemplo muestra que falta (y propone el change 010): el sistema entregó el
> informe con el canal y el cronograma sin definir. Con el control C1, esa entrega se
> habría rechazado hasta completar la divulgación.
