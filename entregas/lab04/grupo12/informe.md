# Informe — Laboratorio 04 · Marcos normativos y gestión

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la estructuración, fundamentación metodológica y redacción técnica de los puntos **A.1** (elección y justificación del marco) y **A.2** (mapeo formal de debilidades a controles oficiales de ISO/IEC 27001:2022 Anexo A).
- **Partes originadas o modificadas:** Secciones A.1 y A.2 de la Parte A.
- **Verificación humana:** Se contrastó la taxonomía y codificación de controles contra la versión oficial de la norma **ISO/IEC 27001:2022 (Anexo A)**, verificando que los identificadores (`A.5.17`, `A.5.24`, `A.8.5`, `A.8.13`, `A.8.26`, etc.) correspondan a la norma real y respondan de forma directa a cada debilidad del escenario de PhantomCorp.

---

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido y justificación

Para el escenario de **PhantomCorp** seleccionamos el marco **ISO/IEC 27001:2022** (Sistema de Gestión de Seguridad de la Información — SGSI), específicamente aplicando los controles de su **Anexo A** revisado.

#### Justificación:
1. **Naturaleza crítica de los activos de información:** PhantomCorp procesa y almacena datos personales (nombres, DNI) e información financiera altamente sensible (números de tarjetas de crédito). Este tipo de activos exige un nivel de cumplimiento riguroso. En el plano legal argentino rige la Ley 25.326 de Protección de Datos Personales, y en el plano financiero internacional la tenencia de datos de tarjetas impone el alineamiento con el estándar PCI-DSS (Payment Card Industry Data Security Standard). ISO/IEC 27001 es el estándar internacionalmente reconocido por auditores, bancos y procesadores de pago para acreditar la debida diligencia (*due diligence*) y un gobierno formal de la seguridad.
2. **Cobertura integral (Gobernanza + Personas + Física + Tecnología):** A diferencia de marcos orientados casi exclusivamente a la operación técnica o defensiva (como NIST CSF o guías de CIS), ISO/IEC 27001:2022 estructura sus controles en 4 dimensiones integrales:
   - *Organizacionales* (Cláusula 5)
   - *Personas* (Cláusula 6)
   - *Físicos* (Cláusula 7)
   - *Tecnológicos* (Cláusula 8)
   
   En el escenario de PhantomCorp, las vulnerabilidades detectadas no son meras fallas de configuración de software: abarcan la ausencia de políticas y procedimientos (falta de política de contraseñas y falta de plan de respuesta a incidentes), riesgos físicos y de continuidad (backups almacenados únicamente en un disco local en la oficina) y debilidades operativas/tecnológicas (acceso remoto sin MFA, servidor web expuesto). ISO 27001 permite abordar todas estas facetas bajo un único sistema de gestión con mejora continua (ciclo PDCA: Plan-Do-Check-Act).
3. **Certificación y valor reputacional para el negocio:** Como empresa comercial que custodia medios de pago, la certificación externa bajo ISO 27001 brinda una garantía verificable ante clientes y socios comerciales de que la organización gestiona el riesgo de manera metódica y no improvisada, reduciendo la responsabilidad civil y penal frente a incidentes.

---

### A.2 — Mapeo de debilidades a controles del marco (ISO/IEC 27001:2022)

Analizando el escenario de PhantomCorp, se identifican y mapean **cinco debilidades críticas** a sus respectivos controles normativos oficiales:

| # | Debilidad identificada en PhantomCorp | Control oficial ISO/IEC 27001:2022 (Anexo A) | Dominio / Categoría | Descripción y aplicación al escenario |
|---|---|---|---|---|
| **1** | **Empleados con acceso remoto sin MFA (autenticación multifactor)** | **A.8.5 — Autenticación segura** *(Secure authentication)* <br> *(Complementado por A.6.7 Trabajo remoto)* | Controles tecnológicos (A.8) / Personas (A.6) | **Problema:** Los empleados acceden remotamente con un único factor (probablemente usuario y contraseña). Si las credenciales son comprometidas mediante phishing, reutilización o keylogger, el atacante obtiene acceso directo a la red interna.<br>**Aplicación del control:** A.8.5 exige implementar autenticación multifactor (MFA) obligatoria para todo acceso remoto y para cuentas con privilegios. A.6.7 exige además asegurar el canal de comunicación mediante VPN cifrada y control de la postura del endpoint del teletrabajador. |
| **2** | **Ausencia de política de contraseñas formal** | **A.5.17 — Información de autenticación** *(Authentication information)* <br> *(Complementado por A.5.1 Políticas de seguridad de la información)* | Controles organizacionales (A.5) | **Problema:** Sin directivas institucionales, los empleados eligen contraseñas predecibles, cortas o reutilizadas, y no existen controles de rotación basada en compromiso ni bloqueo ante ataques de fuerza bruta.<br>**Aplicación del control:** A.5.17 regula el ciclo de vida de las contraseñas: longitud mínima obligatoria (mínimo 12-14 caracteres), verificación contra listas de contraseñas vulneradas, bloqueo tras sucesivos intentos fallidos (*rate limiting*), almacenamiento seguro exclusivamente con funciones hash con salt adaptativas (ej. Argon2id, PBKDF2) y prohibición de compartir o hardcodear credenciales. |
| **3** | **Servidor web público expuesto con datos sensibles (nombres, DNI, tarjetas)** | **A.8.26 — Requisitos de seguridad de las aplicaciones** *(Application security requirements)* <br> *(Complementado por A.8.11 Enmascaramiento de datos y A.8.24 Criptografía)* | Controles tecnológicos (A.8) | **Problema:** El servidor web expuesto hacia Internet procesa y/o almacena directamente datos personales y números de tarjeta, quedando susceptible a vulnerabilidades web (OWASP Top 10: SQLi, RCE, IDOR) que pueden exponer la base de datos completa.<br>**Aplicación del control:** A.8.26 exige definir e implementar controles de seguridad en las aplicaciones web (validación de entradas, WAF, segmentación de base de datos en red interna aislada A.8.22). A.8.11 y A.8.24 exigen además que los números de tarjeta (PAN) y DNI sean tokenizados o cifrados en reposo con algoritmos aprobados (ej. AES-256), de modo que si el servidor web sufre una intrusión, los datos no estén legibles en texto claro. |
| **4** | **Backups almacenados únicamente en un disco físico en la oficina** | **A.8.13 — Copias de seguridad de la información** *(Information backup)* <br> *(Complementado por A.7.1 Perímetros de seguridad física)* | Controles tecnológicos (A.8) / Físicos (A.7) | **Problema:** Existe un punto único de falla ante desastres físicos en la oficina (incendio, inundación, robo físico del disco) o ataques de ransomware en la red local que cifren tanto el servidor como el disco conectado, destruyendo la disponibilidad operativa.<br>**Aplicación del control:** A.8.13 exige respaldos periódicos siguiendo la regla 3-2-1: copias geográficamente separadas (*off-site* o almacenamiento cloud inmutable), cifradas de extremo a extremo, protegidas contra escritura/borrado, y con ensayos periódicos documentados de restauración de datos. A.7.1 y A.7.4 exigen resguardo físico y control de acceso al medio de almacenamiento. |
| **5** | **Ausencia de un plan de respuesta a incidentes de seguridad** | **A.5.24 — Planificación y preparación de la gestión de incidentes** *(Information security incident management planning and preparation)* <br> *(Complementado por A.5.26 Respuesta a incidentes)* | Controles organizacionales (A.5) | **Problema:** Ante una brecha de seguridad (filtración de tarjetas de crédito o intrusión en el servidor), la organización no sabe cómo actuar, quién toma las decisiones, cómo aislar los sistemas comprometidos ni cómo preservar evidencia forense o notificar a los afectados.<br>**Aplicación del control:** A.5.24 y A.5.26 exigen diseñar un protocolo formal de respuesta a incidentes: matriz de roles y responsabilidades (CSIRT interno o de guardia), procedimientos técnicos de detección y contención, cadena de custodia de evidencia digital, protocolos de comunicación interna/externa y cumplimiento de plazos legales de reporte ante autoridades y titulares de los datos. |

---

### A.3 — Respuestas al riesgo para cada debilidad *(Pendiente — a completar por el equipo)*

*Para cada una de las 5 debilidades mapeadas arriba, indicar la respuesta al riesgo elegida (**mitigar**, **transferir**, **aceptar**, o **evitar**) junto con su correspondiente **justificación técnica y económica**.*

1. **Debilidad 1 (Acceso remoto / MFA):**
   - *Respuesta al riesgo:* `[COMPLETAR: ej. Mitigar / Justificación]`
2. **Debilidad 2 (Política de contraseñas):**
   - *Respuesta al riesgo:* `[COMPLETAR]`
3. **Debilidad 3 (Servidor web / Datos de tarjetas expuestos):**
   - *Respuesta al riesgo:* `[COMPLETAR]`
4. **Debilidad 4 (Backups en disco local en oficina):**
   - *Respuesta al riesgo:* `[COMPLETAR]`
5. **Debilidad 5 (Plan de respuesta a incidentes):**
   - *Respuesta al riesgo:* `[COMPLETAR]`

---

## 2. Parte B — Riesgo cuantitativo *(Pendiente — a completar por el equipo)*

### B.1 — Ranking por ALE
*Completar `src/riesgo.py` (`ale`, `roi_control`, `priorizar`), armar `riesgos.json` con al menos 4 riesgos del escenario, correr `python3 src/riesgo.py priorizar --archivo riesgos.json` y analizar el ranking obtenido.*

- `[COMPLETAR: Ranking y análisis intuitivo vs cuantitativo]`

### B.2 — ROI del control para el riesgo #1
- *Control propuesto:* `[COMPLETAR]`
- *Costo estimado anual:* `[COMPLETAR]`
- *ALE antes vs ALE después:* `[COMPLETAR]`
- *Cálculo de ROI y decisión justificada:* `[COMPLETAR]`

### B.3 — Riesgo con respuesta Aceptar o Transferir
- *Riesgo seleccionado:* `[COMPLETAR]`
- *Respuesta elegida:* `[COMPLETAR: Aceptar o Transferir]`
- *Justificación (costo de mitigación vs exposición residual):* `[COMPLETAR]`

---

## 3. Anexo — riesgos.json *(Pendiente — a completar por el equipo)*

```json
[
  // A completar con al menos 4 riesgos: {"nombre": "...", "sle": ..., "aro": ...}
]
```
