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
- **Alcance de la asistencia:** Asistencia en la estructuración, fundamentación metodológica y redacción técnica de los puntos **A.1** (elección y justificación del marco), **A.2** (mapeo formal de debilidades a controles oficiales de ISO/IEC 27001:2022 Anexo A) y **A.3** (decisiones de mitigación/transferencia); en la **Parte B** —implementación de `src/riesgo.py` (`ale`, `roi_control`, `priorizar`), armado de `riesgos.json` y redacción del análisis cuantitativo de **B.1** (ranking por ALE), **B.2** (ROI del control para el riesgo #1) y **B.3** (análisis de respuesta al riesgo: Transferir y Aceptar vs mitigar según costo y ALE); y en la redacción técnica del mini-research sobre **ISO/IEC 27001: qué es un SGSI y el ciclo PDCA** en `research.md`.
- **Partes originadas o modificadas:** Secciones A.1 y A.2 de la Parte A (@gerbaudo19); Sección A.3 de la Parte A (@matiasmariatticasc); de la Parte B, el código `src/riesgo.py`, el archivo `riesgos.json` y las secciones **B.1**, **B.2** y **B.3** (@ColqueAlvaro); y archivo `research.md`.
- **Verificación humana:** Se contrastó la taxonomía y codificación de controles contra la versión oficial de la norma **ISO/IEC 27001:2022 (Anexo A)**, verificando que los identificadores (`A.5.17`, `A.5.24`, `A.8.5`, `A.8.13`, `A.8.26`, etc.) correspondan a la norma real y respondan de forma directa a cada debilidad del escenario de PhantomCorp. Además, los cálculos de la Parte B se validaron ejecutando `python3 src/verificar.py` (3/3 en verde) y `python3 src/riesgo.py` (`ale`, `roi`, `priorizar`), confirmando los valores del ranking (ALE #1 = 100000) y del ROI del control (1.800). En B.3 se fundamentó cuantitativa y cualitativamente la decisión de Transferir mediante ciberseguros y Aceptar cuando el costo del control supera la pérdida anualizada esperada (ROI negativo). En el mini-research se corroboraron las citas de ISO/IEC 27001:2022, ISO/IEC 27002:2022 y CISSP CBK.

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

### A.3 — Respuestas al riesgo para cada debilidad

*Para cada una de las 5 debilidades mapeadas arriba, se detalla la respuesta al riesgo elegida (**mitigar**, **transferir**, **aceptar**, o **evitar**) junto con su correspondiente **justificación técnica y económica**.*

1. **Debilidad 1 (Acceso remoto / MFA):**
   - *Respuesta al riesgo:* **Mitigar**.
   - *Justificación técnica y económica:* El costo de implementar MFA usando aplicaciones estándar (ej. Google Authenticator) y librerías gratuitas es casi nulo (solo horas de configuración inicial). Sin embargo, el impacto de una intrusión a la red interna (SLE) y su frecuencia debido al phishing (ARO alto) hacen que el riesgo sin mitigar sea altísimo. El WAF no frena a un empleado legítimo con contraseña robada, pero el MFA sí. El ROI de esta mitigación es inmediato y masivo.
2. **Debilidad 2 (Política de contraseñas):**
   - *Respuesta al riesgo:* **Mitigar**.
   - *Justificación técnica y económica:* Configurar directivas en el proveedor de identidad para forzar longitud mínima, bloquear contraseñas comunes (diccionarios) y limitar intentos fallidos (*rate limiting*) tiene costo económico $0, solo requiere decisión de gestión (A.5.17). Aceptar este riesgo es inadmisible y anularía la cobertura de cualquier póliza de ciberseguro por negligencia básica.
3. **Debilidad 3 (Servidor web / Datos de tarjetas expuestos):**
   - *Respuesta al riesgo:* **Mitigar** (y evitar parcialmente si es posible).
   - *Justificación técnica y económica:* Almacenar números de tarjeta en texto claro en un servidor público expone a la empresa a multas millonarias de PCI-DSS y demandas colectivas (Ley 25.326). Aceptar el riesgo es imposible legalmente. Se debe invertir (WAF, cifrado y segmentación de red) a pesar de su costo ($25.000 calculados en B.2), ya que el ROI supera el 180%. Opcionalmente, se podría **evitar** el riesgo tercerizando por completo la captura de la tarjeta (usando un iframe de MercadoPago/Stripe) para que el dato tóxico nunca toque el servidor de PhantomCorp.
4. **Debilidad 4 (Backups en disco local en oficina):**
   - *Respuesta al riesgo:* **Transferir** (complementado con una mitigación base).
   - *Justificación técnica y económica:* Como se analizó en la sección B.3, mitigar el riesgo catastrófico creando un centro de datos físico redundante (*hot site*) tiene un ROI negativo por su alto costo operativo ($60.000/año). La mejor decisión es **transferir** el riesgo principal contratando un ciberseguro contra ransomware/desastres que cubra lucro cesante, y aplicar una mitigación barata: copias de seguridad cifradas en la nube (ej. AWS S3 Glacier), cumpliendo con el control A.8.13 a bajo costo mensual.
5. **Debilidad 5 (Plan de respuesta a incidentes):**
   - *Respuesta al riesgo:* **Mitigar**.
   - *Justificación técnica y económica:* Desarrollar un protocolo y asignar roles (A.5.24) no requiere adquirir hardware ni licencias costosas, sino una inversión de tiempo interno (horas de personal o consultoría). Cuando ocurra una brecha, no saber cómo aislar los equipos ni a quién llamar multiplica exponencialmente el impacto (SLE) por el *downtime*. Tener el plan documentado garantiza una contención rápida que disminuye drásticamente las pérdidas del negocio frente a cualquier incidente.

---

## 2. Parte B — Riesgo cuantitativo

### B.1 — Ranking por ALE

Con `src/riesgo.py` implementado y `riesgos.json` cargado (5 riesgos del escenario de
la Parte A), `python3 src/riesgo.py priorizar --archivo riesgos.json` devuelve:

| # | Riesgo | SLE | ARO | ALE |
|--:|---|---:|---:|---:|
| 1 | Brecha de datos de tarjetas por servidor web público expuesto | 200000 | 0.50 | **100000** |
| 2 | Robo de cuentas por acceso remoto sin MFA | 80000 | 0.60 | 48000 |
| 3 | Credential stuffing por contraseñas débiles o reutilizadas | 60000 | 0.80 | 48000 |
| 4 | Ransomware que cifra el servidor y el backup local en oficina | 150000 | 0.30 | 45000 |
| 5 | Filtración de DNI de clientes (Ley 25.326) | 40000 | 0.40 | 16000 |

**¿Coincide con la intuición?** En parte. Sí coincide en que la **brecha de datos de
tarjetas** encabece el ranking: es el activo más sensible (PCI-DSS, datos financieros),
con una probabilidad alta por tratarse de un servidor web público sin mitigaciones. Es
el riesgo que "a ojo" también pondríamos primero.

**¿Dónde NO coincide?** En dos lugares, y es lo valioso del análisis cuantitativo:

1. **El ransomware asusta más de lo que el ALE lo posiciona.** Intuitivamente se
   percibe como el escenario catastrófico (cifra todo, incluido el backup). Pero su
   ARO es bajo (0.30: exige que el atacante entre, ejecute y llegue al disco antes de
   detectarlo), así que termina **cuarto (45000)**, por debajo de dos riesgos que
   "se sienten" menores. El miedo no se traduce 1:1 en pérdida anualizada.
2. **Dos riesgos muy distintos empatan (48000).** El robo de cuentas sin MFA y el
   credential stuffing tienen impacto muy distinto por evento (SLE 80000 vs 60000),
   pero el segundo es más frecuente (ARO 0.80 vs 0.60) y quedan iguales. Esto revela
   que **frecuencia e impacto se compensan**: una política de contraseñas + MFA ataca
   *ambos* a la vez, y por eso es una inversión con doble recompensa que el ranking
   hace visible y la intuición tendería a subestimar.

### B.2 — ROI del control para el riesgo #1

Riesgo **#1** del ranking: *brecha de datos de tarjetas por servidor web expuesto*
(ALE = 100000).

- **Control propuesto:** defensa en profundidad sobre el servidor web y el dato de
  tarjeta: **WAF** (filtrado de intentos de explotación), **segmentación de red** para
  aislar el servidor público de la base de datos de tarjetas, y **tokenización** de los
  números de tarjeta en base de datos (de modo que, aun con acceso, los PAN no estén en
  claro). Impacto: baja el ARO de **0.50 a 0.15** (no elimina el riesgo, lo reduce).
- **Costo estimado anual:** **$25.000** (licencia WAF administrado + horas de
  implementación/segmentación amortizadas + tokenización, mantenimiento incluido).
- **ALE antes vs ALE después:**
  - ALE antes = `200000 × 0.50 = ` **$100.000**
  - ALE después = `200000 × 0.15 = ` **$30.000**
- **Cálculo de ROI** (`roi_control`, verificado con
  `python3 src/riesgo.py roi --antes 100000 --despues 30000 --costo 25000`):

  `ROI = (pérdida evitada − costo) / costo = ((100000 − 30000) − 25000) / 25000 =` **1.800**

- **Decisión justificada:** el ROI de **1.8** significa que, por cada $1 invertido, se
  evitan $1,80 de pérdida anualizada (retorno del 180%). Como es **mayor a 0, el control
  se paga solo** y sobra margen: **conviene mitigar**. Conviene, además, porque ataca el
  riesgo #1 del ranking y arrastra un beneficio de cumplimiento (alineación con PCI-DSS),
  lo que reduce también la exposición a sanciones. Si el costo se duplicara y aún así el
  ROI siguiera >0, la decisión no cambiaría; recién por encima de un costo de ~$70.000/año
  el ROI se volvería negativo y habría que reconsiderar el alcance del control.

### B.3 — Riesgo con respuesta Aceptar o Transferir

- **Riesgo seleccionado:** *Riesgo #4 — Ransomware que cifra el servidor y el backup local en oficina* (SLE = $150.000, ARO = 0.30, ALE = $45.000).
- **Respuesta elegida:** **Transferir** (complementada con la **aceptación** del riesgo residual).
- **Justificación técnica y cuantitativa:**
  1. **Límites de la mitigación técnica y costo desproporcionado:**
     Implementar controles técnicos básicos (como backups inmutables en la nube según el control A.8.13) mitiga parte de la amenaza, pero **no elimina el riesgo catastrófico residual** (*tail risk*): la interrupción prolongada del negocio, la destrucción de equipamiento físico en la oficina por siniestro o la extorsión avanzada. Construir un centro de procesamiento de datos alternativo con redundancia geográfica total en tiempo real (*hot site* tolerante a desastres físicos y ransomware) exigiría una inversión anual superior a $60.000. Al contrastar ese costo contra el ALE de $45.000:
     $$\text{ROI} = \frac{(45.000 - 10.000) - 60.000}{60.000} = -0.416 \quad (-41.6\%)$$
     El ROI es negativo: gastar $60.000 anuales para contener una pérdida esperada de $45.000 destruye valor económico para PhantomCorp.
  2. **Por qué la transferencia es la decisión correcta:**
     En lugar de incurrir en costos de mitigación desmedidos, la organización decide **transferir el impacto financiero residual** contratando una **póliza de ciberseguro (*Cyber Risk Insurance*)** especializada con una prima anual de **$7.500/año**. La póliza transfiere contractualmente a la aseguradora la cobertura de hasta $200.000 ante eventos de ransomware, cubriendo costos de peritaje forense externo, remediación de infraestructura, honorarios legales, multas y el lucro cesante por interrupción operativa (*Business Interruption*).
  3. **Cuándo corresponde Aceptar (análisis comparativo):**
     Para el **Riesgo #5 (Filtración de DNI de clientes, ALE inicial = $16.000)**, una vez aplicadas las políticas de autenticación y cifrado en base de datos, el ALE residual desciende a unos $3.000/año. Adquirir una suite corporativa de *Data Loss Prevention* (DLP) con monitoreo 24/7 que cuesta $15.000 anuales tendría un ROI negativo de $-0.83$. En esa instancia, la decisión técnicamente fundada es **aceptar formalmente el riesgo residual**: el costo del control supera con creces la exposición monetaria esperada, por lo que la dirección aprueba asumir el impacto eventual en lugar de sobredimensionar el presupuesto de seguridad.

---

## 3. Anexo — riesgos.json

Archivo completo en [`riesgos.json`](./riesgos.json) (5 riesgos del escenario):

```json
[
  { "nombre": "Brecha de datos de tarjetas por servidor web público expuesto", "sle": 200000, "aro": 0.5 },
  { "nombre": "Robo de cuentas por acceso remoto sin MFA",                    "sle": 80000,  "aro": 0.6 },
  { "nombre": "Credential stuffing por contraseñas débiles o reutilizadas",    "sle": 60000,  "aro": 0.8 },
  { "nombre": "Ransomware que cifra el servidor y el backup local en oficina","sle": 150000, "aro": 0.3 },
  { "nombre": "Filtración de DNI de clientes (Ley 25.326)",                   "sle": 40000,  "aro": 0.4 }
]
```
