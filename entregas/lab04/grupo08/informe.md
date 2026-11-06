# Informe — Laboratorio 04 · Marcos normativos y gestión

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 16 de octubre de 2026

---

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

Usamos asistentes de IA (Claude, de Anthropic, y Antigravity, de Google) como herramientas de apoyo técnico y metodológico durante el desarrollo del laboratorio, con los siguientes fines:

- **Revisión y consulta de marcos normativos**: contrastación de los controles del Anexo A de la norma internacional **ISO/IEC 27001:2022** (y su guía de implementación **ISO/IEC 27002:2022**), las funciones y categorías del **NIST Cybersecurity Framework (CSF 2.0)**, y su correspondencia con exigencias regulatorias (Ley 25.326 de Protección de Datos Personales, Ley 26.388 de Delitos Informáticos y estándar PCI-DSS v4.0).
- **Estructuración y análisis de tratamiento de riesgos**: evaluación rigurosa de las cuatro respuestas frente al riesgo (*mitigar, transferir, aceptar, evitar*) aplicadas al caso de estudio de PhantomCorp, verificando que las decisiones respondan a criterios económicos, operativos y de gobierno corporativo reales.
- **Redacción técnica**: asistencia en la formulación clara, estructurada y académica del informe.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo verificamos el resultado |
|---|---|---|---|
| Claude (Anthropic) y Antigravity (Google) | Consulta de taxonomía de controles ISO/IEC 27001:2022 y NIST CSF, estructuración de argumentos de gobierno de seguridad y redacción técnica | Sección 1 (Parte A) | Se verificó manualmente cada código y denominación de control contra el texto oficial de la norma ISO/IEC 27001:2022 (Anexo A) y el catálogo de NIST CSF 2.0. Se validó que las respuestas al riesgo no incurrieran en la simplificación de "mitigar todo", sino que reflejaran estrategias combinadas y justificadas. |
| Claude (Anthropic) | Revisión de la Parte A (corrección de categorías de NIST CSF que no existen en la versión 2.0, afirmaciones sin fuente y agregado de fuentes); implementación de `src/riesgo.py`; borrador de la Parte B y del mini-research. | Secciones 1, 2 y 3, `src/riesgo.py`, `riesgos.json` y `research.md` | Corrimos `src/verificar.py` (3/3 OK) y los ejemplos del enunciado (`20000.00` y `0.875`). Todos los números de la Parte B salen de correr `src/riesgo.py`, y los SLE/ARO son estimaciones que el grupo discutió y puede justificar. Abrimos cada fuente citada para confirmar que existe. |

El grupo declara que comprende en su totalidad los conceptos, justificaciones y mapeos volcados en esta entrega.

---

## 1. Parte A — Aplicación del marco

### A.1 — Qué marco elegiste y por qué

Para el análisis y gobierno de la seguridad en **PhantomCorp**, elegimos como marco rector la norma internacional **ISO/IEC 27001:2022** (*Information security, cybersecurity and privacy protection — Information security management systems — Requirements*), complementada en el mapeo operativo con el catálogo de directrices de **ISO/IEC 27002:2022** y cruzada referencialmente con las funciones del **NIST Cybersecurity Framework (CSF 2.0)**.

#### Justificación de la elección

1. **Naturaleza crítica de los activos y exposición regulatoria/contractual:**
   PhantomCorp almacena y procesa información altamente sensible: **datos de identificación personal** (nombres, DNI) y **datos financieros transaccionales** (tarjetas de crédito). 
   - En la República Argentina, el tratamiento de datos personales está tutelado por la **Ley 25.326** y las resoluciones de la Agencia de Acceso a la Información Pública (AAIP, e.g. Resolución 47/2018 sobre medidas de seguridad recomendadas), que exigen la adopción de medidas técnicas y organizativas para garantizar la confidencialidad e integridad.
   - El almacenamiento de datos de titulares de tarjetas de pago somete a la organización a las exigencias contractuales de las marcas de tarjetas (**PCI-DSS v4.0**).
   - A diferencia de NIST CSF —un marco voluntario que nació para infraestructura crítica y que en su versión 2.0 se amplió a organizaciones de cualquier tipo, pero que no tiene un esquema de certificación formal [2]—, **ISO/IEC 27001 es un estándar internacional certificable por terceros independientes** [1]. Para una empresa que maneja datos de clientes, la certificación es una forma verificable de demostrar su nivel de seguridad ante bancos, procesadores de pago y clientes corporativos, que suelen pedirla o valorarla al contratar.

2. **Enfoque en Sistema de Gestión (SGSI) y Ciclo de Mejora Continua (PDCA):**
   PhantomCorp presenta un estado de desgobierno absoluto: no tiene políticas de contraseñas, no tiene MFA y no cuenta con plan de respuesta a incidentes. El problema de PhantomCorp no se soluciona únicamente comprando herramientas tecnológicas aisladas, sino estableciendo un **Sistema de Gestión de la Seguridad de la Información (SGSI)** sustentado en el ciclo PDCA (*Plan-Do-Check-Act* / Planificar-Hacer-Verificar-Actuar):
   - **Cláusulas 4 a 10 de ISO 27001:** obligan a definir el alcance organizacional, el compromiso de la alta dirección (liderazgo y asignación presupuestaria), la metodología formal de evaluación y tratamiento de riesgos (alineada con ISO 31000), auditorías internas periódicas y la revisión por la dirección.

3. **Taxonomía moderna y adaptada a la operatoria híbrida (Anexo A versión 2022):**
   La actualización de ISO/IEC 27001:2022 reestructuró los controles en **4 dominios temáticos integrales** (37 Controles Organizacionales, 8 de Personas, 14 Físicos y 34 Tecnológicos), introduciendo controles específicos que abordan con precisión quirúrgica las vulnerabilidades de PhantomCorp:
   - Control A.5.34 para la privacidad de PII (alineado con ISO/IEC 27701).
   - Control A.6.7 para la seguridad en el teletrabajo / trabajo remoto.
   - Control A.8.5 para autenticación segura en arquitecturas web y remotas.
   - Control A.5.24 para la planificación y respuesta estructurada ante incidentes.

---

### A.2 — Mapeo de debilidades del escenario a controles del marco

A partir del escenario provisto, identificamos y mapeamos **cinco debilidades críticas** a los controles normativos correspondientes de ISO/IEC 27001:2022 (con su correlato en funciones/categorías de NIST CSF 2.0 para enriquecer la trazabilidad):

```
+----------------------------------------------------------------------------------------------------+
|                                    MAPEO DE DEBILIDADES                                            |
+----+---------------------------------------+-----------------------------+-------------------------+
| #  | Debilidad del Escenario               | Control ISO/IEC 27001:2022  | Función / Cat. NIST CSF |
+----+---------------------------------------+-----------------------------+-------------------------+
| 1  | Almacenamiento local de tarjetas,     | A.5.34 (Protección PII)     | PROTECT (PR.DS)         |
|    | DNI y nombres en servidor público     | A.8.24 (Uso de criptografía)| IDENTIFY (ID.RA)        |
+----+---------------------------------------+-----------------------------+-------------------------+
| 2  | Empleados con acceso remoto           | A.8.5 (Autenticación segura)| PROTECT (PR.AA)         |
|    | sin autenticación multifactor (MFA)   | A.6.7 (Trabajo remoto)      |                         |
+----+---------------------------------------+-----------------------------+-------------------------+
| 3  | Inexistencia de política de           | A.5.17 (Info. autenticación)| PROTECT (PR.AA)         |
|    | contraseñas y gestión de credenciales | A.5.15 (Control de acceso)  |                         |
+----+---------------------------------------+-----------------------------+-------------------------+
| 4  | Backups almacenados únicamente en un  | A.8.13 (Copias de seguridad)| PROTECT (PR.DS)         |
|    | disco físico local en la oficina      | A.7.10 (Medios almacenam.)  | RECOVER (RC.RP)         |
|    |                                       | A.5.29 (Seg. en interrupción|                         |
+----+---------------------------------------+-----------------------------+-------------------------+
| 5  | Ausencia de plan de respuesta a       | A.5.24 (Planif. incidentes) | RESPOND (RS.MA / RS.AN) |
|    | incidentes y monitoreo de intrusiones | A.5.26 (Respuesta incident.)| DETECT (DE.AE / DE.CM)  |
|    |                                       | A.5.28 (Recolec. evidencia) |                         |
+----+---------------------------------------+-----------------------------+-------------------------+
```

#### Detalle analítico por debilidad:

1. **Debilidad 1: Almacenamiento local de datos de tarjetas de crédito y datos personales (nombres, DNI) en un servidor web público.**
   - *Riesgo asociado:* Inyección SQL, vulnerabilidad de aplicación web o compromiso del sistema operativo que permita a un atacante externo exfiltrar la base de datos completa. La exposición de números de tarjeta (PAN) y códigos de seguridad (CVV) genera multas directas de adquirentes/marcas de tarjetas, clausura de procesamiento comercial, demandas por fraude de clientes y sanciones de la autoridad de protección de datos (AAIP) bajo la Ley 25.326.
   - *Controles ISO/IEC 27001:2022:*
     - **Control A.5.34 — Privacidad y protección de información de identificación personal (PII):** exige establecer directrices y medidas organizativas y técnicas para salvaguardar los datos personales según las leyes aplicables.
     - **Control A.8.24 — Uso de criptografía:** define el deber de cifrar los datos sensibles tanto en tránsito (TLS 1.3) como en reposo (AES-256), con gestión segura de claves criptográficas.
   - *Equivalencia NIST CSF 2.0:* Función **PROTECT**, Categoría **PR.DS** (*Data Security*), subcategorías `PR.DS-01` (protección de datos en reposo) y `PR.DS-02` (protección de datos en tránsito).

2. **Debilidad 2: Empleados con acceso remoto y total ausencia de autenticación multifactor (MFA).**
   - *Riesgo asociado:* Intrusión a la red interna mediante ataques de fuerza bruta, ingeniería social (spear-phishing), interceptación de tráfico o relleno de credenciales (*credential stuffing*) utilizando bases de datos filtradas en la web. Sin un segundo factor de autenticación, el compromiso de un único par usuario/contraseña otorga a un atacante acceso con privilegios de red privada, facilitando el reconocimiento interno y movimiento lateral.
   - *Controles ISO/IEC 27001:2022:*
     - **Control A.8.5 — Autenticación segura:** exige implementar tecnologías y procedimientos de autenticación segura según las restricciones de acceso a la información. La guía de implementación (ISO/IEC 27002:2022) recomienda autenticación multifactor cuando se trata de información o sistemas críticos, como los accesos remotos y administrativos.
     - **Control A.6.7 — Trabajo remoto:** requiere implementar medidas de seguridad técnicas y organizativas para el acceso a la información corporativa fuera de las instalaciones físicas (dispositivos gestionados, canales cifrados VPN/Zero Trust).
   - *Equivalencia NIST CSF 2.0:* Función **PROTECT**, Categoría **PR.AA** (*Identity Management, Authentication and Access Control*), subcategoría `PR.AA-03` (identidades verificadas con MFA para accesos externos y con privilegios).

3. **Debilidad 3: Inexistencia de política de contraseñas.**
   - *Riesgo asociado:* Elección de contraseñas triviales por parte de usuarios y administradores (`123456`, `Phantom2026!`), reutilización de contraseñas personales, falta de detección de credenciales previamente comprometidas y ausencia de almacenamiento seguro en los sistemas internos (e.g. almacenamiento en texto plano o con hashes débiles como MD5/SHA-1 sin salt), facilitando el descifrado masivo mediante tablas rainbow o ataques de diccionario.
   - *Controles ISO/IEC 27001:2022:*
     - **Control A.5.17 — Información de autenticación:** exige regular y parametrizar la creación, distribución, robustez y ciclo de vida de los secretos de autenticación.
     - **Control A.5.15 — Control de acceso:** determina que el acceso a la información y recursos debe ser concedido y restringido bajo políticas claras de necesidad de saber (*need-to-know*) y mínimo privilegio.
   - *Equivalencia NIST CSF 2.0:* Función **PROTECT**, Categoría **PR.AA**, subcategoría `PR.AA-01` (gestión del ciclo de vida de credenciales e información de autenticación).

4. **Debilidad 4: Backups almacenados únicamente en un disco físico en la oficina.**
   - *Riesgo asociado:* Pérdida irreversible de la información institucional y de clientes ante contingencias físicas (incendio, inundación, sobretensión eléctrica, robo o extravío del disco externo) o lógicas (infección por malware/ransomware que alcance volúmenes conectados localmente y destruya o cifre las copias). Al residir en el mismo dominio de falla físico que la oficina, la empresa carece de resiliencia operativa y capacidad de recuperación ante desastres (DRP).
   - *Controles ISO/IEC 27001:2022:*
     - **Control A.8.13 — Copias de seguridad de la información:** exige la realización sistemática de copias de respaldo de datos, software e imágenes de sistemas, probando periódicamente su restauración y manteniéndolas en ubicaciones remotas y medios aislados.
     - **Control A.7.10 — Medios de almacenamiento:** requiere la protección física y lógica de los medios extraíbles contra acceso no autorizado, daño o robo.
     - **Control A.5.29 — Seguridad de la información durante una interrupción:** establece que la organización debe planificar la continuidad de la seguridad para mantener la disponibilidad de los activos ante fallas mayores.
   - *Equivalencia NIST CSF 2.0:* Función **PROTECT** (`PR.DS-11`: backups probados, aislados e inmutables) y Función **RECOVER**, Categoría **RC.RP** (`RC.RP-01`: ejecución de planes de recuperación).

5. **Debilidad 5: Inexistencia de plan de respuesta a incidentes (IRP) ni capacidades de monitoreo.**
   - *Riesgo asociado:* Tiempo de permanencia (*dwell time*) indefinido de intrusos dentro de la red corporativa sin ser detectados. Ante una intrusión evidente, la respuesta improvisada genera pánico operativo, apagado indebido de servidores con destrucción irrevocable de evidencia volátil en RAM (impidiendo el peritaje forense judicial), propagación descontrolada de la amenaza, incumplimiento del plazo legal de reporte de brechas de datos e indemnizaciones comerciales desproporcionadas.
   - *Controles ISO/IEC 27001:2022:*
     - **Control A.5.24 — Planificación y preparación de la gestión de incidentes de seguridad de la información:** obliga a la organización a documentar procesos, roles, cadenas de mando y canales de comunicación para responder ante eventos de seguridad.
     - **Control A.5.26 — Respuesta a incidentes de seguridad de la información:** establece la ejecución coordinada de acciones de contención, erradicación y recuperación.
     - **Control A.5.28 — Recolección de evidencia:** requiere identificar, recolectar, adquirir y preservar evidencia digital asegurando su cadena de custodia legalmente válida.
   - *Equivalencia NIST CSF 2.0:* Función **RESPOND**, Categorías **RS.MA** (*Incident Management*) y **RS.AN** (*Incident Analysis*), y Función **DETECT**, Categoría **DE.AE** (*Anomalies and Events*).

---

### A.3 — Respuesta al riesgo elegida con justificación

La gestión profesional del riesgo no consiste en "mitigar todo" con tecnología indiscriminada. Una organización con recursos finitos debe balancear el costo de los controles contra el valor del activo y el impacto financiero real. Frente a las debilidades analizadas, aplicamos y justificamos las cuatro estrategias fundamentales: **Evitar, Mitigar, Transferir y Aceptar**.

```
+----------------------------------------------------------------------------------------------------+
|                               ESTRATEGIAS DE RESPUESTA AL RIESGO                                   |
+----+--------------------------------------------+-----------------------+--------------------------+
| #  | Escenario / Activo                         | Respuesta al Riesgo   | Mecanismo de Aplicación  |
+----+--------------------------------------------+-----------------------+--------------------------+
| 1  | Datos de tarjetas de crédito en servidor   | EVITAR (Avoid)        | Tokenización externa     |
|    |                                            | + TRANSFERIR (Transf.)| Pasarela PCI-DSS Nivel 1 |
+----+--------------------------------------------+-----------------------+--------------------------+
| 2  | Empleados con acceso remoto sin MFA        | MITIGAR (Mitigate)    | Despliegue de MFA FIDO2  |
|    |                                            |                       | y TOTP en VPN corporativa|
+----+--------------------------------------------+-----------------------+--------------------------+
| 3  | Falta de política de contraseñas           | MITIGAR (Mitigate)    | Política NIST 800-63B    |
|    |                                            |                       | y gestor de contraseñas  |
+----+--------------------------------------------+-----------------------+--------------------------+
| 4  | Backups en disco físico único en oficina   | TRANSFERIR (Transfer) | Cloud Backup inmutable   |
|    |                                            | + MITIGAR (Mitigate)  | Regla 3-2-1 con WORM/SLA |
+----+--------------------------------------------+-----------------------+--------------------------+
| 5  | Brecha catastrófica / Daños financieros    | TRANSFERIR (Transfer) | Póliza de Ciberseguro    |
|    | e improvisación operativa en incidentes    | + MITIGAR (Mitigate)  | IRP formal + Playbooks   |
+----+--------------------------------------------+-----------------------+--------------------------+
| 6  | Indisponibilidad residual no crítica       | ACEPTAR (Accept)      | Tolerancia documentada   |
|    | en servidor web fuera de horario pico      |                       | en análisis de BIA       |
+----+--------------------------------------------+-----------------------+--------------------------+
```

#### Justificaciones detalladas:

#### 1. Datos de tarjetas de crédito de clientes: EVITAR (Avoid) y TRANSFERIR (Transfer)
- **Decisión:** **EVITAR** completamente el almacenamiento, procesamiento y transmisión directa de números de tarjetas de crédito (PAN) y códigos de verificación (CVV) en los servidores propios de PhantomCorp. En su lugar, se **transfiere** la operatoria transaccional a un proveedor de servicios de pago (*Payment Service Provider* / PSP) certificado como **PCI-DSS Service Provider Level 1** (e.g. Stripe, MercadoPago o Checkout.com).
- **Justificación:**
  Intentar *mitigar* este riesgo internamente exigiría convertir la infraestructura de PhantomCorp en una fortaleza conforme a los cientos de requisitos técnicos y físicos de PCI-DSS v4.0 [3] (segmentación estricta de red, hardware HSM para cifrado de claves, escaneos trimestrales ASV, auditoría QSA externa anual), incurriendo en costos de implementación y mantenimiento que superan con creces el presupuesto operativo de la empresa.
  Al integrar el servidor web mediante formularios encapsulados seguros (*Hosted Fields* o *iFrames tokenizados* provistos por el PSP), los datos de las tarjetas viajan directamente desde el navegador del cliente a los servidores del proveedor de pagos sin tocar la memoria, disco ni red de PhantomCorp. A cambio, PhantomCorp solo almacena un *token* pseudoaleatorio no reversible y no sensible. 
  Esta estrategia **evita de raíz** la existencia del activo tóxico en los servidores propios, reduciendo el alcance de cumplimiento al cuestionario simplificado **PCI-DSS SAQ A**, eliminando el pasivo penal y civil por robo de tarjetas y transfiriendo el riesgo transaccional al procesador de pagos. Para los datos personales restantes (DNI y nombres), que sí deben conservarse por motivos fiscales y legales, se aplica mitigación técnica (cifrado en reposo con AES-256) y transferencia financiera complementaria mediante póliza de seguros.

#### 2. Acceso remoto de empleados sin segundo factor: MITIGAR (Mitigate)
- **Decisión:** **MITIGAR** mediante la imposición obligatoria de autenticación multifactor (MFA) para todas las conexiones remotas (VPN corporativa, paneles web administrativos, accesos SSH).
- **Justificación:**
  La empresa no puede *evitar* el acceso remoto porque el teletrabajo y la gestión descentralizada son indispensables para la continuidad del negocio; tampoco puede *aceptar* el riesgo, ya que las credenciales robadas o débiles son una de las vías de entrada más comunes en intrusiones y ransomware.
  La mitigación se implementa mediante llaves criptográficas físicas FIDO2/WebAuthn para personal con privilegios elevados y aplicaciones TOTP en dispositivos móviles (Google/Microsoft Authenticator bajo RFC 6238) para el resto del personal, prohibiendo taxativamente el uso de SMS o llamadas de voz debido a su vulnerabilidad probada frente a ataques de *SIM swapping* y clonación de líneas. El costo de licenciamiento y configuración de un proveedor de identidad centralizado (IdP como Keycloak u Okta) es ínfimo comparado con el valor de las pérdidas que previene: Microsoft informó que activar MFA bloquea más del 99,9 % de los ataques de compromiso de cuentas que observa [4].

#### 3. Inexistencia de política de contraseñas: MITIGAR (Mitigate)
- **Decisión:** **MITIGAR** a través del diseño, promulgación formal y aplicación técnica forzada de una política corporativa de contraseñas alineada con el estándar **NIST SP 800-63B** (*Digital Identity Guidelines: Authentication and Lifecycle Management*).
- **Justificación:**
  El uso de secretos de autenticación es consustancial al acceso a sistemas, por lo que no se puede evitar. La respuesta técnica y organizativa consiste en:
  1. Configurar una longitud mínima obligatoria de 14 caracteres, promoviendo el uso de frases de paso (*passphrases* memorables y con alta entropía).
  2. Implementar verificación automatizada en tiempo de registro contra diccionarios de contraseñas previamente comprometidas (usando la API k-anonymity de *Have I Been Pwned* o listas locales de credenciales expuestas).
  3. Eliminar la rotación periódica forzada arbitraria (e.g. cada 60 o 90 días), dado que la evidencia empírica demuestra que induce a los usuarios a introducir alteraciones predecibles (e.g. `Primavera2026!`), limitando el cambio forzado exclusivamente a incidentes confirmados de compromiso.
  4. Proveer a todos los empleados un gestor corporativo de contraseñas (e.g. Bitwarden Enterprise) para generar y custodiar credenciales únicas por servicio en bóvedas cifradas de extremo a extremo.

#### 4. Backups en disco físico único en la oficina: TRANSFERIR (Transfer) y MITIGAR (Mitigate)
- **Decisión:** Estrategia combinada: **TRANSFERIR** la custodia física, durabilidad y contingencia geográfica contratando un servicio de almacenamiento en la nube (*Cloud Storage*), y **MITIGAR** el riesgo de indisponibilidad y ransomware aplicando una política de respaldo estructurada bajo la **regla 3-2-1**.
- **Justificación:**
  Mantener los respaldos en un único disco externo en la oficina presenta un punto único de falla (*Single Point of Failure* - SPOF) inaceptable. Construir un centro de datos secundario propio fuera de las instalaciones para albergar servidores de réplica sería financieramente inviable para PhantomCorp.
  Por lo tanto, la empresa **transfiere contractualmente** la responsabilidad sobre la redundancia física y geográfica a un proveedor de nube pública (e.g. AWS S3 Glacier Flexible Retrieval / Azure Blob Storage):
  - El proveedor diseña el almacenamiento para una durabilidad del 99,999999999 % (11 nueves), y el contrato de servicio (SLA) fija un nivel de disponibilidad con créditos económicos si no se cumple [5].
  - Como control de mitigación técnica complementario, las copias enviadas a la nube se configuran con **inmutabilidad de objetos** (*Object Lock / WORM - Write Once, Read Many*) durante un período de retención mínimo (e.g. 30 días) y cifrado del lado del cliente con claves gestionadas por PhantomCorp (AES-256). Esto asegura que, aun si un ransomware destruye los datos locales y compromete credenciales administrativas, las copias en la nube no pueden ser borradas ni sobreescritas por el atacante.

#### 5. Ausencia de plan de respuesta a incidentes y contingencias mayores: MITIGAR (Mitigate) y TRANSFERIR (Transfer)
- **Decisión:** **MITIGAR** la capacidad operativa de contención desarrollando un Plan de Respuesta a Incidentes (IRP), y **TRANSFERIR** el impacto financiero catastrófico derivado de una brecha mediante la contratación de una póliza de **Seguro contra Ciberriesgos (*Cyber Insurance*)**.
- **Justificación:**
  Bajo el postulado moderno de "asumir la brecha" (*assume breach*), ninguna organización puede garantizar una probabilidad de compromiso cero.
  - La empresa **mitiga** los tiempos de detección y respuesta creando un plan formal de respuesta a incidentes con roles definidos (CSIRT interno, asesores legales, comunicación corporativa), procedimientos de preservación forense de evidencia volátil (respetando la cadena de custodia) y playbooks específicos ante ransomware, intrusión web y fuga de información.
  - Sin embargo, las consecuencias económicas de una intrusión grave (honorarios de consultoras de respuesta a incidentes forenses, asesoría legal en litigios civiles, multas regulatorias y costos de notificación a miles de clientes) pueden causar la quiebra de la compañía. Para proteger su viabilidad económica, PhantomCorp **transfiere el impacto financiero residual** suscribiendo una póliza de ciberseguro que indemnice las pérdidas operativas, rescates extorsivos no evitables, peritajes forenses externos y reclamos de terceros.

#### 6. Riesgo residual de indisponibilidad transitoria en el servidor web público: ACEPTAR (Accept)
- **Decisión:** **ACEPTAR** formalmente el riesgo residual de indisponibilidad temporal no crítica (por ejemplo, tiempos de inactividad programados para mantenimiento o microcortes de conectividad inferiores a 15 minutos mensuales fuera de horario comercial).
- **Justificación:**
  Alcanzar una disponibilidad del 99.999% ("cinco nueves") requeriría diseñar una arquitectura redundante multirregión activa-activa en múltiples proveedores cloud con balanceadores de carga globales de tipo Anycast, cuyo costo superaría con creces los 10.000 USD mensuales. 
  Dado que PhantomCorp no opera un servicio médico de soporte vital ni un sistema financiero en tiempo real, el impacto financiero de una interrupción menor de algunos minutos fuera de hora punta es despreciable frente al costo de mitigarla. Por tanto, la Alta Dirección aprueba, documenta y asume formalmente este riesgo residual en el Registro de Riesgos del SGSI, estableciendo un objetivo de disponibilidad realista acorde al Análisis de Impacto en el Negocio (BIA).

### Fuentes (Parte A)

1. International Organization for Standardization. (2022). *ISO/IEC 27001:2022 — Information security, cybersecurity and privacy protection — Information security management systems — Requirements*. https://www.iso.org/standard/27001 — **Primaria** (norma).
2. National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0* (NIST CSWP 29). https://doi.org/10.6028/NIST.CSWP.29 — **Primaria**.
3. PCI Security Standards Council. (2022). *Payment Card Industry Data Security Standard v4.0* [Biblioteca de documentos]. https://www.pcisecuritystandards.org/document_library/ — **Primaria**.
4. Weinert, A. (2019, 20 de agosto). One simple action you can take to prevent 99.9 percent of attacks on your accounts. *Microsoft Security Blog*. https://www.microsoft.com/en-us/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/ — **Primaria** (datos del fabricante).
5. Amazon Web Services. (s. f.). *Amazon S3 Service Level Agreement*. https://aws.amazon.com/s3/sla/ — **Primaria**.
6. Argentina. (2000). *Ley 25.326 de Protección de los Datos Personales*. https://www.argentina.gob.ar/normativa/nacional/ley-25326-64790 — **Primaria**.
7. Agencia de Acceso a la Información Pública. (2018). *Resolución 47/2018: Medidas de seguridad recomendadas para el tratamiento y conservación de los datos personales*. https://www.argentina.gob.ar/normativa/nacional/resoluci%C3%B3n-47-2018-310997 — **Primaria**.

---

## 2. Parte B — Riesgo cuantitativo

Cargamos en `riesgos.json` cinco riesgos del escenario de la Parte A (ver Anexo). Los montos están en dólares y son **estimaciones del grupo**, no datos reales de PhantomCorp: el SLE (*Single Loss Expectancy*) es lo que cuesta un evento y el ARO (*Annualized Rate of Occurrence*) cuántas veces esperamos que ocurra por año. El ALE (*Annualized Loss Expectancy*) es `SLE × ARO`.

Criterios que usamos para estimar:

- **Robo de la base de clientes** (SLE 250.000, ARO 0,3): incluye respuesta forense, notificación a clientes, asesoría legal, multas de las marcas de tarjetas por exponer datos de pago y sanciones de la AAIP. Un ARO de 0,3 (un evento cada ~3 años) refleja un servidor web público sin monitoreo.
- **Ransomware** (SLE 120.000, ARO 0,25): días de operación detenida más la recuperación. Es alto porque el único backup está en un disco conectado en la oficina y probablemente también quede cifrado.
- **Compromiso de una cuenta remota** (SLE 40.000, ARO 0,5): sin MFA, una contraseña filtrada o adivinada alcanza. Es el evento más frecuente, pero acá contamos solo el daño directo del acceso.
- **Caída del servidor web** (SLE 1.500, ARO 4): unas horas sin ventas online, varias veces por año.
- **Pérdida del disco de backup** (SLE 60.000, ARO 0,05): incendio, robo o falla del disco; si coincide con una pérdida de los datos originales, no hay de dónde recuperar.

### B.1 — Ranking por ALE

```
$ python src/riesgo.py priorizar --archivo riesgos.json
      75000.00  Robo de la base de clientes (nombres, DNI y tarjetas) desde el servidor web
      30000.00  Ransomware que cifra servidores y el disco de backup conectado
      20000.00  Compromiso de una cuenta de acceso remoto por credenciales robadas (sin MFA)
       6000.00  Caida del servidor web publico por fallas o mantenimiento (pocas horas)
       3000.00  Perdida del disco de backup de la oficina (robo, incendio o falla)
```

**Dónde coincide con nuestra intuición:** que el robo de la base de clientes quede primero. Combina el activo más sensible (tarjetas y DNI) con el punto más expuesto (un servidor público), y es lo que la Parte A ya marcaba como prioridad.

**Dónde no coincide:**

1. **El disco de backup quedó último**, y nuestra intuición lo ponía alto, porque "perder todos los datos" suena catastrófico. El ALE lo baja porque el evento es raro (ARO 0,05). Pero el número esconde algo: ese disco es también lo que haría falta para recuperarse del ransomware (#2). Su valor real no está en su propia fila sino en cuánto reduce el SLE de otro riesgo. El ALE trata cada riesgo como independiente y no ve esas dependencias.
2. **El compromiso de cuenta remota quedó tercero**, y para nosotros es el más urgente: es el más probable de todos y, sobre todo, es la **puerta de entrada** de los dos primeros. Un atacante que entra con una cuenta remota es quien después roba la base o despliega el ransomware. El ranking le asigna solo el daño directo y subestima su papel como causa.
3. **La caída del servidor web** tiene un ALE mayor que la pérdida del disco (6.000 contra 3.000) aunque intuitivamente es un problema menor. Pasa porque ocurre seguido: muchos eventos chicos suman más que uno grande y raro.

La conclusión es que el ranking por ALE ordena bien qué riesgo cuesta más en promedio, pero no reemplaza el análisis: hay que mirar qué riesgos habilitan a otros y qué tan seguros estamos de cada estimación.

### B.2 — Control para el riesgo #1 y su ROI

**Control propuesto:** el mismo que elegimos en la Parte A, más un refuerzo del servidor:

1. **Tokenizar los pagos con un proveedor certificado PCI-DSS** (formularios alojados por el proveedor): PhantomCorp deja de guardar números de tarjeta. Esto **baja el SLE**, porque una filtración ya no expone datos de pago; quedan nombres y DNI, que se cifran en reposo.
2. **WAF delante del servidor web, parcheo mensual y escaneo de vulnerabilidades**: esto **baja el ARO**, porque se cierran las vías de entrada más comunes.

**Estimaciones:**

| | Antes | Después | Por qué |
|---|---:|---:|---|
| SLE | 250.000 | 80.000 | Sin tarjetas, desaparecen las multas de las marcas y el fraude; quedan forense, notificación y AAIP por los datos personales. |
| ARO | 0,3 | 0,15 | WAF y parcheo reducen a la mitad la probabilidad de una intrusión exitosa. |
| ALE | 75.000 | 12.000 | |

**Costo anual del control:** 15.000 USD (comisiones adicionales del proveedor de pagos, integración amortizada, WAF administrado y escaneos).

```
$ python src/riesgo.py ale --sle 80000 --aro 0.15
12000.00

$ python src/riesgo.py roi --antes 75000 --despues 12000 --costo 15000
3.200
```

ROI = (75.000 − 12.000 − 15.000) / 15.000 = **3,2**. Por cada dólar invertido, el control evita 3,2 dólares de pérdida esperada además de pagarse a sí mismo. **Conviene.**

Como nuestras estimaciones de ARO pueden estar infladas, probamos un escenario pesimista para el control: que el riesgo sea tres veces menos frecuente de lo que supusimos (ARO 0,1 antes y 0,05 después):

```
$ python src/riesgo.py ale --sle 250000 --aro 0.1
25000.00
$ python src/riesgo.py ale --sle 80000 --aro 0.05
4000.00
$ python src/riesgo.py roi --antes 25000 --despues 4000 --costo 15000
0.400
```

Aun así el ROI sigue siendo positivo (0,4). La decisión no depende de que nuestra estimación sea exacta, y eso la hace más sólida.

### B.3 — Un riesgo para aceptar (y uno para transferir)

**Aceptar: la caída breve del servidor web (ALE 6.000).** Mitigarlo en serio significa alta disponibilidad: servidores redundantes en más de una región con balanceo de carga, que estimamos en unos 10.000 USD por mes (120.000 por año). Aun suponiendo que eso bajara el ALE de 6.000 a 1.000:

```
$ python src/riesgo.py roi --antes 6000 --despues 1000 --costo 120000
-0.958
```

El ROI es **−0,96**: se gastarían 120.000 por año para evitar 5.000 de pérdida. Lo correcto es **aceptar** el riesgo, documentarlo en el registro de riesgos con la aprobación de la dirección y fijar un objetivo de disponibilidad realista, como dijimos en la Parte A (respuesta #6). Esto solo vale mientras el servidor no sea crítico: si PhantomCorp pasara a vender principalmente online, el SLE subiría y habría que recalcular.

**Transferir: el impacto residual del ransomware y de una brecha grave.** Aun con controles, un evento grave sigue siendo posible y su costo puede superar lo que la empresa puede absorber. Para ese residuo corresponde **transferir** con una póliza de ciberseguro: se paga una prima fija y conocida a cambio de no cargar con una pérdida grande e incierta. No reemplaza a los controles (las aseguradoras suelen exigir MFA y backups como condición), pero cubre lo que los controles no eliminan.

---

## 3. Anexo — riesgos.json

```json
[
  {"nombre": "Robo de la base de clientes (nombres, DNI y tarjetas) desde el servidor web", "sle": 250000, "aro": 0.3},
  {"nombre": "Ransomware que cifra servidores y el disco de backup conectado", "sle": 120000, "aro": 0.25},
  {"nombre": "Compromiso de una cuenta de acceso remoto por credenciales robadas (sin MFA)", "sle": 40000, "aro": 0.5},
  {"nombre": "Caida del servidor web publico por fallas o mantenimiento (pocas horas)", "sle": 1500, "aro": 4},
  {"nombre": "Perdida del disco de backup de la oficina (robo, incendio o falla)", "sle": 60000, "aro": 0.05}
]
```

Los nombres van sin tildes a propósito: `riesgo.py` abre el archivo con `open()` sin indicar codificación, y en Windows eso usa cp1252 y desfigura los caracteres UTF-8. Para no tocar la parte del esqueleto que no era un TODO, preferimos un JSON en ASCII.
