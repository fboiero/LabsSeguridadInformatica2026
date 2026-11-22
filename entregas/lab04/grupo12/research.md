# Mini-research — Laboratorio 04

**Tema elegido:**
- [x] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [ ] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [ ] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

---

## Desarrollo

### 1. ¿Qué es un SGSI (Sistema de Gestión de Seguridad de la Información)?

Un **Sistema de Gestión de Seguridad de la Información (SGSI)** —o *ISMS* por sus siglas en inglés (*Information Security Management System*)— es un enfoque sistemático, estructurado y documentado para gestionar los riesgos que amenazan la confidencialidad, integridad y disponibilidad (la tríada CID) de los activos de información dentro de una organización.

Lejos de reducirse a la adquisición de herramientas de software o hardware (firewalls, EDR, SIEM), un SGSI aborda la seguridad como un **proceso de gobernanza integral y transversal**:
- **Alineación con el negocio:** La seguridad no es un fin en sí mismo, sino una función de apoyo estratégico que protege la continuidad operativa, el valor reputacional y el cumplimiento legal (como las leyes de protección de datos personales o regulaciones del sector financiero).
- **Enfoque basado en el riesgo (*Risk-based approach*):** No existe la "seguridad absoluta". El SGSI no busca blindar todos los activos con los mismos recursos, sino identificar formalmente qué activos tienen mayor criticidad, evaluar sus amenazas y vulnerabilidades, y determinar un nivel de **riesgo aceptable** mediante un tratamiento justificado (mitigar, transferir, aceptar o evitar).
- **Separación entre requisitos normativos y controles:** La norma **ISO/IEC 27001:2022** se divide en dos componentes centrales:
  1. *Cláusulas 4 a 10:* Establecen los requisitos de gestión obligatorios (contexto de la organización, liderazgo, planificación, soporte, operación, evaluación del desempeño y mejora continua).
  2. *Anexo A (normativo):* Provee un catálogo de **93 controles de seguridad** estructurados en cuatro temas (Organizacionales, Personas, Físicos y Tecnológicos). La organización elabora la **Declaración de Aplicabilidad (*Statement of Applicability* — SoA)**, justificando qué controles del Anexo A implementa y cuáles excluye según su análisis de riesgo.

---

### 2. El Ciclo PDCA (Plan - Do - Check - Act): Motor de la Mejora Continua

La columna vertebral metodológica de las normas de gestión ISO (incluyendo ISO/IEC 27001) es el **Ciclo de Deming** o ciclo **PDCA** (*Plan-Do-Check-Act*). Su principio rector es que la seguridad es un proceso iterativo y dinámico, no un estado estático ni un proyecto con fecha de fin.

```
                  +-----------------------------------+
                  |             PLAN                  |
                  |  - Contexto y partes interesadas  |
                  |  - Política de seguridad          |
                  |  - Evaluación y trat. de riesgos  |
                  |  - Declaración de Aplicabilidad   |
                  +-----------------+-----------------+
                                    |
                                    v
+-----------------+                 |                 +-----------------+
|      ACT        |                 |                 |       DO        |
|  - Acciones     | <---------------+---------------- |  - Implementar  |
|    correctivas  |                                   |    controles    |
|  - Gestión de   |                                   |  - Concientizar |
|    cambio       |                                   |  - Operar y     |
|  - Mejora       | <---------------+---------------- |    gestionar    |
|    continua     |                 |                 |    incidentes   |
+-----------------+                 |                 +-----------------+
                                    v
                  +-----------------+-----------------+
                  |             CHECK                 |
                  |  - Auditorías internas            |
                  |  - Métricas e indicadores (KPI)   |
                  |  - Revisión por la Dirección      |
                  +-----------------------------------+
```

#### A. Fase PLAN (Planificar — Cláusulas 4, 5, 6 y 7)
- **Objetivo:** Establecer el contexto, los objetivos de seguridad y los procesos necesarios para gestionar el riesgo.
- **Acciones clave:**
  - Definición del alcance del SGSI (qué sucursales, redes y sistemas abarca).
  - Aprobación formal de la Política de Seguridad de la Información por parte de la alta dirección (Cláusula 5.2).
  - Ejecución metodológica de la evaluación de riesgos (*Risk Assessment*): identificación de activos, amenazas, vulnerabilidades, cálculo de probabilidad e impacto (cualitativo o cuantitativo como SLE/ARO/ALE).
  - Plan de Tratamiento de Riesgos (*Risk Treatment Plan*) y confección del SoA.

#### B. Fase DO (Hacer / Implementar — Cláusula 8)
- **Objetivo:** Ejecutar las decisiones y los controles planificados en el SGSI.
- **Acciones clave:**
  - Puesta en marcha de controles tecnológicos (MFA, segmentación de red, cifrado de bases de datos), físicos (controles de acceso biométrico, resguardo de servidores) y organizacionales (políticas de contraseñas, acuerdos de confidencialidad).
  - Programas de capacitación y concientización a todo el personal contra ingeniería social y phishing (control A.6.3).
  - Despliegue de procedimientos operativos y del plan formal de respuesta a incidentes de seguridad (controles A.5.24 y A.5.26).

#### C. Fase CHECK (Verificar / Evaluar — Cláusula 9)
- **Objetivo:** Monitorear, medir y auditar si el SGSI funciona según lo planificado y si los controles son realmente eficaces.
- **Acciones clave:**
  - Seguimiento de métricas de efectividad (KPIs/KRIs): tasa de éxito en simulaciones de phishing, tiempo medio de detección y respuesta (MTTD/MTTR), número de parches pendientes.
  - Ejecución de **auditorías internas periódicas** e independientes para verificar la conformidad con la norma.
  - **Revisión por la Dirección (*Management Review*):** Reuniones formales donde la alta gerencia evalúa los resultados de las auditorías, incidentes ocurridos y cambios en el entorno de amenazas para asignar recursos adicionales si se requiere.

#### D. Fase ACT (Actuar / Mejorar — Cláusula 10)
- **Objetivo:** Corregir desviaciones, responder a no conformidades e introducir mejoras permanentes al sistema.
- **Acciones clave:**
  - Análisis de causa raíz de incidentes o hallazgos de auditoría e implementación de **acciones correctivas**.
  - Ajuste del análisis de riesgo frente a la aparición de nuevas técnicas de ataque o cambios regulatorios.
  - Retroalimentación directa a la fase *Plan*, cerrando el ciclo virtuoso de maduración institucional de la ciberseguridad.

---

## Fuentes (mín. 3)

1. **International Organization for Standardization (2022).** *ISO/IEC 27001:2022 — Information security, cybersecurity and privacy protection — Information security management systems — Requirements*. Ginebra, Suiza: ISO.  
   Disponible en: https://www.iso.org/standard/27001
2. **International Organization for Standardization (2022).** *ISO/IEC 27002:2022 — Information security, cybersecurity and privacy protection — Information security controls*. Ginebra, Suiza: ISO.  
   Disponible en: https://www.iso.org/standard/75652.html
3. **Calder, A., & Watkins, S. (2019).** *IT Governance: An International Guide to Data Security and ISO27001/ISO27002* (7th Edition). Kogan Page Publishers. ISBN: 978-0749486914.
4. **Hummel, R., & Tipton, H. F. / (ISC)² (2021).** *Official (ISC)² Guide to the CISSP CBK — Domain 1: Security and Risk Management*. Sybex / Wiley.

---

## Reflexión

El estudio de ISO/IEC 27001 y del ciclo PDCA desarma una de las confusiones más dañinas en el ejercicio profesional de la informática: **creer que la seguridad se resuelve comprando tecnología o que se agota en la obtención de un certificado en la pared**.

En organizaciones con bajo nivel de madurez, suele cometerse el error de encarar la seguridad como un "evento único": se contrata un pentest anual, se instala un firewall de última generación o se redacta un manual de políticas que nadie lee, y la dirección asume que la empresa "ya está segura". Esta postura es peligrosa porque el panorama de amenazas es esencialmente dinámico: nuevas vulnerabilidades zero-day emergen a diario, los empleados rotan, las arquitecturas migran a la nube y los procesos de negocio mutan constantemente. 

El valor fundamental del ciclo PDCA radica en transformar la seguridad en un **hábito operativo continuo**:
- La fase **Check** evita que la organización caiga en la complacencia; exige evidencia empírica de si las medidas adoptadas realmente frenan incidentes o si son mero gasto cosmético.
- La fase **Act** institucionaliza el aprendizaje tras cada falla, obligando a remediar las causas estructurales en lugar de limitarse a culpar al usuario que hizo clic en un enlace malicioso.

En última instancia, un SGSI efectivo no elimina el riesgo al 100%, sino que dota a la organización de la resiliencia y el gobierno necesarios para tomar decisiones de inversión inteligentes, demostrables ante clientes y reguladores, y sostenibles a lo largo del tiempo.
