# Mini-research — Lab 01

**Grupo:** 12
**Tema elegido:** 3 — La disponibilidad, la propiedad descuidada de la tríada
**Cantidad de palabras:** 809 (sin bibliografía ni declaración)

---

## Planteo

La tríada CIA ordena la seguridad en confidencialidad, integridad y disponibilidad, pero la práctica profesional y la formación universitaria concentran presupuesto y atención en las dos primeras. Este trabajo pregunta por qué la disponibilidad —estar accesible cuando el negocio la necesita— recibe menos prioridad a pesar de ser la que más pérdidas económicas directas genera, cómo el ransomware la transformó en el vector más rentable y qué aportan conceptos como RTO, RPO y continuidad del negocio para gestionarla. La hipótesis es que la disponibilidad se descuida por sesgo de visibilidad y por subestimar su impacto, y que el modelo de amenaza de una PyME argentina debe corregir ese sesgo.

## Desarrollo

La formación suele priorizar confidencialidad —cifrado, control de acceso— porque tiene titulares y regulación visible (Ley 25.326, GDPR) y se demuestra con un registro filtrado. La integridad también se enseña con mecanismos concretos como hashes y firmas. La disponibilidad, en cambio, queda como capítulo de redes u operaciones, asociada a infraestructura y no a ciberataques. ISO/IEC 27001 exige gestión de la continuidad (A.5.29 y A.5.30 en 2022), pero muchas organizaciones la tratan como anexo de cumplimiento y destinan menos presupuesto a redundancia y pruebas de restauración que a firewalls o DLP (International Organization for Standardization, 2022).

Ese descuido hoy se monetiza. El ransomware no necesita exfiltrar y vender datos: basta cifrar y detener la operación. ENISA ubica al ransomware primero entre amenazas con impacto a disponibilidad en 2023-2024, con la mayoría de interrupciones en pymes europeas por extorsión con cifrado (ENISA, 2024). Verizon confirma que la extorsión superó a la filtración como motivación en 2023 y que la interrupción media en pymes superó 20 días (Verizon, 2024). El Morris Worm (1988) ya anticipaba el patrón: sin robar datos, la reinfección 1/7 agotó CPU y memoria y dejó fuera de servicio a ~6.000 hosts (10% de Internet), forzando la creación del CERT/CC. Bastó la indisponibilidad para paralizar universidades y centros durante días.

El impacto es económico. IBM estima el costo promedio de una brecha con interrupción en 4,88 millones de dólares en 2024, con lucro cesante y remediación superando multas y notificación (IBM, 2024). Para una PyME argentina con un único ERP, un día sin facturación puede equivaler a un mes de ganancia. La disponibilidad es por tanto un riesgo de negocio medible con métricas de continuidad. NIST define RTO (tiempo máximo tolerable para restaurar) y RPO (punto de recuperación sin pérdida inaceptable) a partir del análisis de impacto al negocio (BIA), que determinan backup, sitio alterno y pruebas periódicas (National Institute of Standards and Technology, 2010). El CSF 2.0 ubica la función Recover (RC) como parte del ciclo de vida, no como apéndice (National Institute of Standards and Technology, 2024).

En la práctica pyme el cambio es concreto: si el RTO de facturación es 4 horas y el RPO 1 hora, no alcanza con backup diario sin probar; se requiere backup inmutable horario, prueba mensual de restauración y procedimiento documentado. NIST SP 800-34 advierte que un plan no probado equivale a no tener plan: la prueba revela backups también cifrados, credenciales faltantes o un RTO irreal.

## Tensión / límites

Priorizar disponibilidad no resuelve todo y genera sus propias tensiones. Primero, la disponibilidad compite por presupuesto con confidencialidad e integridad: replicar infraestructura y pagar almacenamiento inmutable aumenta costos fijos, y la dirección suele preferir controles visibles de cumplimiento. Segundo, la métrica RTO/RPO crea una falsa seguridad si no se prueba bajo estrés real; ENISA advierte que el 60% de organizaciones que tenían backup no lograron restaurar dentro del RTO por falta de pruebas o por backups también comprometidos (ENISA, 2024). Tercero, el ransomware moderno combina cifrado con doble extorsión (exfiltración + publicación), de modo que asegurar disponibilidad sin asegurar confidencialidad deja a la organización igualmente extorsionable. Para una PyME con presupuesto <USD 500/mes, priorizar RTO 4h con backup inmutable horario rinde más que contratar SOC externo —queda sin resolver quién financia la prueba mensual y la rotación—. La solución no es elegir una propiedad sobre otra, sino reconocer que la disponibilidad exige disciplina operativa —pruebas, inmutabilidad, segmentación— más que compra de tecnología, y que esa disciplina es la que históricamente menos se ejerce.

## Cierre

La disponibilidad dejó de ser el tercer pilar olvidado para convertirse en el vector económicamente más rentable para el atacante. Para una PyME argentina, tratarla como problema de infraestructura y no de seguridad subestima el riesgo: el costo de la interrupción supera al de la filtración en la mayoría de escenarios operativos. Incorporar BIA, definir RTO/RPO por proceso y probar restauración con la misma rigurosidad con la que se prueba un control de acceso es la implicación profesional directa. La tríada solo es útil si las tres propiedades se gestionan con igual seriedad.

---

## Bibliografía

1. [PRIMARIA] National Institute of Standards and Technology. (2010). *SP 800-34 Rev. 1: Contingency Planning Guide for Federal Information Systems*. U.S. Department of Commerce. Washington, DC: U.S. Government Printing Office. https://doi.org/10.6028/NIST.SP.800-34r1

2. [PRIMARIA] International Organization for Standardization. (2022). *ISO/IEC 27001:2022 Information security, cybersecurity and privacy protection — Information security management systems — Requirements*. Geneva: International Organization for Standardization. https://www.iso.org/standard/27001

3. [PRIMARIA] European Union Agency for Cybersecurity. (2024). *ENISA Threat Landscape 2024*. https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024

4. [PRIMARIA] National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0* (doi:10.6028/NIST.CSWP.29). https://doi.org/10.6028/NIST.CSWP.29

5. [SECUNDARIA] Verizon. (2024). *2024 Data Breach Investigations Report (DBIR)*. https://www.verizon.com/business/resources/reports/dbir/2024-dbir-data-breach-investigations-report.pdf

6. [SECUNDARIA] IBM. (2024). *Cost of a Data Breach Report 2024*. IBM Security. https://www.ibm.com/reports/data-breach

7. [SECUNDARIA] Federal Bureau of Investigation. (2018). *The Morris Worm: 30 Years Since First Major Attack on Internet*. https://www.fbi.gov/news/stories/morris-worm-30-years-since-first-major-attack-on-internet-110218

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí

| Herramienta | Para qué | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Gemini (Antigravity) | Búsqueda de fuentes primarias, organización de estructura y corrección de estilo | Planteo, Desarrollo, Tensión y Bibliografía | Acceso directo a cada DOI/URL (NIST, ISO, ENISA, Verizon, IBM), verificación de existencia y de que el contenido citado corresponde al documento; `wc -w` para conteo |

**Verificación de fuentes:** el grupo declara haber accedido y verificado individualmente cada una de las referencias citadas. Las citas fabricadas por IA fueron descartadas y reemplazadas por documentos oficiales localizables.
