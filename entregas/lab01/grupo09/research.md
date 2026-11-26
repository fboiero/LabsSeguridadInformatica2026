# Mini-research — Lab 01

**Grupo:** 09
**Tema elegido:** 3 — La disponibilidad, la propiedad descuidada de la tríada

---

## Planteo

Cuando se habla de seguridad informática, el reflejo casi automático es pensar en datos robados: una brecha, una filtración, un titular de diario sobre millones de registros expuestos. La confidencialidad domina la conversación pública y buena parte de la formación técnica. Sin embargo, para muchas organizaciones —y de forma especialmente visible en servicios críticos como la salud— el costo real no viene de que alguien *vea* un dato, sino de que nadie pueda *usar* un sistema cuando lo necesita. Este trabajo sostiene que la disponibilidad recibe sistemáticamente menos atención de la que su impacto económico y humano justificaría, y que el ransomware fue el fenómeno que terminó de exponer esa asimetría.

## Desarrollo

La tríada CIA (confidencialidad, integridad, disponibilidad) presenta sus tres propiedades como pares conceptuales equivalentes, pero no reciben el mismo tratamiento en la práctica. La formación en seguridad suele estructurarse alrededor del control de acceso y el cifrado —mecanismos que protegen confidencialidad e integridad— mientras que la disponibilidad queda relegada a la gestión de infraestructura (IT operations), un área que históricamente no se enseña como parte del currículo de seguridad sino como una disciplina aparte de continuidad de negocio.

El ransomware cambió el cálculo económico del atacante de una forma que expuso esta brecha. El caso WannaCry (2017), analizado en la Parte A de este informe, es ilustrativo: el ataque no robó ni alteró datos de forma encubierta, simplemente los volvió inaccesibles mediante cifrado. El impacto documentado por la National Audit Office del Reino Unido en su investigación sobre el NHS no fue una fuga de historiales médicos, sino la cancelación de miles de citas y procedimientos porque los sistemas clínicos dejaron de estar disponibles (National Audit Office, 2017). Monetizar la *indisponibilidad* —en vez de monetizar el dato robado, que requiere encontrar comprador— resultó ser, para el atacante, más simple, más rápido y más escalable: alcanza con que la víctima misma pague para recuperar el acceso a lo que ya era suyo.

El panorama de amenazas más reciente confirma que esto no fue un episodio aislado sino una tendencia consolidada. El informe *ENISA Threat Landscape 2024*, de la Agencia de la Unión Europea para la Ciberseguridad, que cubre el período de julio de 2023 a junio de 2024, ubica a las **amenazas contra la disponibilidad** (ataques de denegación de servicio) como la categoría de amenaza más prevalente del período, con el ransomware inmediatamente después en segundo lugar (ENISA, 2024). Es decir: las dos amenazas dominantes del ecosistema actual atacan directamente la misma propiedad de la tríada que menos espacio ocupa en la formación técnica tradicional.

Esta brecha entre impacto real y atención formativa tiene un correlato conceptual preciso en la gestión de continuidad de negocio. El NIST, en su *SP 800-34 Rev. 1 — Contingency Planning Guide for Federal Information Systems*, formaliza dos métricas que cualquier organización debería definir para cada sistema crítico: el **RTO** (*Recovery Time Objective*), que establece cuánto tiempo de inactividad es tolerable antes de que el daño se vuelva inaceptable, y el **RPO** (*Recovery Point Objective*), que establece cuánta pérdida de datos —medida en tiempo desde el último respaldo válido— es tolerable (NIST, 2010). Estas métricas no son un ejercicio teórico: son la traducción operativa de la disponibilidad en un número que una organización puede planificar, presupuestar y probar. El mismo documento del NIST advierte que el RTO debe ser necesariamente menor que el **MTD** (*Maximum Tolerable Downtime*), la frontera a partir de la cual la interrupción deja de ser recuperable para el negocio. Un hospital que nunca calculó su RTO para los sistemas de turnos no tiene forma objetiva de decidir si vale la pena pagar un rescate, reconstruir desde backups, u operar en papel durante la contingencia: está decidiendo a ciegas, en el peor momento posible, algo que debería haberse decidido con calma meses antes.

El vínculo entre CISA y el caso WannaCry refuerza este punto desde otro ángulo: la alerta oficial *TA17-132A* no recomendaba, en primer lugar, un control de confidencialidad, sino aplicar el parche MS17-010 y, de no ser posible, deshabilitar el protocolo SMBv1 — es decir, una medida de endurecimiento orientada directamente a preservar disponibilidad frente a un vector de propagación automática (CISA, 2017). La recomendación técnica más urgente del incidente de disponibilidad más grande documentado hasta esa fecha fue, también, una medida de disponibilidad.

## Tensión / límites

Lo que no está resuelto es *por qué* persiste la asimetría formativa si la evidencia de impacto es tan clara. Una hipótesis razonable es que la disponibilidad se mide en consecuencias **operativas y económicas** (horas de inactividad, citas canceladas, producción detenida), que son más difíciles de convertir en un "incidente de seguridad" narrativamente atractivo que una filtración de datos personales, la cual activa de inmediato un marco regulatorio y mediático reconocible (notificación de brecha, exposición de identidades). Esto genera un sesgo de atención: lo que se regula y se titula más, se enseña más, independientemente de dónde esté el daño real. Además, la disponibilidad depende de disciplinas que tradicionalmente no están bajo el paraguas de "seguridad" —arquitectura de infraestructura, backups, planificación de continuidad—, lo que fragmenta la responsabilidad entre equipos distintos y diluye quién es responsable de definir el RTO/RPO de cada sistema.

## Cierre

Para la práctica profesional, la implicancia es concreta: no alcanza con pensar la seguridad como protección de la confidencialidad de los datos. Cualquier análisis de riesgo tiene que incluir, con el mismo rigor, qué sistemas son críticos para la operación, cuál es su RTO/RPO definido formalmente, y qué controles de disponibilidad (segmentación, gestión de parches, backups probados y aislados) existen para sostenerlo. El caso WannaCry y el panorama de amenazas 2024 de ENISA muestran, con ocho años de distancia entre uno y otro, el mismo patrón: la disponibilidad sigue siendo el blanco más rentable para un atacante, y seguirá siéndolo mientras reciba menos atención que las otras dos propiedades de la tríada.

---

## Bibliografía

1. [PRIMARIA] National Institute of Standards and Technology. (2010). *SP 800-34 Rev. 1: Contingency Planning Guide for Federal Information Systems*. https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-34r1.pdf
2. [PRIMARIA] European Union Agency for Cybersecurity (ENISA). (2024). *ENISA Threat Landscape 2024*. https://www.enisa.europa.eu/publications/enisa-threat-landscape-2024
3. [PRIMARIA] Cybersecurity and Infrastructure Security Agency (CISA). (2017). *Alert TA17-132A: Indicators Associated With WannaCry Ransomware*. https://www.cisa.gov/ncas/alerts/TA17-132A
4. [SECUNDARIA] National Audit Office (Reino Unido). (2017). *Investigation: WannaCry cyber attack and the NHS*. https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude Code (Anthropic) | Búsqueda de fuentes, redacción y estructuración del texto. | Todo el documento. | Cada una de las cuatro fuentes se verificó con una búsqueda web que confirmó que la URL existe y resuelve al documento citado, antes de incluirla en la bibliografía. |

**Verificación de fuentes:** se declara haber accedido y verificado individualmente cada una de las referencias citadas.
