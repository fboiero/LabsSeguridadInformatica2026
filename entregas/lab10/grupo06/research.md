# Mini-research — Laboratorio 10: SIEM y correlación de logs

**Grupo:** 06  
**Tema elegido:** C — SIEM y correlación de logs

## Qué aporta un SIEM frente a una firma aislada

Un SIEM centraliza y analiza eventos provenientes de distintas fuentes: aplicaciones, servidores, red e identidades. Su valor no consiste únicamente en guardar alertas, sino en conservar campos que permitan relacionarlas, como tiempo, IP de origen y destino, usuario, proceso, ruta, código HTTP y tipo de evento. NIST define la correlación basada en reglas como la comparación de varias entradas de uno o varios orígenes mediante valores registrados, por ejemplo marcas de tiempo, direcciones IP y tipos de evento [1].

En el laboratorio, el SOC del caso usa firmas puntuales: una User-Agent con nombres de herramientas, una ruta con ../ o un patrón de consulta. Eso es útil para reconocer indicadores conocidos de inmediato, pero una firma no explica si un evento aislado forma parte de un ataque ni detecta necesariamente una variante que no coincide con su texto.

Un SIEM permite sumar contexto. En lugar de alertar solo porque una ruta contiene ../, podría correlacionar solicitudes del mismo origen a rutas administrativas, errores repetidos, respuestas exitosas y cambios de comportamiento dentro de una ventana temporal. La correlación no convierte el resultado en certeza: organiza evidencia para que una persona o una respuesta automatizada evalúe prioridad y alcance.

## Aplicación al R5: de la línea aislada a una detección útil

R5 muestra una línea que no correspondía al tráfico de práctica del grupo: una solicitud desde 185.220.101.42 hacia /admin/../../etc/passwd, con respuesta 200 y etiqueta ALERT[path-traversal]. Una regla de correlación razonable debería conservar al menos el origen, momento, método, ruta, código de respuesta, firma que alertó y la identidad o sesión disponible.

Una primera regla puede generar una alerta de alta prioridad ante una coincidencia de recorrido de directorios que devuelve 2xx. Sin embargo, un 200 no demuestra por sí solo que el archivo se haya leído: puede ser una página de error mal configurada o una respuesta genérica. La alerta debe impulsar la revisión de la respuesta, de los registros de la aplicación y de otros accesos desde el mismo origen.

Una segunda regla puede correlacionar, por IP y en una ventana acotada, varios indicadores: enumeración de rutas, errores 4xx o 5xx, intentos de traversal y después una respuesta 2xx a un recurso sensible. Este tipo de secuencia reduce el riesgo de decidir por una sola cadena y permite priorizar un patrón de reconocimiento seguido de acceso potencialmente exitoso.

El diseño debe contemplar falsos positivos y volumen. Umbrales demasiado bajos pueden saturar al SOC; umbrales demasiado altos dejan pasar ataques de una sola solicitud. Plataformas actuales de detección ofrecen reglas de correlación de eventos y reglas de umbral, además de otras clases de reglas [2]. La selección debe partir del riesgo del activo, el tráfico normal y la capacidad de investigación disponible.

## Qué datos y controles hacen falta

La correlación solo puede usar la información que fue registrada. Para el caso sería necesario sincronizar los relojes y retener registros con campos consistentes. NIST recomienda definir los tipos de eventos que se registran y conservar contenido suficiente para auditoría; entre los campos útiles se encuentran marcas de tiempo, direcciones de origen y destino, identificadores de usuario o proceso, descripciones del evento, archivos y reglas de control invocadas [3].

Además de los logs HTTP, una investigación real podría necesitar logs del proxy, firewall, DNS, autenticación, sistema operativo y aplicación. La ausencia de una fuente no prueba que no haya ocurrido una acción: limita lo que puede concluirse. También se requieren controles de acceso al SIEM, retención adecuada y protección contra alteración o borrado de eventos.

La detección no reemplaza la corrección de causa raíz. En PhantomCorp, validar las rutas del servidor y aplicar controles de acceso evita que un traversal tenga éxito; la correlación ayuda a descubrir intentos y a dimensionar incidentes ya ocurridos. Firma, correlación, controles preventivos y revisión humana son capas complementarias.

## Reflexión

El R5 ilustra que una alerta puede estar presente y aun así pasar inadvertida si queda mezclada con tráfico normal. Como atacante, entender qué información produce un request permite evaluar qué lo delata. Como defensor, entender variantes y secuencias de ataque permite diseñar reglas menos frágiles y revisar los eventos con contexto. Ninguno de los dos enfoques sustituye al otro: la detección necesita conocer comportamientos ofensivos, y una evaluación ofensiva responsable debe considerar cómo será observada y contenida.

## Fuentes

1. NIST. [Rule-Based Event Correlation](https://csrc.nist.gov/glossary/term/rule_based_event_correlation).
2. Elastic. [Create a detection rule using the UI](https://www.elastic.co/docs/solutions/security/detect-and-alert/using-the-rule-ui).
3. NIST. [SP 800-171 Rev. 3, Audit and Accountability](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/800-171r3/NIST.SP.800-171r3.html).

## Declaración de uso de IA

Se utilizó Codex para estructurar el research, contrastar fuentes primarias y mejorar la redacción. El grupo revisó el texto contra las evidencias de R5, el ruleset del laboratorio y las fuentes citadas antes de incluir las afirmaciones.
