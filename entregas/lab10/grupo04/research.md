# Mini-research — Laboratorio 10

**Grupo:** 04 · [Integrantes](INTEGRANTES.md).
**Tema C:** SIEM y correlación de logs: cómo detectar lo que ninguna firma ve.

## Desarrollo

### De un registro a una decisión

Un SIEM centraliza eventos y permite relacionarlos para investigar y alertar.
No es una garantía de detección: depende de la calidad y cobertura de las fuentes,
los casos de uso y la capacidad del equipo para responder. NIST SP 800-92 [1]
plantea la gestión de logs como infraestructura y procesos de toda la organización,
no como instalar una herramienta aislada. La guía conjunta publicada por CISA [3]
vincula el logging con visibilidad y resiliencia operativa.

Una firma inspecciona patrones conocidos. La correlación permite detectar una
secuencia sospechosa aunque cada evento individual parezca aceptable: por ejemplo,
fallos de autenticación, acceso exitoso desde un contexto inusual y una exportación
de datos posterior. Este es un caso de uso propuesto, no un resultado observado
en PhantomCorp. Incluso sin una firma de payload, la secuencia puede contradecir
la conducta esperada del usuario. Para juzgarla hacen falta contexto y una línea
base; «inusual» no significa automáticamente malicioso.

### Telemetría necesaria

OWASP [2] recomienda registrar cuándo, dónde, quién y qué ocurrió, incluyendo
resultado, severidad e identificadores de interacción. Un esquema útil para este
lab incluiría fecha UTC, host, IP origen, usuario, request ID, método, ruta,
parámetros normalizados, estado HTTP, firma y acción tomada. La versión original
y la interpretación normalizada ayudan a investigar discrepancias de parsing,
siempre filtrando secretos y limitando tamaños.

Las fuentes deben compartir referencias temporales confiables y un formato
consistente. Una cuenta o request ID suele dar mejor contexto que una IP sola,
que puede corresponder a NAT, proxies o infraestructura compartida. Los logs deben
protegerse contra lectura y modificación no autorizadas. Contraseñas, tokens y
datos sensibles no deben copiarse indiscriminadamente al SIEM. OWASP también
advierte sobre inyección de logs: entradas controladas por el cliente deben
sanitizarse y codificarse de manera segura, preferentemente en registros
estructurados [2].

### Aplicación al evento R5

El registro del lab contiene `ALERT[path-traversal]` para
`/admin/../../etc/passwd` con HTTP 200. No es un caso donde ninguna firma detectó
el ataque: la firma ya lo etiquetó. El problema demostrable es la necesidad de
seleccionarlo, investigarlo y actuar entre 120 entradas benignas. Además, el SOC
simulado no persiste nuestras solicitudes, por lo que no sirve como pipeline real.

Proponemos el siguiente flujo, sin afirmar que fue instalado:

1. Emitir eventos dinámicos del WAF y aplicación a un colector central.
2. Validar campos, normalizar rutas con semántica coherente y conservar el contexto.
3. Crear un caso ante traversal a recurso sensible y priorizarlo con estado 2xx.
4. Notificar a un analista responsable con evidencia, origen, destino y request ID.
5. Confirmar acceso real mediante otras fuentes antes de concluir exfiltración;
   contener según el impacto confirmado y el procedimiento autorizado.

Como complemento sin firma literal, una regla de comportamiento podría observar
una cuenta que normalmente consulta catálogo y pasa a recursos administrativos,
junto con accesos denegados o cambios de privilegios. Requiere historial y campos
que el log simplificado del laboratorio no ofrece: no se puede evaluar su eficacia
con esta única muestra. La correlación no puede recuperar información nunca
registrada.

### Límites, operación y medición

Una regla excesivamente amplia genera fatiga y puede ocultar incidentes. Una regla
con un umbral alto puede perder un único intento importante. Las excepciones
deben justificarse y revisarse; una prueba autorizada puede etiquetarse sin dejar
de registrar su actividad. Conviene medir falsos positivos sobre tráfico revisado,
cobertura con casos controlados, demora de ingestión, tiempo hasta triage y pérdida
de fuentes. Deben probarse alertas de «fuente silenciosa», retención y recuperación.
No asignamos métricas numéricas sin datos reales ni equiparamos once pruebas de
regex con una evaluación completa de un SIEM.

La automatización puede deduplicar o enriquecer eventos, pero bloquear por una sola
señal débil puede causar denegación de servicio a usuarios legítimos. El contenido
registrado es evidencia no confiable hasta contextualizarlo; nunca debe ejecutarse
como una instrucción por el sistema de análisis o un agente.

## Fuentes

Fuentes primarias consultadas durante la preparación; las recomendaciones
específicas para PhantomCorp son una aplicación propia de sus principios.

1. **Kent, K. y Souppaya, M. — NIST SP 800-92, Guide to Computer Security Log
   Management (2006).** [Publicación oficial](https://csrc.nist.gov/pubs/sp/800/92/final).
   Se consultó la ficha y resumen oficiales: fundamentan la gestión organizacional
   y la infraestructura de logging; no se presenta como manual de implementación.
2. **OWASP — Logging Cheat Sheet.**
   [Documento](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
   Secciones utilizadas: Event attributes, Data to exclude, Event collection,
   Verification, Protection y Monitoring of events. Aporta campos, seguridad del
   registro e integración con alertamiento y respuesta.
3. **ASD/ACSC y socios internacionales, publicada por CISA — Best Practices for
   Event Logging and Threat Detection (21 de agosto de 2024).**
   [Página oficial](https://www.cisa.gov/resources-tools/resources/best-practices-event-logging-and-threat-detection).
   Se consultó la presentación oficial de la guía y su alcance: una línea base de
   logging para visibilidad y resiliencia, considerando restricciones de recursos.

## Reflexión

La diferencia central es entre tener evidencia y usarla. En R5 ya había una alerta;
buscar una firma más compleja no resolvería por sí solo la falta de seguimiento.
En R4, en cambio, la diferencia de interpretación entre detector y aplicación
explica la evasión. Ambos problemas exigen observabilidad y pruebas de extremo a
extremo, no confianza ciega en un panel o en un HTTP 200. Un SOC eficaz combina
telemetría útil, reglas verificadas, contexto y personas responsables de responder.

## Asistencia de IA

Este desarrollo fue redactado con OpenCode/GPT-6.1 Sol, incluyendo búsqueda y
lectura de las fuentes indicadas. Se contrastaron los hallazgos del laboratorio
con respuestas HTTP reales y el código del simulador; no se implementó un SIEM
ni se atribuyen ensayos o resultados de producción inexistentes.
