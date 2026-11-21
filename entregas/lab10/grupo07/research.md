# Mini-research — Laboratorio 10

**Tema elegido:** C. SIEM y correlación de logs.

## Desarrollo

Un SIEM centraliza eventos de fuentes como el inicio de sesión, los servidores web y la auditoría de la aplicación. Al normalizar el formato de la hora, el tipo de evento y los identificadores, puede vincular acciones que cada fuente registra por separado. Conservar los registros originales y controlar quién puede modificarlos facilita que un analista compruebe cómo se generó una alerta. [ASD’s ACSC — Best practices for event logging and threat detection](https://www.cyber.gov.au/publication/best-practices-for-event-logging-and-threat-detection).

Para reconstruir una secuencia conviene ordenar por el momento en que ocurrió el evento. Un recolector puede recibirlo más tarde, por ejemplo si una fuente acumuló registros durante una interrupción. OpenTelemetry distingue `Timestamp`, la hora del evento, de `ObservedTimestamp`, la hora de observación. También define `TraceId` para relacionar registros de una misma traza. Para relacionar acciones de una sesión a través de varias trazas, el ejemplo de abajo supone que las fuentes comparten un identificador de sesión registrado como metadato y una identidad de cuenta normalizada. [OpenTelemetry — Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/).

Supongamos que el sistema de identidad registra un inicio de sesión exitoso desde un dispositivo nuevo y que, minutos después, la aplicación registra una descarga sensible completada. Ambas operaciones pueden ser legítimas. Para priorizar la revisión, una regla busca un inicio de sesión de ese tipo seguido de una descarga sensible en un máximo de diez minutos, para la misma cuenta y sesión. Una secuencia ordenada con claves compartidas y una ventana máxima es un tipo de correlación expresable en EQL. [Elastic — EQL syntax reference](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax).

| Caso ficticio | Cuenta y sesión | Hora UTC del inicio y de la descarga | Evaluación de la regla |
|---|---|---|---|
| A | Misma cuenta, misma sesión | 14:00 y 14:04 | Genera alerta. |
| B | Misma cuenta, sesiones distintas | 14:00 y 14:04 | Queda fuera de la secuencia. |
| C | Misma cuenta, misma sesión | 14:00 y 14:18 | Queda fuera de la ventana. |

La regla de ejemplo se comprobó con esos datos ficticios. Una descarga legítima desde un equipo recién incorporado podría generar un falso positivo. Un inicio de sesión que llega tarde o carece de identificador podría dejar un falso negativo si la consulta ya cerró la ventana o carece de la clave para unirlo. El analista puede revisar la autorización del equipo y el contexto de la descarga antes de clasificar la alerta. Para evaluar cobertura, también importa vigilar cuánto tardan en llegar los registros y si se están perdiendo campos de correlación.

## Fuentes (mín. 3)

1. ASD’s ACSC y coautores. Centralización, normalización, integridad y consistencia temporal de los registros. [Best practices for event logging and threat detection](https://www.cyber.gov.au/publication/best-practices-for-event-logging-and-threat-detection).
2. OpenTelemetry. Campos temporales e identificadores de trazas en un registro. [Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/).
3. Elastic. Secuencias ordenadas, claves para unir eventos y duración máxima de una secuencia. [EQL syntax reference](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax).

## Reflexión

Correlacionar por sesión cambia qué registros puedo atribuir a una misma actividad. Una coincidencia por IP o por hora deja más ambigüedad, sobre todo si varias personas comparten un origen. En el lab, conservaría el registro inicial y la bitácora de los operadores para que otro integrante pueda revisar si la atribución se sostiene con los mismos datos.
