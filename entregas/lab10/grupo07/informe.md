# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 07 · **Fecha de preparación:** 19/11/2026

**Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8) y Lautaro Mariño (@lautaromarino0).

## 0. Declaración de uso de IA

| Integrante | Herramienta, uso y verificación |
|---|---|
| Fernando Cagliero | Se usó OpenAI Codex para redactar P5 y el mini-research y preparar el informe, la bitácora y el borrador del PR. Se contrastó P5 con los enunciados y el research con documentación oficial. La secuencia del ejemplo se comprobó con eventos ficticios. Pendiente la revisión personal de Fernando. |
| Guadalupe Gómez | Pendiente de su declaración. |
| Lorenzo Blanc | Pendiente de su declaración. |
| Lautaro Mariño | Pendiente de su declaración. |

## 1. Flags capturadas (salida de `./ctf status 10`)

Estado del checkout local al 19/11/2026 (UTC−03:00). La captura consolidada del grupo queda pendiente. [Salida cruda](evidencia/salidas/status-10-local.txt).

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                      │
  ╰────────────────────────────────────────────────────────────╯

   ·  R1     Acceso a la vista del SOC
   ·  R2     Disparar una deteccion (te vieron)
   ·  R3     Conocer el ruleset del IDS
   ·  R4     Evadir una firma de deteccion
   ·  R5     Encontrar la intrusion en el ruido

  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0/5 (0%)

[ctf status] código de salida: 1
```

## 2. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| `scanner-ua` | Pendiente del aporte de Lorenzo y de la evidencia de R2. | Pendiente de su propuesta y sus casos de prueba. |
| `sqli-union` | Pendiente del aporte de Lautaro y de la evidencia de R4. | Pendiente de su propuesta y sus pruebas locales. |

## 3. Preguntas P1–P5

### P1 — Límites de las firmas y señales complementarias

Pendiente del aporte de Guadalupe.

### P2 — Mejora de la firma y sus límites

Pendiente del aporte de Lautaro.

### P3 — User-Agent y señales alternativas

Pendiente del aporte de Lorenzo.

### P4 — Cómo alertar sobre la intrusión registrada

Pendiente del aporte de Guadalupe y de la evidencia de R5.

### P5 — Por qué ataque y defensa necesitan el mismo conocimiento

Quien evalúa un sistema necesita saber qué rastros dejan sus acciones para explicar qué pudo observar el defensor y dónde hay un punto ciego. Quien defiende necesita entender qué busca la otra parte y qué secuencia de acciones tendría sentido. Eso le permite elegir qué registrar, qué alertas relacionar y qué evidencia reunir antes de concluir que hubo una intrusión.

En los labs 05 y 06, el reconocimiento y la enumeración sirven para ubicar servicios y entender cómo responden. Esa misma actividad le permite al defensor preguntar si un origen consultó muchos servicios en una ventana breve y si ese comportamiento coincide con la actividad habitual. En el Lab 07, entender qué efecto tendría una inyección ayuda a vincular un request sospechoso con una consecuencia en el servicio. En el Lab 08, atribuir cambios a una cuenta o a un proceso exige conservar la identidad, la hora y la secuencia de eventos. [Lab 05](../../../labs/lab05-reconocimiento/README.md), [Lab 06](../../../labs/lab06-enumeracion-de-servicios/README.md), [Lab 07](../../../labs/lab07-explotacion/README.md), [Lab 08](../../../labs/lab08-postexplotacion/README.md).

El Lab 09 lleva ese razonamiento al agente. Su transcript permite seguir las decisiones y ver cuáles llegaron a ejecutarse, mientras que el control de alcance impone un límite en las herramientas. En el Lab 10, la captura inicial del SOC y los horarios permiten contrastar los registros con los requests del grupo. La coincidencia de hora, origen y evento ayuda a atribuir una alerta. Una detección aislada indica que se cumplió una condición de la regla. La evidencia del efecto en el servidor permite evaluar si hubo una intrusión. [Lab 09](../../../labs/lab09-agentes/README.md), [Lab 10](../../../labs/lab10-deteccion-evasion/README.md).

## 4. Bitácora

Se registró el estado inicial del checkout. La integración de los operadores queda pendiente. Para vincular cada request a su evento, la bitácora debe conservar autor, fecha y zona horaria, referencia a la salida cruda y, cuando figure, identificador del evento. Para R5, comparar los registros inicial y final con esa bitácora antes de atribuir la actividad al escenario. [Bitácora](evidencia/comandos.txt).
