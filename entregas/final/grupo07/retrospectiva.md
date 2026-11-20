# Retrospectiva y uso de IA - Grupo 07

Síntesis del trabajo del equipo redactada por Fernando con asistencia de Codex,
basada en el historial y las evidencias del repositorio. No se presenta como acta
de una reunión ni se atribuyen lecturas o aprobaciones personales no registradas.

## Qué salió bien

La división por changes permitió avanzar en paralelo y conectar módulos sin
cambiar el contrato público del harness. El diseño y los tests negativos ayudaron
a mantener controles que no dependieran de la respuesta de un modelo: alcance,
tokens, gates, parada y bitácora. La integración conservó un modo de pruebas con
fixtures y agregó un modo Docker real identificado de forma explícita.

El historial de evidencias permitió corregir la presentación cuando llegaron
SQLite y las herramientas reales. Pusimos por separado lo observado, lo inconcluso
y lo cargado manualmente. Los mutation checks aportaron una comprobación más útil
que contar tests: al retirar un control, la prueba correspondiente dejó de pasar.

## Qué salió mal y qué haríamos distinto

Se llegó al cierre con implementaciones probadas por separado, pero con pasos aún
sin conectar al comando integrado. Hubo que adaptar la ruta de SQLite, el ejecutor
Docker y el pasaje de evidencia entre fases. En otro trabajo acordaríamos al
principio un comando mínimo de punta a punta y lo ejecutaríamos después de cada
incorporación, manteniendo visibles los tramos que usan fixtures.

La asistencia de IA aceleró la escritura, pero no aseguró que entendiéramos cada
decisión ni que las descripciones fueran exactas. También quedaron textos y
números históricos que podían confundirse con el estado actual. Mantendríamos un
único corte de resultados para informe y exposición, y reservaríamos tiempo para
leer el código, contrastar afirmaciones y ensayar. Las revisiones documentales de
cierre asistidas no se presentan como revisiones personales de los compañeros.

## Ejemplos de errores detectados y corregidos

| Área / responsable | Asistencia | Error o afirmación revisada | Cómo se comprobó | Corrección |
|---|---|---|---|---|
| 003 / Guadalupe | Claude | Tests con una ventana RoE fija, incompatible con la comprobación del reloj real | Pytest dejaba cuatro pruebas en rojo | Usar una ventana alrededor de la hora de ejecución en tests del harness |
| 002 / Lautaro; comprobación final de Fernando | Claude en el desarrollo; Codex en el cierre | La documentación atribuía detección a cualquier borrado de una fila | En una copia del lab se desactivó el trigger y borró la última fila: 20 a 19 registros; verify devolvió OK | Precisar que se detectan alteraciones y borrado intermedio, pero no truncado final sin ancla externa; no declarar esa garantía |
| 004/005 / Lorenzo | Codex | Un test esperaba EPSS para una CVE ausente del snapshot | Contraste con epss-snapshot.json | Mantener null cuando el dato no está disponible |
| 006/007 / Fernando | Codex | Comparar la subred Docker completa con un único CIDR del token luego de excluir .5 | El sandbox rechazaba la red válida del laboratorio | Separar validación de la red interna máxima y validación de la IP contra el token efectivo |

El ejemplo del 002 fue comprobado por Fernando durante esta preparación, a pedido
del usuario que asumió el cierre. No se afirma que Lautaro haya hecho esa lectura
o experimento. Evidencia:
[limite-bitacora-002.json](ptaas-kit/evidencia/fernando/cierre-pr/limite-bitacora-002.json).
El archivo original no se modificó ni se conservó la copia alterada como evidencia
de una corrida auténtica.

## Cómo verificamos

Se ejecutaron pytest, 20 evaluaciones golden y progress.py; se inspeccionó el diff,
la procedencia y las evidencias de herramientas. Los mutation checks de 003, 002
y 006/007 detectaron roturas deliberadas de controles. Se verificaron bases SQLite
de las corridas reales y una copia alterada. En el informe se mantienen los 39
errores previos de mypy como control no aprobado.

El estado 90/90 corresponde a las tareas 002-007. Las revisiones documentales de
`docs/revisiones-cierre.md` están registradas como asistidas por IA a pedido de
Lorenzo. No equivalen a revisión humana individual ni a aprobación académica. La
PR queda disponible para la revisión independiente correspondiente.

## Declaraciones de uso de IA

**Guadalupe Gómez.** Según la declaración incorporada al informe compartido,
utilizó Claude (Anthropic) para apoyar el parser RoE, la emisión de tokens, los
tests, el diseño y el delta del 003. La verificación documentada incluyó pruebas
de fechas, exclusiones y reutilización de tokens, además de mutation checks.

**Lautaro Mariño.** Según `ptaas-kit/docs/lautaro-002.md`, utilizó Claude para el
esquema SQLite, la política de integridad, el delta audit-log, tests y audit.py.
Documentó pytest, Ruff, mypy y un mutation check. El cierre del ejemplo de
documentación y su redacción fueron realizados por Fernando con Codex, sin
atribuirle ese trabajo personal a Lautaro.

**Lorenzo Blanc.** Utilizó Codex en diseño, implementación y pruebas de 004/005,
snapshots y adaptadores. Documentó corridas reales HTTPX, Nuclei y ZAP contra DVWA,
la corrección de rutas Windows/Linux y la integración Docker real de A/B. Registró
el cierre documental asistido sin atribuir lecturas humanas al resto.

**Fernando Cagliero.** Utilizó Codex en diseño, tests e implementación de 006/007,
integración SQLite y preparación de la entrega, el informe, la retrospectiva,
presentación, guion y demo. Codex ejecutó comprobaciones técnicas y redactó a partir
de los archivos existentes. Los números y ejemplos se contrastaron con evidencias;
las decisiones de prueba automatizada no se declaran aprobaciones personales.

Las ilustraciones de portada, del edificio y de los tres escudos del cierre se
generaron con IA. El prompt del cierre se incluye junto a su imagen en
`presentacion/`. El video es una reproducción visual de resultados capturados y no una
grabación de ejecución en vivo. La asistencia de IA fue amplia y no demuestra por
sí sola comprensión individual; el equipo debe poder explicar el alcance entregado.
