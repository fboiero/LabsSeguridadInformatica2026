# Retrospectiva — ética, gobernanza y trabajo con IA (grupo 14)

Criterio 6 de la rúbrica. Cómo trabajamos con la IA, qué errores suyos detectamos
y corregimos, y qué controles proponemos. Honesto, con ejemplos reales de la sesión.

## 1. Cómo usamos la IA

Usamos **Claude Code (modelo Opus)** como asistente bajo nuestra conducción:
fijamos el objetivo, decidimos el camino y validamos cada salida corriéndola. La
IA ayudó a leer el kit, implementar el delta (`GuardedHarness`, `evidence_ref`,
tests, demo) y redactar. Nada se da por bueno sin que un test o una corrida lo
confirme: **la evidencia manda, no la afirmación de la IA.**

## 2. Errores de la IA que detectamos y corregimos

Estos pasaron de verdad y los dejamos documentados como aprendizaje:

1. **Afirmaciones no verificables en caja negra (en el engagement clásico).** Un
   primer borrador del informe del pentest afirmaba detalles internos (p. ej. que
   el servidor usaba `os.popen`, o el nombre de una tabla `users`) que en una
   auditoría de caja negra no se pueden saber. **Corrección:** reescribir cada
   afirmación para que se sostenga solo en el comportamiento observado, y **volver
   a ejecutar** la enumeración real (login por el `action` del form, `ls` del
   filesystem) para respaldar las rutas. Lección: la IA tiende a "rellenar" con lo
   que infiere; hay que anclar todo a evidencia reproducible.

2. **Propuesta de una declaración de IA falsa.** Al discutir la declaración de uso
   de IA, se evaluó afirmar un control ("restringimos el acceso al código fuente")
   que no había ocurrido. Lo descartamos: una declaración de integridad con un
   dato falso es, además de deshonesta, trivialmente refutable. Lección: la
   gobernanza empieza por no mentirle al evaluador.

3. **Sesgo a sobre-prometer alcance.** La IA tendía a ofrecer "hacemos todo el
   PTaaS hoy". Lo acotamos a un delta defendible y declaramos lo pendiente.
   Lección: medir el alcance contra el tiempo real, no contra el entusiasmo.

## 3. Controles de gobernanza que aplicamos

- **Guard determinista, no IA, en el camino crítico**: la decisión de autorizar o
  bloquear nunca la toma el LLM (invariante I2). La IA *propone*; el harness
  *decide*.
- **Bitácora de toda decisión** (OK/BLOCKED/PENDING_HITL/ABORTED) con hash
  encadenado: trazabilidad y no repudio.
- **Gates HITL** antes de acciones activas, validación y entrega: un humano
  aprueba los puntos sensibles.
- **Sin datos sensibles en claro** (`evidence_ref`): la bitácora cita evidencia por
  digest, no credenciales ni datos del cliente.
- **Topes de iteración** (`GuardedHarness`): contención ante un loop desbocado.

## 4. Controles adicionales propuestos (con estándares)

- **Divulgación coordinada** de los hallazgos siguiendo **ISO/IEC 29147**
  (disclosure) y **ISO/IEC 30111** (manejo interno de vulnerabilidades): plantilla
  de reporte, canal y plazos.
- **Metodología de pruebas** anclada en **NIST SP 800-115** y **OWASP WSTG**: cada
  capability referencia su técnica.
- **Severidades con CVSS v4 + CWE** obligatorios por hallazgo (ya lo exige
  `reporting.py`).
- **Red-team continuo del guard**: mantener una batería adversarial que crezca con
  cada bypass encontrado (empezamos con `test_grupo14_redteam.py`).
- **Rate limit por segundo** con ventana temporal (pendiente, anotado en el
  change 008) para completar la contención.

## 5. Conclusión

El valor del proyecto no está en que la IA "haga el pentest", sino en los
**controles deterministas y los gates humanos** que la encuadran. Nuestro aporte de
hoy va en esa dirección: encontrar dónde el control declarado no se cumplía
(topes), corregirlo, y cerrar un hueco de la bitácora (datos sensibles) — todo con
tests que lo prueban.
