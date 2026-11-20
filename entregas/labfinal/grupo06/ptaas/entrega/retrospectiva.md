# Retrospectiva de IA — P2

En esta retrospectiva se registran los errores de IA detectados durante el
trabajo y los defectos adicionales encontrados al revisar el harness. Los
commits se conservaron en la historia local de la rama; todavía no se hizo push.
Para los casos 4–6 también se conservó el par separado de test rojo y corrección.

## 1. El test A1 fallaba por el fixture, no por la normalización

- **Error:** el test utilizaba el token de ejemplo (`lab.example.test`) pero probaba
  `dvwa.lab.test`; por eso seguía en rojo incluso con la normalización correcta.
- **Detección:** al ejecutar A1 después de implementar la normalización, el test
  todavía fallaba.
- **Corrección:** se emitió el token con `domains=("dvwa.lab.test",)`.
- **Aprendizaje:** se debe comprobar que el target del test esté dentro del token antes
  de atribuir un fallo al código bajo prueba.
- **Referencia histórica:** `1b9392e`.

## 2. Literal IPv6 inválido en el caso A3

- **Error:** se utilizó `fd00:lab::/64`; `lab` no es un grupo hexadecimal IPv6.
- **Detección:** `ipaddress.ip_network` rechazó el literal antes de probar el
  comportamiento del Guard.
- **Corrección:** se reemplazó el literal por `fd00:abcd::/64` y `fd00:beef::5`.
- **Aprendizaje:** los datos de prueba deben validarse con el parser estándar antes de
  interpretar el resultado como un defecto del control.
- **Referencia histórica:** `1b9392e`.

## 3. Test de exclusión sin exclusión en el RoE

- **Error:** el test esperaba que el token aplicara una exclusión que no se había
  incluido en su fixture.
- **Detección:** el token conservó correctamente `10.99.0.0/24` completo y el
  test no produjo la condición esperada.
- **Corrección:** se agregó `10.99.0.10/32` a `exclusions.cidrs`.
- **Aprendizaje:** se debe revisar el conjunto de condiciones del escenario (RoE,
  alcance y exclusiones), no solo la aserción.
- **Referencia histórica:** `1b9392e`.

## 4. El token seguía vivo en el instante exacto de expiración

- **Error:** la comparación de vigencia incluía `window_end`; un token todavía
  se consideraba válido en el límite de expiración.
- **Detección:** un test fijó el reloj exactamente en `window_end` y `is_live()`
  devolvió verdadero.
- **Corrección:** se cambió a un intervalo semiabierto `[window_start, window_end)`
  y se verificó que `Harness.invoke` bloquee y registre `BLOCKED` en ese límite.
- **Aprendizaje:** se incorporaron pruebas para los límites exactos de tiempo, además
  de instantes anteriores y posteriores.
- **Test rojo:** `9a76691`. **Corrección:** `937a234`.

## 5. El hash no cubría todas las restricciones y se escapaba un alcance vacío

- **Error:** `approval_hash` se calculaba sin exclusiones ni fases. Además, la validación
  del alcance revisaba CIDR y dominios por separado, no el caso donde ambos
  grupos quedaban vacíos a la vez.
- **Detección:** tests nuevos cambiaron una exclusión o fase sin cambiar el hash y
  combinaron exclusiones que anulaban CIDR y dominios sin obtener rechazo.
- **Corrección:** se incluyeron todas las restricciones del RoE en el hash y se
  agregó el rechazo cuando el conjunto combinado de destinos restantes quedó vacío.
- **Aprendizaje:** el hash debe cubrir todo dato que altere la autorización y la
  validación debe evaluar el resultado combinado, no ramas independientes.
- **Test rojo:** `9a76691`. **Corrección:** `937a234`.

## 6. Se podían emitir tokens sin registrar la emisión

- **Error:** `audit` era opcional en `tokens.issue()`, de modo que una llamada
  normal podía devolver un token y no dejar registro.
- **Detección:** un test llamó al emisor sin sink y confirmó que se recibía
  un token sin auditoría.
- **Corrección:** `audit` se hizo obligatorio; sin sink, el emisor no
  entrega un token. Se actualizó la nota de traspaso para que los consumidores
  conozcan el contrato.
- **Aprendizaje:** las propiedades de la spec deben quedar forzadas por la
  interfaz, en vez de depender de que cada consumidor recuerde un parámetro opcional.
- **Test rojo:** `9a76691`. **Corrección:** `937a234`.


---

# Retrospectiva de IA — P3

Herramienta: Codex (GPT-6). Change 004 y tareas 007 · 2.3–2.4.
Los dos casos siguientes tienen su fila en `ia-errores.md` y fallos conservados en
`entrega/evidencia/salidas/P3-red-review.txt`.

## 1. Una salida HTTP vacía se interpretaba como éxito

- **Error:** el adaptador httpx devolvía `OK` ante stdout vacío, aunque no había
  una observación HTTP válida que justificara ese resultado.
- **Detección:** `test_http_empty_output_is_not_convergence` esperaba `ERROR`
  con `empty_output` y recibió `OK`.
- **Corrección:** se rechazó la salida HTTP vacía explícitamente. Se mantuvo
  separada de una enumeración pasiva exitosa sin descubrimientos y del estado
  `UNAVAILABLE` observado al ejecutar Subfinder sin fuentes locales.
- **Aprendizaje:** una salida vacía necesita interpretarse según la herramienta
  y su estado de ejecución; no basta con que el parser no encuentre líneas.
- **Referencia histórica:** `cf5b76f`; test y fallo en la evidencia citada.

## 2. Reanudar un grafo detenido volvía a ejecutar herramientas

- **Error:** el loop A iniciaba nuevas acciones al recibir un grafo `STOPPED`
  y tampoco preservaba la espera `PENDING_HITL` por errores de schema.
- **Detección:** `test_stopped_checkpoint_is_terminal` y
  `test_schema_hitl_is_preserved_on_resume` mostraron llamadas a subfinder/httpx
  cuando correspondía conservar el estado sin ejecutar herramientas.
- **Corrección:** se comprobó el estado antes de iniciar otra vuelta y se
  preservaron la parada y la espera de intervención al reanudar.
- **Aprendizaje:** persistir datos no alcanza: los tests de reanudación también
  deben comprobar qué acciones dejan de estar permitidas en cada estado.
- **Referencia histórica:** `cf5b76f`; test y fallo en la evidencia citada.

## Balance

La IA ayudó a desarrollar código, pruebas y documentación, pero las primeras
versiones necesitaron correcciones. Revisar el motivo de los fallos permitió
detectar errores que una prueba del recorrido normal no mostraba. La ejecución
real aportó otra comprobación: Subfinder sin fuentes disponibles no equivale a
descubrimiento exitoso. Se conservaron esa limitación y las salidas reales,
mientras que los subdominios y exclusiones se validaron por simulación. La
revisión cruzada de P2 complementó las comprobaciones automáticas.

---

# Retrospectiva de IA — P5

Herramienta: Claude Code (Opus 5.5). Changes 006, 007, 008 y 009, implementación del
002 y cierre del 005. Cada caso tiene su fila en `ia-errores.md`. Todos se detectaron
antes de que el error llegara a un informe entregado.

## 1. El Scenario del kill switch esperaba el resultado equivocado

- **Error:** el delta de `validation` decía que, con el kill switch activado, el
  resultado era `BLOCKED`. `Harness.invoke` registra `ABORTED`, que es lo que exige la
  invariante I6.
- **Detección:** al leer `contracts.py` antes de escribir el test.
- **Corrección:** se corrigió el Scenario para describir el comportamiento real.
- **Aprendizaje:** la spec también puede estar mal; antes de escribir el test hay que
  contrastarla con el código que ya hace cumplir el control.
- **Referencia:** `edb9dfc`.

## 2. Tests en rojo por la razón equivocada

- **Error (dos veces):** los tests de `path` y `param_name` fallaban porque un sender
  falso devolvía `None` y rompía el evaluador, no porque faltara el control. Más
  tarde, los tests negativos de `approve-gate` "fallaban" solo porque el subcomando
  todavía no existía.
- **Detección:** revisando el motivo de cada fallo antes de commitear el rojo, no solo
  la cantidad de fallos.
- **Corrección:** el sender falso devuelve una respuesta válida (ahora fallan con
  `DID NOT RAISE ParameterError`); los tests de `approve-gate` comprueban primero que
  una llamada válida funciona y que no quedó ninguna aprobación registrada.
- **Aprendizaje:** un test en rojo solo prueba algo si falla por la ausencia del
  control. Hay que leer el motivo, no contar fallos.
- **Referencia:** `cfdd3a0`, `0b53073`.

## 3. Dos tests que se contradecían

- **Error:** un test exigía un único contenedor por hallazgo validado; otro necesitaba
  un segundo intento para detectar resultados inconsistentes. Los dos no podían pasar
  a la vez.
- **Detección:** al implementar el loop C.
- **Corrección:** el primero pasó a verificar lo que realmente le importaba (que cada
  contenedor se destruya); la cantidad de intentos la cubre otro test.
- **Aprendizaje:** corregir un test está bien cuando el test estaba mal, no cuando
  molesta. Quedó registrado como error de la IA, no como ajuste.
- **Referencia:** `d7c457a`.

## 4. Una mutación sobrevivió: el test no probaba el control

- **Error:** el test de "alertas informativas no generan hallazgos" usaba una alerta
  sin CWE, que otra regla ya descartaba. El filtro de riesgo 0 nunca se probaba.
- **Detección:** la mutación M33 (desactivar el filtro) no rompió ningún test.
- **Corrección:** el test usa una alerta informativa con CWE válido; M33 pasó a
  detectarse.
- **Aprendizaje:** un test verde no demuestra que el control funcione. Las mutaciones
  encontraron lo que la revisión del código no vio.
- **Referencia:** `5164ec7`.

## 5. Un informe con errores llegó hasta el gate de entrega

- **Error:** el código usó el valor `NINGUNA` (hallazgo sin verificación en el
  catálogo) como si fuera una verificación real. El informe unificó dos alertas
  distintas (10009 y 10036, ambas CWE-497) y mostró `Verificación: NINGUNA vNone`.
- **Detección:** P5 revisó el informe antes de aprobar la entrega en la corrida real
  `P5-recorrido-03`. Ningún test lo había detectado.
- **Corrección:** test en rojo, corrección y mutación M35; la corrida `-03` se
  conservó sin entregar y la corregida (`-04`) se entregó.
- **Aprendizaje:** es el caso que justifica el gate humano de entrega: la persona que
  revisa el resultado encontró lo que los tests no cubrían.
- **Referencia:** `de98ef2` (test rojo), `70884f5` (corrección).

## 6. Errores de proceso, no de código

- **Interpretación del alcance:** la IA entendió que P5 tomaba toda la parte de P1,
  incluido el change 002, cuando el acuerdo era solo la parte del 007. Lo corrigió P5
  en la conversación.
- **Evidencia desfasada:** la evidencia final se generó antes de marcar una task, y el
  progreso registrado no coincidía con `tasks.md`. Se detectó comparándolos y se
  regeneró (`7dc09d5`).
- **Un argumento equivocado:** la IA justificó no usar LangGraph citando la invariante
  I2, que solo exige que el *Guard* sea determinista, no la orquestación. P5 pidió ver
  dónde estaba I2 y la IA corrigió el argumento antes de registrar la decisión
  (change 009).
- **Detalles de implementación:** un atributo con el nombre equivocado
  (`LoopDecision.action` en lugar de `decision`), detectado por los tests.
- **Aprendizaje:** la IA también se equivoca al interpretar qué se acordó y al
  justificar decisiones. Pedirle la fuente de un argumento lo dejó en evidencia.

## Patrones

| Tipo de error | Cómo se detectó |
|---|---|
| Tests que no prueban el control (casos 2 y 4) | Leer el motivo del rojo; mutaciones |
| Spec o tests inconsistentes con el código (casos 1 y 3) | Leer el código antes de escribir; implementar |
| Defecto que ningún test cubría (caso 5) | Gate humano de entrega |
| Interpretación y argumentación (caso 6) | Revisión de la persona; pedir la fuente |

La conclusión práctica: los tests y las mutaciones atraparon los errores de código,
pero no todos. Los dos errores más importantes (el informe defectuoso y el argumento
sobre I2) los encontró una persona revisando lo que la IA producía. Por eso los gates
humanos y la revisión no son trámites: son la última barrera.


---

# Retrospectiva de IA — P4

Herramienta: ChatGPT (GPT-6). Change 005, correlación y análisis.

## 1. Problemas de codificación al ejecutar ZAP

- **Error:** la solución inicial generada con ayuda de IA no contempl? todas las llamadas a Docker que debían decodificarse con UTF-8 en Windows.
- **Detección:** al ejecutar ZAP apareci? un `UnicodeDecodeError` con `cp1252`; una primera corrección no lo resolvi? por completo.
- **Corrección:** se configur? la decodificación UTF-8 con reemplazo de caracteres inválidos en las llamadas correspondientes y se repiti? el escaneo.
- **Aprendizaje:** que el código pase los tests no garantiza que funcione con la codificación del entorno real. Hay que revisar cada llamada externa y conservar el error como evidencia.
- **Referencia:** `bd47ceb`.

## 2. Corrección de calidad del código

- **Error:** código generado con asistencia de IA necesit? ajustes de imports para cumplir las reglas de Ruff.
- **Detección:** la ejecución del chequeo estático de Ruff.
- **Corrección:** se ordenaron los imports sin modificar la funcionalidad y se repitieron las comprobaciones.
- **Aprendizaje:** además de tests funcionales, es necesario ejecutar herramientas estáticas y revisar los cambios antes de publicarlos.
- **Referencia:** `038df86`.

## Balance

La IA ayud? a acelerar la implementación, preparar pruebas y documentar el Change 005, pero no reemplaz? las verificaciones. Los errores de ejecución aparecieron al trabajar con Docker y Windows, y se resolvieron comprobando la causa y repitiendo las pruebas.

También result? importante distinguir entre resultados simulados, validación de sintaxis, escaneos reales y aprobaciones humanas: no son evidencias equivalentes.


# Retrospectiva de IA — P1

Herramienta: Claude Code (Haiku 5.5). Bitácora y auditoría (change 002) y revisión
cruzada del change 006.

## 1. Commit del contrato sin mostrar la firma antes

- **Error:** el contrato de la bitácora (`harness/audit.py`) se commiteó sin mostrar
  antes la firma propuesta. El método del plan pide mostrarla y esperar revisión.
- **Detección:** al releer la sección 7.2 del plan, después del commit.
- **Corrección:** la firma quedó explícita en `design.md` y en la nota de traspaso,
  para que el grupo la revise. El test en rojo ya estaba en un commit separado.
- **Aprendizaje:** un contrato compartido por todo el grupo necesita revisión antes de
  commitearse, aunque la implementación sea pequeña. Un test en rojo no reemplaza la
  revisión de la firma.
- **Referencia:** `a5170fe`, `e0634d9`.

## 2. Informe de un push que sí había llegado

- **Error:** le informé al usuario que mis commits quedaban sin subir y que el push
  estaba bloqueado. Esa afirmación no coincidía con el estado del remoto.
- **Detección:** al hacer `git fetch`, `origin/labfinal-ptaas-grupo06` ya contenía los
  commits que creía pendientes.
- **Corrección:** se corrigió el informe al usuario. No hubo cambios de código.
- **Aprendizaje:** antes de afirmar que algo no se subió, hay que consultar el remoto
  (`git fetch` y `git log origin/...`). Un error de comando no garantiza que la acción
  haya fallado.
- **Referencia:** sin commit de código.

## Balance

La IA ayudó a escribir el contrato, los tests y los documentos de diseño. Los dos
errores fueron de proceso y de reporte, no de código, y se detectaron al comparar lo
dicho con el estado real del repositorio y con el método del plan.
