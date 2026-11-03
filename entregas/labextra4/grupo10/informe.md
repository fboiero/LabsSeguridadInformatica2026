# Informe — Laboratorio Extra 4: Cracking de contraseñas

> Borrador de documentación. Los campos entre corchetes quedan pendientes de evidencia verificable o de información del grupo. No completar por estimación ni copiar valores del generador del caso.

| Campo | Información |
|---|---|
| **Grupo** | 10 |
| **Integrantes** | Saby, Juan Pablo; Ramello, Belén; Kordek, Chiara; Corazza, Carolina |
| **Fecha** | [Completar al cerrar la entrega] |
| **Entorno y autorización** | Caso ficticio provisto por la cátedra; pruebas limitadas al laboratorio local. No se realizaron pruebas contra terceros. |

**Declaración de uso de IA (obligatoria):**
- **Herramientas utilizadas:** Antigravity/Gemini, Claude y OpenCode (asistente de IA).
- **Alcance y propósito:** planificación y auditoría de requisitos; preparación de estructura y borradores de documentación e investigación.
- **Partes asistidas por IA:** borradores de este informe y `research.md`; verificar y actualizar esta declaración para reflejar el uso real del equipo.
- **Verificación humana/técnica:** [Completar con las revisiones y pruebas realmente realizadas por el grupo. No conservar verificaciones que no se hayan realizado.]

## 1. Resumen

Este laboratorio analiza la resistencia de cuatro hashes ficticios de PhantomCorp mediante un cracker propio, con ataques de diccionario y reglas de mangling. El objetivo es comparar el efecto del algoritmo y del trabajo por intento, documentar el descifrado del loot asociado y proponer medidas defensivas. Los resultados de cracking, tiempos, contenidos descifrados y estado de flags se incorporarán únicamente a partir de salidas originales verificables.

## 2. Alcance y metodología

**Alcance:** archivos de caso y herramientas incluidos en `labs/labextra4-cracking/`, en el entorno local del laboratorio. El volcado está identificado en la consigna como ficticio. No se probaron hashes, contraseñas ni servicios de terceros.

**Metodología prevista:**

1. Revisar el formato del volcado `usuario:algoritmo:salt_hex:hash_hex`.
2. Ejecutar el cracker propio contra el diccionario suministrado, primero sin reglas y luego con reglas.
3. Medir intentos por segundo por algoritmo con el procedimiento documentado y las condiciones reales de ejecución.
4. Intentar abrir los archivos `.enc` correspondientes a credenciales recuperadas y guardar la salida cruda.
5. Registrar el estado de las flags y analizar los resultados junto con las preguntas P1–P5.

**Estado de ejecución:** pendiente de incorporar las salidas verificables del responsable de implementación y las mediciones del benchmark proporcionadas por Chiara.

## 3. Tabla de resultados

Completar únicamente a partir de `evidencia/salidas/` y registrar el nombre de la evidencia que respalda cada fila. No inferir las contraseñas desde el código generador del caso.

| Usuario | Algoritmo | ¿Cayó? | Técnica (diccionario/regla y regla aplicada) | Contraseña recuperada | Tiempo aprox. | Evidencia |
|---|---|---|---|---|---|---|
| operador | MD5 + salt | Pendiente | Pendiente | Pendiente | Pendiente | `evidencia/salidas/` — pendiente |
| analista | SHA-256 + salt | Pendiente | Pendiente | Pendiente | Pendiente | `evidencia/salidas/` — pendiente |
| admin | SHA-256 + salt | Pendiente | Pendiente | Pendiente | Pendiente | `evidencia/salidas/` — pendiente |
| root | PBKDF2-HMAC-SHA-256, 200.000 iteraciones | No evaluado completamente todavía | No aplica si no cae | No aplica si no cae | No aplica si no cae | Salida completa pendiente |

La consigna indica que `root` no debe caer en este caso. El cracker del grupo informa progreso de PBKDF2 y permite interrumpir la búsqueda; una ejecución interrumpida es **inconclusa**, no demuestra que la contraseña no esté en el conjunto probado. Para sostener el resultado esperado, registrar una ejecución completa o evidencia suficiente del procedimiento solicitado por la cátedra. No se afirmará un resultado hasta registrar esa evidencia.

## 4. Medición de velocidad — P1

**Procedencia:** [Completar: mediciones propias o benchmark entregado por Chiara; identificar equipo, versión de Python, comando, cantidad de intentos y método de cálculo].

| Algoritmo | Intentos/segundo medidos | Tamaño de muestra | Diccionario completo tardaría… | Evidencia/fuente |
|---|---:|---:|---|---|
| MD5 | Pendiente | Pendiente | Pendiente | Pendiente |
| SHA-256 | Pendiente | Pendiente | Pendiente | Pendiente |
| PBKDF2-HMAC-SHA-256 (200.000 iteraciones) | Pendiente | Pendiente | Pendiente | Pendiente |

**Método de estimación:** registrar el tiempo real para un número conocido de intentos; calcular `intentos/segundo = intentos medidos / segundos transcurridos`. Para estimar el diccionario completo, usar `cantidad de candidatos / intentos por segundo`. Indicar límites y condiciones de la medición; no extrapolar una medición de CPU como si fuera una GPU. Si se interrumpe PBKDF2, informar solo los intentos completados y marcar la muestra como parcial; no afirmar que se evaluó el diccionario entero.

**Interpretación:** [Completar después de recibir los datos. Comparar diferencias en órdenes de magnitud y explicar que el trabajo deliberadamente costoso de PBKDF2 reduce los intentos por segundo. Cualquier velocidad de GPU debe citar una fuente o benchmark identificable y no presentarse como medición local.]

## 5. El loot

Documentar cada archivo que haya sido abierto efectivamente. Adjuntar la salida cruda del descifrado; no transcribir contenido supuesto.

| Cuenta | Archivo | ¿Se descifró? | Salida/evidencia | Impacto en PhantomCorp |
|---|---|---|---|---|
| operador | `caso/loot/operador.enc` | Pendiente | Pendiente | Completar según el contenido observado y su contexto ficticio. |
| analista | `caso/loot/analista.enc` | Pendiente | Pendiente | Completar según el contenido observado y su contexto ficticio. |
| admin | `caso/loot/admin.enc` | Pendiente | Pendiente | Completar según el contenido observado y su contexto ficticio. |
| root | No hay `.enc` en el caso provisto | No corresponde | No corresponde | La consigna no proporciona loot para root; no afirmar que se descifró. |

## 6. Flags

**Estado:** pendiente de captura real de `./ctf status extra4`.

Insertar aquí la captura legible o transcripción íntegra obtenida del comando, junto con `evidencia/salidas/ctf_status_extra4.txt`. No escribir flags hasta que hayan sido entregadas por el procedimiento del laboratorio. Mantener las flags únicamente donde las solicite la entrega y evitar duplicarlas innecesariamente.

## 7. Respuestas P1–P5

### P1. Velocidad de ataque

La medición debe comparar intentos por segundo de MD5, SHA-256 y PBKDF2 usando el cracker y una muestra conocida, con tiempos registrados. La velocidad permite estimar el tiempo de búsqueda, pero la extrapolación debe indicar algoritmo, hardware y supuestos. Una GPU puede acelerar mucho los hashes rápidos; no se debe atribuir una cifra a este experimento sin fuente o medición. **Resultado numérico y comparación:** pendientes del benchmark y de la evidencia.

### P2. ¿Para qué sirve el salt?

Un salt aleatorio y único por cuenta evita que un mismo hash revele directamente que dos usuarios eligieron la misma contraseña y hace ineficaces las tablas precalculadas reutilizables (como rainbow tables) para ese valor de salt. También obliga a calcular candidatos por separado para cada cuenta. Sin embargo, no vuelve lenta una función rápida ni impide probar un diccionario contra cada hash: para eso hacen falta contraseñas robustas y una función de derivación de contraseñas deliberadamente costosa, configurada con parámetros adecuados.

### P3. Políticas de contraseñas

Cumplir requisitos de longitud y mezcla de clases de caracteres no garantiza resistencia si la contraseña sigue patrones comunes o se basa en palabras predecibles. La recomendación moderna de NIST SP 800-63B prioriza longitud suficiente, comparación contra listas de contraseñas comunes o comprometidas y límites razonables contra intentos en línea, en lugar de imponer reglas arbitrarias de composición y cambios periódicos sin indicios de compromiso. Para almacenamiento, deben usarse salts únicos y una función de derivación lenta para contraseñas, con parámetros actuales y revisables; esto es distinto de la política para elegir contraseñas. Las recomendaciones concretas deben citar la edición vigente de NIST consultada en `research.md`.

### P4. Trabajo por intento y `root`

PBKDF2 realiza un número configurable de iteraciones de una función pseudorrandómica por candidato; por eso cada intento requiere mucho más trabajo que MD5 o SHA-256 de una sola pasada. Si el diccionario contiene `N` candidatos y el atacante consigue en conjunto `R` intentos por segundo, el tiempo ideal aproximado es `N / R` segundos. Para 1.000 GPUs, no se debe multiplicar por 1.000 sin una medición o supuesto explícito de rendimiento por GPU, escalabilidad y compatibilidad del algoritmo. **Cálculo numérico:** pendiente de las mediciones/fuente y del tamaño de diccionario adoptado. La conclusión sobre `root` se apoyará en la salida real del cracker, no en una contraseña adivinada.

### P5. Respuesta al incidente y defensa

Ante un volcado real, primero se activa y coordina la respuesta al incidente: asignar responsables, preservar evidencia y registrar decisiones. Luego, de forma ordenada y según el plan de respuesta: contener el acceso y la exposición; evaluar alcance e integridad de evidencia; revocar sesiones/tokens y rotar credenciales afectadas con prioridad; investigar accesos y sistemas relacionados; cumplir las obligaciones de notificación aplicables; recuperar y monitorear; y documentar lecciones aprendidas. No se deben destruir logs ni modificar evidencia durante la investigación.

Para el almacenamiento futuro, usar una función específica para contraseñas (por ejemplo, Argon2id; o PBKDF2/bcrypt cuando corresponda), con salt aleatorio único por cuenta y parámetros de coste calibrados y actualizados. Proteger cualquier pepper en un gestor de secretos separado, si se adopta. Permitir contraseñas largas, bloquear contraseñas conocidas como comprometidas, habilitar MFA donde aplique y migrar credenciales existentes de forma segura —por ejemplo, al próximo inicio de sesión o mediante restablecimiento según riesgo— sin conservar hashes débiles como mecanismo permanente.

## 8. Conclusión

[Completar al integrar resultados.] PhantomCorp debería almacenar contraseñas con [algoritmo y parámetros sustentados], un salt único por cuenta y controles de acceso adecuados. Las cuentas existentes con hashes rápidos deberían migrarse mediante [estrategia acordada]. La eficacia de la política debe validarse con parámetros medidos en el entorno previsto y revisarse periódicamente. Las conclusiones sobre este caso se limitarán a lo demostrado por las evidencias adjuntas.

## 9. Evidencias y trazabilidad

Se adjuntan `evidencia/comandos.txt` con la secuencia fiel de comandos y `evidencia/salidas/` con salidas originales, sin edición. Las referencias a resultados de este informe deben apuntar a esas evidencias. La contribución de cada integrante se reflejará en los commits del PR.

**Checklist previo a la entrega:**

- [ ] Completar grupo, integrantes y fecha.
- [ ] Incorporar declaración de uso de IA real del grupo.
- [ ] Incorporar resultados de cracking sin alterar la salida original.
- [ ] Incorporar mediciones de Chiara con procedencia, condiciones y unidad.
- [ ] Incorporar salidas reales del descifrado del loot.
- [ ] Añadir captura/salida completa de `./ctf status extra4`.
- [ ] Completar los cálculos de P1 y P4 con datos y supuestos explícitos.
- [ ] Verificar que cada afirmación empírica tenga evidencia o fuente citada.
- [ ] Revisar que no haya secretos reales ni datos personales.
- [ ] Verificar que los commits del PR reflejen el trabajo de todos los integrantes.
