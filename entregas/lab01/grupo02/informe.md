# Laboratorio 01 — Informe

> **Instrucciones de uso de esta plantilla**
>
> 1. Copiala a `entregas/lab01/grupoXX/informe.md`.
> 2. Completá **todas** las secciones. Borrá estas instrucciones y todos los
>    textos en *cursiva*, que son consignas, no contenido.
> 3. No borres los encabezados ni cambies el orden: la corrección los sigue.
> 4. Si una sección no aplica, escribí por qué no aplica. **No la borres.**

---

## Identificación

| | |
|---|---|
| **Grupo** | 02 |
| **Caso asignado (Parte A)** | Filtración de datos de Target (2013) |
| **Tema del mini-research** | Tema 2 — La cadena de suministro de software como superficie de ataque |
| **Fecha de entrega** | 15/10/2026 |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha | Hecho | Fuente |
|---|---|---|
| Noviembre de 2013 | Los atacantes obtuvieron acceso a la red de Target utilizando credenciales vinculadas a un proveedor externo, según los informes sobre la investigación. | U.S. Senate Committee on Commerce, Science, and Transportation (2014). |
| 27 de noviembre–15 de diciembre de 2013 | Se produjo el período principal de exposición de datos de tarjetas de pago en tiendas estadounidenses. | Target Corporation (2014a). |
| Diciembre de 2013 | Se instaló malware en sistemas de punto de venta (POS), que permitió recolectar información de tarjetas utilizada en las transacciones. | Target Corporation (2014a). |
| 15 de diciembre de 2013 | Target informó que había eliminado el malware de prácticamente todas las cajas de sus tiendas estadounidenses. | Target Corporation (2014a). |
| 19 de diciembre de 2013 | Target comunicó públicamente el acceso no autorizado a datos de tarjetas y estimó que podían haberse visto afectadas aproximadamente 40 millones de cuentas. | Target Corporation (2013). |
| 10 de enero de 2014 | La empresa informó que la investigación también había identificado el robo de información personal de hasta 70 millones de personas. | Target Corporation (2014b). |
| 25 de marzo de 2014 | Un informe del Senado estadounidense analizó oportunidades en las que las alertas y los controles podrían haber ayudado a detener el ataque antes de que alcanzara su impacto final. | U.S. Senate Committee on Commerce, Science, and Transportation (2014). |

---

## A.2 — Activo afectado

**Activo principal:**

Los datos de las tarjetas de crédito y débito utilizados en las compras de los clientes de Target, procesados por los sistemas de punto de venta de las tiendas estadounidenses. Entre la información comprometida se encontraban datos de tarjetas utilizados para efectuar transacciones.

**¿Por qué es el principal?**

Es el activo directamente relacionado con el objetivo inmediato del ataque: obtener información financiera susceptible de ser utilizada de forma fraudulenta. Target informó que aproximadamente 40 millones de cuentas de tarjetas de crédito y débito podían haber sido afectadas durante el período principal del incidente. La magnitud del compromiso y la posibilidad de fraude financiero justifican priorizar este activo.

**Otros activos afectados:**

También se comprometió información personal de hasta 70 millones de personas, incluidos nombres, direcciones postales, números telefónicos y direcciones de correo electrónico, según la información publicada por Target en enero de 2014. Además, se vieron afectados la confianza de los clientes, la reputación de la empresa y sus recursos financieros, debido a los costos de investigación, respuesta y remediación.

---

## A.3 — Matriz CIA


| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | Sí | Los atacantes obtuvieron datos de tarjetas de pago y otra información personal de clientes sin autorización. |
| **Integridad** | No demostrado con la evidencia citada | Las fuentes utilizadas para este informe documentan principalmente el robo de información. No alcanza con la gravedad del incidente para afirmar que se modificaron datos de negocio o transacciones. |
| **Disponibilidad** | No demostrado como impacto principal | La evidencia citada no demuestra una interrupción generalizada de los servicios de compra causada por el ataque. La eliminación del malware y la respuesta al incidente no prueban por sí mismas una violación de disponibilidad. |

**Justificación ampliada de la propiedad más discutible:**

La integridad es la propiedad más difícil de determinar. La presencia de malware en sistemas de punto de venta demuestra que existió una alteración no autorizada del entorno informático, pero eso no prueba automáticamente que los registros de ventas, los importes de las transacciones o las cuentas de los clientes hayan sido modificados. Para declarar una violación de integridad de los datos de negocio sería necesario contar con evidencia específica de esas modificaciones. Por eso, con las fuentes citadas, la respuesta más rigurosa es que no está demostrada.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

| Elemento | En este caso |
|---|---|
| **Amenaza** | Atacantes externos con motivación económica, interesados en robar información financiera y personal para monetizarla. |
| **Vulnerabilidad** | Debilidades en la gestión de accesos de terceros y en la segmentación, supervisión y respuesta frente a actividad maliciosa dentro de la red. El acceso inicial se asoció a credenciales de un proveedor externo. |
| **Activo** | Sistemas de punto de venta, datos de tarjetas de pago e información personal de los clientes. |
| **Impacto** | Exposición de información financiera y personal, riesgo de fraude, costos de respuesta, consecuencias reputacionales y pérdida de confianza. |

En el incidente de Target de 2013, atacantes externos con motivación económica lograron acceder a la infraestructura de la empresa a partir de credenciales asociadas a un proveedor externo. El acceso inicial se combinó con fallas de control que permitieron que la actividad maliciosa avanzara hacia sistemas relacionados con las operaciones comerciales. El malware instalado en los sistemas de punto de venta recolectó información de tarjetas de pago. La amenaza explotó debilidades en la administración de accesos de terceros, la segmentación y la detección oportuna, afectando como activos principales los datos financieros y personales de los clientes. El impacto más claramente documentado fue la pérdida de confidencialidad de esos datos, junto con costos de respuesta y daño a la confianza en la empresa (Target Corporation, 2013, 2014a; U.S. Senate Committee on Commerce, Science, and Transportation, 2014).

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | Acceso de terceros con privilegios mínimos, credenciales individuales y limitadas, autenticación multifactor cuando corresponda, y segmentación estricta entre la red de proveedores y los sistemas de punto de venta. |
| **Propiedad de la tríada que protege** | Principalmente confidencialidad; también reduce la posibilidad de alteraciones no autorizadas y limita el alcance del incidente. |
| **Por qué habría funcionado en este caso concreto** | Si las credenciales de un proveedor se hubieran limitado únicamente a los sistemas necesarios para su tarea, no habrían permitido por sí solas alcanzar sistemas de pago. La segmentación y las reglas de acceso entre zonas habrían dificultado el movimiento lateral desde la red accesible al proveedor hasta los POS. Este control no garantiza que el acceso inicial sea imposible, pero reduce la probabilidad de que se convierta en una intrusión de gran alcance. |

### Control 2

| | |
|---|---|
| **Qué es** | Detección y respuesta de seguridad con monitoreo continuo de los POS, alertas de comportamiento, correlación de eventos y un procedimiento probado para aislar equipos comprometidos. |
| **Propiedad de la tríada que protege** | Principalmente confidencialidad, al reducir el tiempo de extracción de datos; también disponibilidad, al permitir aislar sistemas afectados de forma controlada. |
| **Por qué habría funcionado en este caso concreto** | Una alerta correctamente investigada sobre la ejecución de malware o la extracción anómala de datos podía activar una respuesta antes de que la intrusión afectara a tantas transacciones. La detección debe estar acompañada por un procedimiento de escalamiento y contención: generar alertas sin investigarlas no detiene un ataque. El informe del Senado identificó oportunidades de detección y respuesta que merecían atención durante la cadena del incidente. |

---

## A.6 — Fuentes consultadas (Parte A)

1. **[PRIMARIA]** Target Corporation. (2013, 19 de diciembre). *Target confirms unauthorized access to payment card data in U.S. stores*. https://corporate.target.com/news-features/article/2013/12/target-confirms-unauthorized-access-to-payment-car

2. **[PRIMARIA]** Target Corporation. (2014a). *Annual report 2013: Data breach*. https://corporate.target.com/getmedia/47488c66-8bc8-41d6-834b-80513bba407a/Target_2013_10-K_Report.pdf

3. **[PRIMARIA]** Target Corporation. (2014b, 10 de enero). *An update on our data breach and financial performance*. https://corporate.target.com/news-features/article/2014/01/an-update-on-our-data-breach-and-financial-perform

4. **[PRIMARIA]** U.S. Senate Committee on Commerce, Science, and Transportation. (2014, 25 de marzo). *Rockefeller: Staff report details Target’s missed opportunities to stop massive data breach*. https://www.commerce.senate.gov/press/dem/release/rockefeller-staff-report-details-targets-missed-opportunities-to-stop-massive-data-breach-2014-3/

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

**Nota sobre las evidencias:** las salidas que siguen reflejan resultados compartidos durante las pruebas. Para la entrega final, conviene conservar la salida íntegra del transcript de PowerShell, incluyendo los comandos ejecutados y sus mensajes. No debe atribuirse a la terminal una salida que no se haya registrado realmente.

### Generación del manifiesto

Comando ejecutado:

```powershell
python src\integridad.py generar --dir data\muestra --salida manifest.sha256
```

El programa generó un manifiesto con cuatro archivos indexados. El contenido del manifiesto registrado fue:

```json
{
  "app.bin": "a1f259d4365ed4320c377ce26f5c8c56dcdc9a89e7b641bfd8eabfbbeac86654",
  "logs/acceso.log": "479bb8382eca943570ac69b7189e4feb62d152436f77cafcf551c52ea00c5cd4",
  "politica_seguridad.md": "4f27c493a553b185aebdea570d0cc4aa5763425de0fc91d51a32eb71a4c46393",
  "transferencia.txt": "4394e0a7006eecb79b32dbfa7471fd7121893239fb94e1a7a3269c31b5262334"
}
```

### Verificación sobre un directorio íntegro

Comando ejecutado:

```powershell
python src\integridad.py verificar --dir data\muestra --manifiesto manifest.sha256
```

Salida real compartida:

```text
Directorio:  data\muestra\
Manifiesto:  manifest.sha256\

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          0

INTEGRIDAD VERIFICADA — sin diferencias contra el manifiesto.
```

La ejecución terminó correctamente. El estado observado demuestra que los cuatro archivos coinciden con los digests registrados en el manifiesto.

### Detección de la modificación de un byte

El procedimiento consistió en agregar el carácter `X` al final de `transferencia.txt` y ejecutar nuevamente el verificador. El resultado compartido fue:

- `transferencia.txt` clasificado como **MODIFICADO**.
- Tres archivos permanecieron en estado **OK**.
- El programa finalizó con código de salida `1`.

La prueba demuestra que una modificación de un solo byte cambia el digest SHA-256 y es detectada al compararlo con el valor previamente registrado.

**Para completar esta sección:** pegá desde el transcript la salida original completa del comando de modificación, incluyendo el mensaje de hallazgo y el código de salida.

### Detección de archivo faltante y de archivo nuevo

Se realizaron dos pruebas adicionales.

**Archivo faltante:** se eliminó temporalmente `logs\acceso.log` y se verificó el directorio. El programa informó:

- Tres archivos en estado `OK`.
- Un archivo en estado `FALTANTE`: `logs/acceso.log`.
- Código de salida `1`.

Luego se regeneraron los datos de muestra para restaurar el archivo.

**Archivo nuevo:** se creó `data\muestra\backdoor.sh` con contenido de prueba y se ejecutó el verificador. El programa informó:

- Cuatro archivos en estado `OK`.
- Un archivo en estado `NUEVO`: `backdoor.sh`.
- Código de salida `1`.

Después se eliminó el archivo de prueba. La verificación final confirmó que el directorio volvió a coincidir con el manifiesto.

### Efecto avalancha

Comando ejecutado:

```powershell
python src\integridad.py avalancha --a 'transferencia: $1000' --b 'transferencia: $1001'
```

Salida real compartida:

```text
mensaje A: "transferencia: $1000"
  SHA-256: 341511c4c817d55f30c81e212d0e82b0b16dd5a58d49fe5e45c9d5c998ab794a
mensaje B: "transferencia: $1001"
  SHA-256: 5fb87fd7adf8a226f61c666a3ed140b147501b8a1b8e1822e57fc4b3925323d9

Distancia de Hamming: 139 de 256 bits (54.30 %)
Efecto avalancha: para entradas distintas se espera un valor cercano al 50 %.
```

**Distancia obtenida:** 139 bits de 256 (**54,30 %**).

**¿Coincide con lo esperado? ¿Qué esperaban antes de correrlo?**

Sí. Antes de ejecutar la prueba esperábamos que un cambio pequeño en el mensaje produjera un cambio amplio en el digest. La distancia obtenida fue de 139 bits sobre 256, equivalente al 54,30 %. Este valor es cercano al 50 % esperado estadísticamente para dos entradas distintas procesadas por una función hash criptográfica segura. El resultado es una observación concreta del efecto avalancha; por sí solo no constituye una demostración matemática de la seguridad de SHA-256.

### HMAC

Comando ejecutado:

```powershell
python src\integridad.py mac --clave "secreto" --mensaje "transferir 1000"
```

Salida real compartida:

```text
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

La prueba de verificación con el tag correcto devolvió:

```text
TAG VÁLIDO — el mensaje es auténtico e íntegro.
```

La prueba con un tag alterado devolvió:

```text
TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
```

La ejecución con el tag válido finalizó con código `0`; la ejecución con el tag alterado finalizó con código `1`.

Estos resultados muestran que el programa calcula el HMAC-SHA256 y diferencia entre un tag coincidente y uno que no coincide. La clave compartida permite verificar que el mensaje y el tag corresponden a quien conoce la clave, bajo el supuesto de que esta no haya sido comprometida.

---

## B.2 — Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Recorrido de archivos | Se utiliza `Path.rglob("*")` para recorrer el directorio recursivamente. | Permite incluir archivos en subdirectorios, como `logs/acceso.log`, sin depender de una lista fija de nombres. |
| Rutas del manifiesto | Se registran rutas relativas en formato POSIX mediante `as_posix()`. | Facilita la portabilidad del manifiesto entre Windows y otros sistemas operativos. |
| Exclusión del manifiesto | Se excluye el propio archivo de salida mediante rutas normalizadas con `resolve()`. | Evita que el manifiesto se incluya a sí mismo y cambie su digest al escribirse. |
| Lectura de archivos | SHA-256 se calcula leyendo en modo binario por bloques de 64 KiB. | Evita la decodificación de contenido binario y mantiene acotado el uso de memoria. |
| Orden del manifiesto | Las rutas se ordenan alfabéticamente antes de serializarse. | Produce resultados deterministas y facilita comparar versiones. |
| Comparación de HMAC | Se utiliza `hmac.compare_digest()` para comparar el tag calculado con el recibido. | Evita la comparación ordinaria que puede revelar información temporal sobre coincidencias parciales. |

---

## B.3 — Preguntas de análisis

> **Se responden con fundamento técnico, no con opinión.** Dos o tres párrafos
> cada una. Las respuestas de una línea no suman puntos.

### 1. El manifiesto por sí solo no alcanza

*Un atacante con acceso de escritura al directorio también puede escribir
`manifest.sha256`. ¿Qué le impide modificar un archivo y regenerar el
manifiesto para que todo dé `OK`? ¿Qué habría que cambiar en el esquema para
que ese ataque no funcione?*

**Respuesta:**

Un manifiesto de hashes permite detectar cambios respecto de una referencia confiable, pero no garantiza por sí mismo que esa referencia sea auténtica. Si un atacante puede modificar tanto un archivo como `manifest.sha256`, puede cambiar el contenido y volver a calcular su SHA-256. Cuando el verificador compare el archivo modificado contra el nuevo digest, el resultado será `OK`, aunque el contenido original haya sido alterado.

Para impedir ese escenario, el manifiesto debe protegerse con un mecanismo de autenticidad independiente del directorio que se verifica. Una alternativa es firmarlo digitalmente y verificar la firma con una clave pública que el atacante no pueda reemplazar. Otra opción es guardar el manifiesto en un sistema remoto de solo lectura, con control de acceso y registro de auditoría, o utilizar un HMAC cuya clave secreta se almacene fuera del alcance del atacante. En todos los casos, la seguridad depende de proteger la clave o la referencia confiable.

Por lo tanto, el hash responde a la pregunta «¿el archivo coincide con este digest?», pero no responde por sí solo «¿quién generó este digest?» ni «¿el digest de referencia es legítimo?». Esas garantías requieren un mecanismo adicional de autenticación y protección del manifiesto.

---

### 2. Qué agrega HMAC y qué no

*¿Qué propiedad de seguridad aporta HMAC que un hash simple no aporta? Y la
parte importante: ¿qué **no** resuelve HMAC? Pensá en el no repudio y en
quién conoce la clave.*

**Respuesta:**

HMAC combina una función hash con una clave secreta compartida. En este laboratorio se utiliza HMAC-SHA256. Quien conoce la clave puede calcular un tag válido para el mensaje; quien no la conoce no debería poder producir uno válido de manera factible. Así, HMAC agrega autenticación del mensaje e integridad frente a participantes que no poseen la clave, siempre que la clave se mantenga secreta y se use correctamente.

Sin embargo, HMAC no cifra el contenido. Si un atacante intercepta el mensaje, puede leerlo si no existe un mecanismo de confidencialidad adicional. Tampoco evita por sí solo la repetición de un mensaje válido: si una aplicación necesita impedir que una orden antigua vuelva a utilizarse, debe incorporar controles como números de secuencia, marcas de tiempo, identificadores únicos o estados de operación.

Además, HMAC no proporciona no repudio entre los participantes que comparten la clave. Cualquiera que conozca la misma clave puede generar un tag válido, por lo que un tercero no puede demostrar criptográficamente cuál de los poseedores de la clave produjo un mensaje. Para un esquema de no repudio suele requerirse una firma digital con claves privadas individuales y una infraestructura adecuada de validación.

---

### 3. MD5 y SHA-1

*Ambos siguen apareciendo en software en producción. ¿Qué propiedad
criptográfica se les rompió, exactamente? ¿Hay algún uso en el que todavía
sean aceptables, o ninguno? Fundamentá con al menos una fuente.*

**Respuesta:**
Las propiedades criptográficas comprometidas de MD5 y SHA-1 son principalmente su resistencia a colisiones: existen técnicas prácticas para construir entradas diferentes que producen el mismo digest. Una colisión no significa que todos sus usos hayan dejado de funcionar ni que sea posible recuperar automáticamente el mensaje original a partir del hash. Sin embargo, debilita su uso como prueba criptográfica de integridad cuando un atacante puede preparar contenidos deliberadamente.

Para nuevas aplicaciones que requieran resistencia a colisiones se debe preferir una función moderna, como SHA-256, de la familia SHA-2, o una función segura apropiada para el propósito. MD5 y SHA-1 pueden seguir apareciendo en contextos heredados o como identificadores no adversariales, pero no deberían elegirse para nuevas firmas digitales ni para validar la integridad frente a un atacante capaz de crear colisiones. La elección debe considerar el protocolo completo y sus requisitos de seguridad, no solamente el nombre del algoritmo.

**Fuente:**

---

### 4. Comparación en tiempo constante

*¿Por qué comparar un tag de autenticación con `==` puede filtrar información
al atacante, y cómo lo evita `hmac.compare_digest()`? Describí el ataque
concreto que esto previene.*

**Respuesta:**
Una comparación ordinaria de cadenas puede terminar tan pronto como detecta una diferencia. Según la implementación, el tiempo de ejecución puede depender de la longitud del prefijo que coincide entre el tag recibido y el esperado. Si un atacante puede enviar muchas pruebas y medir el tiempo con suficiente precisión, podría intentar inferir información sobre el tag válido a partir de diferencias temporales. Este tipo de canal lateral se conoce como ataque de temporización.

`hmac.compare_digest()` está diseñado para evitar el comportamiento de comparación que se detiene según el contenido coincidente. Por eso resulta apropiado para comparar tags de autenticación. No elimina todos los posibles canales laterales de una aplicación, y las diferencias de longitud o de tipo todavía requieren tratamiento cuidadoso, pero reduce el riesgo específico de filtrar información mediante una comparación basada en coincidencias parciales. En la implementación del laboratorio, el tag calculado y el recibido se convierten a bytes antes de la comparación.

---

### 5. SHA-256 para contraseñas: mala idea

*SHA-256 es una función de hash criptográfica sólida. ¿Por qué, entonces, es
una mala elección para almacenar contraseñas? ¿Qué se usa en su lugar y qué
propiedad tienen esas funciones que SHA-256 no tiene?*

**Respuesta:**
SHA-256 es una función hash criptográfica adecuada para muchos usos de integridad, pero es rápida. Esa velocidad resulta perjudicial para almacenar contraseñas: si una base de datos se filtra, un atacante puede probar grandes cantidades de contraseñas candidatas por segundo y comparar sus hashes con los almacenados. Una contraseña débil puede descubrirse por fuerza bruta o mediante diccionarios, incluso cuando se utiliza un hash criptográfico conocido.

Para almacenar contraseñas se recomiendan funciones especializadas, como Argon2id, scrypt, bcrypt o PBKDF2, con parámetros de costo apropiados y un salt único por contraseña. Estas funciones hacen que cada intento de derivación sea más costoso; algunas, como Argon2id y scrypt, también consumen memoria de manera deliberada. El salt evita que contraseñas iguales produzcan siempre el mismo resultado y dificulta el uso de tablas precalculadas. El objetivo no es impedir matemáticamente toda adivinación, sino aumentar el costo de cada intento y hacer que los ataques masivos resulten mucho más caros.

**Fuente:** OWASP Foundation. (s. f.). *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

---

# Cierre

## Dificultades encontradas

Una de las principales dificultades fue diferenciar la integridad del contenido de la mera existencia de un archivo. La verificación no podía limitarse a recalcular hashes de los archivos que estuvieran presentes: también debía identificar archivos esperados que faltaran y archivos adicionales que no estuvieran en el manifiesto.

Las pruebas permitieron comprender por qué es necesario comparar el directorio completo contra una referencia previa. Al modificar un byte de `transferencia.txt`, el programa detectó el estado `MODIFICADO`. Al eliminar `logs/acceso.log`, informó `FALTANTE`; al crear `backdoor.sh`, informó `NUEVO`. Finalmente, se regeneraron los datos de muestra y la verificación terminó con cuatro archivos `OK`, sin diferencias contra el manifiesto.

Otra dificultad conceptual fue distinguir lo que demuestra un hash de lo que demuestra HMAC. El hash permite comparar el contenido con un digest de referencia, pero no autentica por sí solo quién generó ese digest. HMAC incorpora una clave secreta y permite verificar un tag, aunque no cifra el mensaje ni proporciona no repudio entre quienes comparten la clave.

---

## Distribución del trabajo

| Integrante | Aportes |
|---|---|
| [Hebe Del Lourdes Milanesio] | [Describir aportes reales al análisis del incidente, fuentes y cronología] |

---

## Declaración de uso de asistentes de IA

> **Obligatoria.** No está prohibido usar asistentes de IA. Lo que se evalúa es
> que entiendan lo que entregan. La omisión de esta declaración es **causal de
> rechazo automático** de la entrega. Una declaración honesta no baja la nota.

**¿El grupo usó asistentes de IA en este trabajo?**  Sí / No

*Si la respuesta es No, firmen igual la sección y pasen al final.*

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| ChatGPT | Apoyo para estructurar la redacción, explicar conceptos de seguridad y organizar las referencias. | Borradores del informe, respuestas de análisis y mini-research. | Se contrastaron las afirmaciones con fuentes técnicas y oficiales, y las pruebas de código se verificaron mediante ejecuciones reales en PowerShell. |


**Declaración:**

*El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del análisis,
independientemente de la asistencia recibida.*

---

## Fuentes consultadas (general)

1. Target Corporation. (2013, 19 de diciembre). *Target confirms unauthorized access to payment card data in U.S. stores*. https://corporate.target.com/news-features/article/2013/12/target-confirms-unauthorized-access-to-payment-car
2. Target Corporation. (2014a). *Annual report 2013: Data breach*. https://corporate.target.com/getmedia/47488c66-8bc8-41d6-834b-80513bba407a/Target_2013_10-K_Report.pdf
3. Target Corporation. (2014b, 10 de enero). *An update on our data breach and financial performance*. https://corporate.target.com/news-features/article/2014/01/an-update-on-our-data-breach-and-financial-perform
4. U.S. Senate Committee on Commerce, Science, and Transportation. (2014, 25 de marzo). *Rockefeller: Staff report details Target’s missed opportunities to stop massive data breach*. https://www.commerce.senate.gov/press/dem/release/rockefeller-staff-report-details-targets-missed-opportunities-to-stop-massive-data-breach-2014-3/
5. OWASP Foundation. (s. f.). *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
6. Python Software Foundation. (s. f.). *hmac — Keyed-Hashing for Message Authentication*. https://docs.python.org/3/library/hmac.html

