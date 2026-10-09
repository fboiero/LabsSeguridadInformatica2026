# Laboratorio 01 — Informe

---

## Identificación

| | |
|---|---|
| **Grupo** | 14 |
| **Caso asignado (Parte A)** | 2 — Target (brecha de datos de tarjetas, 2013) |
| **Tema del mini-research** | 4 — Criptografía post-cuántica |
| **Fecha de entrega** | *(completar)* |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Valentina Chiapero | *(completar)* | @*(completar)* |
| Fede Peron | *(completar)* | @fedeeperon |
| Laureano Gomez Redondo | *(completar)* | @Laureano-GR |
| Martín Cesano | *(completar)* | @*(completar)* |
| *(completar)* | *(completar)* | @martingaidoo |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha | Hecho | Fuente |
|---|---|---|
| Sep. 2013 | Un asesor externo certifica a Target como conforme con PCI-DSS. Ese mismo mes, aproximadamente, los atacantes ya habían robado por phishing las credenciales de Fazio Mechanical Services, contratista de climatización con acceso remoto al portal de proveedores de Target. | Senado de EE. UU. (2014), pp. 4–5, 7 y fig. 6; Krebs (2014) |
| 15 nov. 2013 | Primer ingreso a la red de Target con las credenciales del proveedor. Hay otra fuente que lo ubica el 12/11. | Krebs (2014); Senado de EE. UU. (2014), p. 3 |
| 15–28 nov. 2013 | Los atacantes prueban un malware de tipo *RAM scraper* (variante de BlackPOS) en algunas terminales de punto de venta (POS). | Senado de EE. UU. (2014), pp. 2–3 |
| 30 nov. 2013 | El malware ya está en la mayoría de los POS. Se instala el malware de exfiltración en servidores internos. FireEye emite alertas y Symantec detecta actividad maliciosa en el mismo servidor, pero nadie responde. | Senado de EE. UU. (2014), p. 3 |
| 2 dic. 2013 | Empieza la exfiltración por FTP hacia servidores externos, uno de ellos en Rusia. Se disparan nuevas alertas de FireEye. | Senado de EE. UU. (2014), pp. 3–4, 11 |
| 12 dic. 2013 | El Departamento de Justicia notifica a Target. | Senado de EE. UU. (2014), p. 1 |
| 15 dic. 2013 | Target confirma la intrusión y elimina la mayor parte del malware. | Senado de EE. UU. (2014), fig. 6 |
| 19 dic. 2013 | Target anuncia públicamente que se comprometieron cerca de 40 millones de tarjetas de crédito y débito usadas entre el 27/11 y el 15/12. | Target Corporation (2013) |
| 10 ene. 2014 | Target informa que también se robaron nombres, direcciones postales, teléfonos o correos de hasta 70 millones de personas. | Target Corporation (2014) |
| 23 may. 2017 | Acuerdo de USD 18,5 millones con 46 estados y el Distrito de Columbia por la brecha. | Fiscalía General de Virginia (2017) |

---

## A.2 — Activo afectado

**Activo principal:** los datos de las tarjetas de pago de los clientes de las tiendas físicas de Target en EE. UU.: nombre, número de tarjeta, fecha de vencimiento, código de seguridad y datos de la banda magnética (*track data*). En el caso de las tarjetas de débito, también el PIN cifrado. Estos datos estaban en la memoria RAM de las terminales POS mientras se procesaba cada compra, en texto plano, antes de enviarse cifrados al procesador de pagos (Senado de EE. UU., 2014, p. 2; Target Corporation, 2013).

**Por qué es el principal:** es el dato que los atacantes fueron a buscar. Todo el ataque (el malware hecho a medida para POS y la infraestructura de exfiltración) apuntaba a esos datos. Además tiene valor de reventa inmediato: las tarjetas aparecieron a la venta en mercados clandestinos días después (Senado de EE. UU., 2014, p. 1–2). Con el *track data* se pueden clonar tarjetas físicas, y con el PIN se puede retirar efectivo de cajeros.

**Otros activos afectados:**

1. **Datos personales no financieros de hasta 70 millones de clientes** (nombre, dirección postal, teléfono, email), guardados en sistemas internos de Target que no son los POS (Target Corporation, 2014). Van en segundo lugar porque no permiten un fraude financiero directo, aunque sí facilitan el phishing dirigido contra esos clientes.
2. **Las credenciales de acceso de Fazio Mechanical al portal de proveedores** de Target. No eran el objetivo, sino el medio de ingreso. Las listamos porque su compromiso fue la condición necesaria para todo lo demás.

---

## A.3 — Matriz CIA

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | **Sí** | Los datos de unas 40 millones de tarjetas y los datos personales de hasta 70 millones de personas se copiaron y se transfirieron por FTP a servidores externos controlados por los atacantes, al menos uno en Rusia (Senado de EE. UU., 2014, pp. 3–4, 11). Las tarjetas se ofrecieron a la venta en mercados clandestinos (p. 1–2). |
| **Integridad** | **Parcial** | Los datos de los clientes **no** fueron alterados: se copiaron, no se modificaron. Lo que sí se alteró sin autorización fue el **software de las terminales POS y de servidores internos**: se instaló BlackPOS en las cajas y un malware de exfiltración disfrazado de un producto legítimo de BMC Software (Senado de EE. UU., 2014, pp. 2–3, 5). |
| **Disponibilidad** | **No** | No hay evidencia de que las tiendas, las cajas o los sistemas de pago dejaran de funcionar. Al contrario, el ataque *necesitaba* que los POS siguieran operando con normalidad para capturar más tarjetas. Los datos robados siguieron disponibles para Target y para sus clientes. |

**Justificación ampliada de la propiedad más discutible:**

La más difícil fue **integridad**. Si se mira solo el activo principal (los datos de tarjetas), la respuesta es «No»: ningún número de tarjeta, saldo ni registro de cliente se modificó, y el daño vino de que alguien más los *leyó*. Por eso no marcamos «Sí».

Tampoco marcamos «No», porque el incidente incluye una modificación no autorizada concreta y verificable: el código que ejecutaban las terminales POS dejó de ser el que Target había instalado. ISO/IEC 27000 define integridad como la propiedad de exactitud y completitud, y eso aplica tanto a la información como a los sistemas que la procesan. Un POS con BlackPOS ya no es exacto: además de procesar el pago, copia la tarjeta. Esta alteración fue el **mecanismo** que permitió violar la confidencialidad, no el fin del ataque. Por eso la calificamos como **Parcial**: se violó la integridad de los sistemas, pero no la de los datos del activo principal. El mismo informe del Senado señala que PCI-DSS 11.5 exigía monitorear la integridad de archivos críticos de sistema (p. 10). Es exactamente el control que implementamos en la Parte B, y de haber estado operativo sobre los POS habría detectado esta violación.

Disponibilidad es claramente «No». La reemisión masiva de tarjetas que hicieron los bancos es un *impacto* económico del incidente, no una pérdida de disponibilidad del activo.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

| Elemento | En este caso |
|---|---|
| **Amenaza** *(quién / qué, con qué motivación)* | Un grupo de ciberdelincuentes con motivación económica, que monetiza vendiendo tarjetas robadas en mercados clandestinos («card shops»). |
| **Vulnerabilidad** *(la debilidad concreta que se explotó)* | Dos debilidades encadenadas: (1) el acceso remoto de un proveedor externo protegido solo con usuario y contraseña, sin segundo factor; (2) la falta de segmentación entre ese portal de proveedores y la red donde están los POS y los datos de tarjetas. De fondo, también estuvo la falta de respuesta a las alertas de FireEye. |
| **Activo** *(sobre qué recayó)* | Los datos de tarjetas de pago procesados en los POS de las tiendas de EE. UU. y, en segundo lugar, los datos personales de hasta 70 millones de clientes. |
| **Impacto** *(consecuencia sobre el negocio o las personas)* | Para los clientes: riesgo de fraude con tarjetas clonadas y de phishing. Para Target y los bancos: reemisión masiva de tarjetas, costos de investigación, demandas y un acuerdo de USD 18,5 millones con 46 estados y el Distrito de Columbia, además del daño reputacional. |

**Redacción:**

Un grupo de ciberdelincuentes con motivación económica (la **amenaza**) primero robó por phishing las credenciales de Fazio Mechanical, un proveedor de climatización. Con ellas **explotó** una **vulnerabilidad** de Target: el acceso remoto de proveedores dependía solo de una contraseña y no estaba aislado de la red interna. Desde ese punto de entrada se movió hasta las cajas e instaló BlackPOS. Ese malware no es la vulnerabilidad, sino la herramienta con la que se aprovechó el acceso obtenido. Así leyó desde la memoria de los POS los datos de unas 40 millones de tarjetas, que son el **activo**, y además extrajo datos personales de hasta 70 millones de clientes. Todo se exfiltró a servidores externos. Eso **produjo** un **impacto** que no es el ataque en sí, sino sus consecuencias: fraude potencial para los titulares, reemisión de tarjetas para los bancos y, para Target, costos legales y reputacionales, incluido un acuerdo de USD 18,5 millones con 46 estados y el Distrito de Columbia.

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | Segmentación de red del entorno de datos de tarjetas (CDE), combinada con autenticación multifactor obligatoria para todo acceso remoto de proveedores. El portal de proveedores queda en una zona aislada que no tiene rutas hacia los POS ni hacia los servidores del CDE. |
| **Propiedad de la tríada que protege** | Confidencialidad de los datos de tarjetas. |
| **Por qué habría funcionado en este caso concreto** | El ataque se apoyó en dos hechos: que la credencial de Fazio servía sola, porque Target rara vez exigía doble factor a contratistas de bajo nivel, y que desde ese acceso se podía llegar a los POS, porque el portal externo «no estaba completamente aislado del resto de la red» (Senado de EE. UU., 2014, pp. 5, 8). Con MFA, la contraseña robada por phishing no habría bastado para entrar. Y aun con la credencial válida, la segmentación habría dejado al atacante encerrado en un sistema de facturación sin conexión con las cajas. Fazio solo necesitaba el acceso para facturación, contratos y gestión de proyectos (p. 4), así que el control no afectaba su trabajo. |

### Control 2

| | |
|---|---|
| **Qué es** | Lista blanca de aplicaciones (*application allowlisting*) combinada con monitoreo de integridad de archivos (FIM) en las terminales POS y en los servidores del CDE. Solo pueden ejecutarse binarios con hash aprobado, y cualquier cambio en archivos de sistema genera una alerta con respuesta obligatoria. |
| **Propiedad de la tríada que protege** | Integridad de los sistemas POS y, de forma derivada, confidencialidad de los datos de tarjetas. |
| **Por qué habría funcionado en este caso concreto** | Para robar los datos, los atacantes tuvieron que **instalar código nuevo** en las cajas (BlackPOS) y en servidores internos (el malware de exfiltración disfrazado de BMC), entre el 15 y el 30 de noviembre. Un POS es un sistema de función fija: el conjunto de binarios legítimos es chico y conocido, así que la lista blanca es viable. Con ella, BlackPOS no habría podido ejecutarse porque su hash no estaba aprobado. El informe del Senado propone exactamente este control (p. 10) y recuerda que PCI-DSS 11.5 ya exigía monitorear la integridad de archivos críticos. A diferencia de las alertas de FireEye, que el equipo de Target ignoró, una lista blanca **bloquea por defecto** y no depende de que un analista interprete correctamente una alerta genérica («malware.binary»). |

---

## A.6 — Fuentes consultadas (Parte A)

1. **[PRIMARIA]** U.S. Senate Committee on Commerce, Science, and Transportation. (2014, 26 de marzo). *A "kill chain" analysis of the 2013 Target data breach* (Majority staff report for Chairman Rockefeller). https://www.commerce.senate.gov/services/files/24d3c229-4f2f-405d-b8db-a3a67f183883
2. **[PRIMARIA]** Target Corporation. (2013, 19 de diciembre). *Target confirms unauthorized access to payment card data in U.S. stores* [Comunicado de prensa]. https://corporate.target.com/press/release/2013/12/target-confirms-unauthorized-access-to-payment-card-data-in-u-s-stores
3. **[PRIMARIA]** Target Corporation. (2014, 10 de enero). *Target provides update on data breach and financial performance* [Comunicado de prensa]. https://corporate.target.com/press/release/2014/01/target-provides-update-on-data-breach-and-financial-performance
4. **[PRIMARIA]** Office of the Attorney General of Virginia. (2017, 23 de mayo). *Target Corporation to pay $18.5M over 2013 data breach* [Comunicado de prensa]. https://oag.state.va.us/consumer-protection/index.php/news/209-may-23-2017-target-corporation-to-pay-18-5m-over-2013-data-breach
5. **[SECUNDARIA]** Krebs, B. (2014, 5 de febrero). *Target hackers broke in via HVAC company*. KrebsOnSecurity. https://krebsonsecurity.com/2014/02/target-hackers-broke-in-via-hvac-company/

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

*Pegá la salida real de cada comando. No la transcribas a mano: copiala tal
cual sale de la terminal.*

### Generación del manifiesto

```
$ python3 src/integridad.py generar --dir data/muestra --salida manifest.sha256

(pegar salida)
```

### Verificación sobre un directorio íntegro

```
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"

(pegar salida)
```

### Detección de la modificación de un byte

*Esta prueba es obligatoria y tiene una penalización específica en la rúbrica
si falla.*

```
$ printf 'X' >> data/muestra/transferencia.txt
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"

(pegar salida — debe reportar MODIFICADO y salir con 1)
```

### Detección de archivo faltante y de archivo nuevo

```
(pegar los comandos que usaron y la salida)
```

### Efecto avalancha

```
$ python3 src/integridad.py avalancha --a "transferencia: $1000" --b "transferencia: $1001"

(pegar salida)
```

**Distancia obtenida:** ____ bits de 256 (____ %)

*¿Coincide con lo esperado? ¿Qué esperaban antes de correrlo?*

### HMAC

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"

(pegar salida)
```

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar <tag válido>
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar <tag alterado>

(pegar ambas salidas)
```

---

## B.2 — Decisiones de implementación

*Qué decisiones tuvieron que tomar que el enunciado no resolvía por ustedes.
Ejemplos: cómo trataron los enlaces simbólicos, qué hicieron con los archivos
vacíos, cómo excluyeron el manifiesto del recorrido, qué pasa si el directorio
está vacío. Una o dos oraciones por decisión.*

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| | | |
| | | |

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

---

### 2. Qué agrega HMAC y qué no

*¿Qué propiedad de seguridad aporta HMAC que un hash simple no aporta? Y la
parte importante: ¿qué **no** resuelve HMAC? Pensá en el no repudio y en
quién conoce la clave.*

**Respuesta:**

---

### 3. MD5 y SHA-1

*Ambos siguen apareciendo en software en producción. ¿Qué propiedad
criptográfica se les rompió, exactamente? ¿Hay algún uso en el que todavía
sean aceptables, o ninguno? Fundamentá con al menos una fuente.*

**Respuesta:**

**Fuente:**

---

### 4. Comparación en tiempo constante

*¿Por qué comparar un tag de autenticación con `==` puede filtrar información
al atacante, y cómo lo evita `hmac.compare_digest()`? Describí el ataque
concreto que esto previene.*

**Respuesta:**

---

### 5. SHA-256 para contraseñas: mala idea

*SHA-256 es una función de hash criptográfica sólida. ¿Por qué, entonces, es
una mala elección para almacenar contraseñas? ¿Qué se usa en su lugar y qué
propiedad tienen esas funciones que SHA-256 no tiene?*

**Respuesta:**

---

# Cierre

## Dificultades encontradas

*Qué les costó, dónde se trabaron, qué decidieron y por qué. Esta sección se
lee y suma. No es relleno: es donde se ve si entendieron el problema.*

---

## Distribución del trabajo

*Quién hizo qué. Tiene que ser consistente con el historial de commits.*

| Integrante | Aportes |
|---|---|
| | |
| | |
| | |
| | |
| | |

---

## Declaración de uso de asistentes de IA

> **Obligatoria.** No está prohibido usar asistentes de IA. Lo que se evalúa es
> que entiendan lo que entregan. La omisión de esta declaración es **causal de
> rechazo automático** de la entrega. Una declaración honesta no baja la nota.

**¿El grupo usó asistentes de IA en este trabajo?**  Sí / No

*Si la respuesta es No, firmen igual la sección y pasen al final.*

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| | | | |
| | | | |

**Declaración:**

*El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del análisis,
independientemente de la asistencia recibida.*

---

## Fuentes consultadas (general)

*Todas las fuentes del trabajo, en formato APA. Las de la Parte A pueden
repetirse acá o referenciarse a la sección A.6.*

1.
2.
3.
