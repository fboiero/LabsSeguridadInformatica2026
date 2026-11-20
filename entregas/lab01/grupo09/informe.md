# Laboratorio 01 — Informe

## Identificación

| | |
|---|---|
| **Grupo** | 09 |
| **Caso asignado (Parte A)** | WannaCry (2017) — asignado por `número_de_grupo mod 6` = `9 mod 6` = 3 |
| **Tema del mini-research** | Tema 3 — La disponibilidad, la propiedad descuidada de la tríada |
| **Fecha de entrega** | 2026-11-20 |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Santiago Cocchi | 15271 | @santicocchi |
| Franco Ferraro | 14973 | @francovalentin08 |
| Francisco Mossello | 15339 | @FranMossello |
| Tomas Spat | 15055 | @TomiSpat |
| Santiago Torres | 15059 | @santy500 |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha | Hecho | Fuente |
|---|---|---|
| 2017-03-14 | Microsoft publica el boletín **MS17-010**, que parchea la vulnerabilidad en el protocolo SMBv1 que después explotaría WannaCry. | CISA, *Alert TA17-132A — Indicators Associated With WannaCry Ransomware* ([cisa.gov/ncas/alerts/TA17-132A](https://www.cisa.gov/ncas/alerts/TA17-132A)) |
| 2017-05-12 (madrugada) | Comienza la propagación masiva del ransomware. Telefónica (España) está entre las primeras víctimas reportadas. | CISA, *Alert TA17-132A* |
| 2017-05-12 | El investigador Marcus Hutchins registra el dominio "kill switch" codificado en el binario del malware, lo que frena la propagación de la variante inicial. | Check Point Research, *"WannaCry Ransomware"* ([checkpoint.com/cyber-hub/threat-prevention/ransomware/wannacry-ransomware](https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/wannacry-ransomware/)) |
| 2017-05-12/14 | Europol confirma más de 200.000 equipos infectados en más de 150 países, y describe el ataque como "de un nivel sin precedentes". | Europol, declaración oficial de mayo de 2017, recogida en *Global Security* ([globalsecurity.org/security/library/news/2017/05/sec-170514-voa01.htm](https://www.globalsecurity.org/security/library/news/2017/05/sec-170514-voa01.htm)) |
| 2017-05-13 | Microsoft publica parches de emergencia **fuera de su ciclo normal**, incluso para sistemas sin soporte (Windows XP, 8, Server 2003). | CISA, *Alert TA17-132A* (recomienda aplicar el parche MS17-010 o, si no es posible, deshabilitar SMBv1) |
| 2017-10-27 | El **National Audit Office** del Reino Unido publica la investigación oficial sobre el impacto en el NHS: decenas de *trusts* hospitalarios afectados y miles de citas canceladas. | National Audit Office (UK), *"Investigation: WannaCry cyber attack and the NHS"* ([nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs](https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/)) |

---

## A.2 — Activo afectado

**Activo principal:** la **disponibilidad operativa de los sistemas de información clínicos y administrativos del NHS** (Reino Unido) — específicamente estaciones de trabajo, sistemas de imágenes y de gestión de turnos en hospitales afectados, corriendo versiones de Windows sin el parche MS17-010 aplicado. No es "los datos del NHS" en abstracto: es la capacidad de los equipos de atención primaria y hospitalaria de **usar sus propios sistemas** para atender pacientes.

**Por qué es el principal:** porque es el activo cuya pérdida produjo el impacto más directo y medible sobre personas reales — según el informe de la National Audit Office (2017), decenas de *trusts* del NHS tuvieron que cancelar o derivar atención, con miles de citas y procedimientos reprogramados. A diferencia de otras víctimas (empresas que perdieron productividad administrativa), acá el activo indisponible estaba directamente en la cadena de atención médica.

**Otros activos afectados:** (1) la continuidad operativa de otras organizaciones a nivel global (Telefónica en España, Renault-Nissan en sus plantas de manufactura, Deutsche Bahn en Alemania — los sistemas de producción y de información al público quedaron indisponibles); (2) en menor medida, la confidencialidad **no** fue el vector de este incidente: WannaCry es un ransomware de cifrado, no de exfiltración, así que el "activo" que compromete es el acceso al propio dato, no su secreto.

---

## A.3 — Matriz CIA

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | **No** | WannaCry cifra archivos localmente y pide rescate; no hay evidencia reportada por CISA, Europol ni el informe de la NAO de que el malware exfiltrara datos a un servidor del atacante. El objetivo del binario es bloquear el acceso, no robar información. |
| **Integridad** | **No** (en sentido estricto) | Los archivos no quedan "alterados" en el sentido de que su contenido cambie de forma legible o utilizable de otro modo: quedan **cifrados en el mismo lugar**, con la misma estructura de bytes transformada reversiblemente (si se paga o se obtiene la clave). No es el mismo mecanismo que, por ejemplo, un atacante editando campos de una base de datos para que digan algo distinto. El dato no fue "modificado para mentir": fue vuelto inaccesible. |
| **Disponibilidad** | **Sí** | Es la violación central y documentada: el NAO reporta decenas de hospitales y *trusts* del NHS sin acceso a sus sistemas, con citas y cirugías canceladas (National Audit Office, 2017); CISA y Europol documentan cientos de miles de equipos inoperables en más de 150 países en el mismo fin de semana. |

**Justificación ampliada de la propiedad más discutible:**

La más discutible es **Integridad**, precisamente porque "ransomware" suena a que algo se "corrompió" o se "dañó", y es tentador marcar que sí se violó. Pero la tríada CIA distingue la propiedad por su definición técnica, no por la sensación de gravedad del incidente. Integridad significa que el dato **sigue siendo exacto y no fue alterado sin autorización de forma que su contenido quede falseado**. El cifrado de WannaCry no falsea el contenido del archivo: lo vuelve ilegible sin la clave, pero los bytes cifrados son una transformación matemática reversible del original, no una modificación de su significado. Es un matiz importante: si alguien después restaura el archivo desde un backup anterior al ataque, el dato "restaurado" es exactamente el mismo que había — no hubo alteración de contenido que sobreviva al incidente, hubo **pérdida de acceso** a ese contenido. Por eso la violación real y comprobable es Disponibilidad, no Integridad.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

| Elemento | En este caso |
|---|---|
| **Amenaza** | Un actor malicioso no identificado con certeza públicamente (atribuciones posteriores de EE.UU., Reino Unido y otros gobiernos señalaron a Corea del Norte), con motivación de extorsión masiva mediante ransomware auto-propagable. |
| **Vulnerabilidad** | Una falla en la implementación del protocolo **SMBv1** de Windows, parcheada por Microsoft el 14/03/2017 (MS17-010), pero **sin aplicar** en un enorme número de sistemas en producción — incluidos equipos con sistemas operativos ya sin soporte oficial (Windows XP, Server 2003). |
| **Activo** | Los sistemas de información operativos de organizaciones que no habían aplicado el parche, con el caso del NHS (Reino Unido) como el de mayor impacto documentado sobre personas. |
| **Impacto** | Indisponibilidad masiva y simultánea de esos sistemas: en el NHS, cancelación de miles de citas y procedimientos; a nivel global, más de 200.000 equipos afectados en 150+ países en un fin de semana (Europol, 2017). |

**Redacción:**

La amenaza —un actor que buscaba extorsionar a gran escala— explotó una vulnerabilidad concreta y conocida en el protocolo SMBv1 de Windows (parcheada dos meses antes del ataque, el 14 de marzo de 2017, mediante MS17-010) sobre un activo específico: los sistemas operativos de organizaciones, entre ellas el NHS británico, que no habían aplicado ese parche a tiempo. El resultado no fue el robo de información ni su alteración encubierta, sino la **pérdida de disponibilidad** de esos sistemas: el NAO documentó decenas de hospitales incapaces de operar normalmente, con el consiguiente impacto directo sobre la atención de pacientes reales. La cadena completa muestra algo central para este curso: el exploit (EternalBlue, filtrado por el grupo Shadow Brokers) no creó la vulnerabilidad, solo la hizo utilizable a gran escala — la vulnerabilidad ya existía y ya tenía parche disponible; lo que faltó fue **gestión de parches**, no una falla sin solución conocida.

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | Gestión sistemática de parches (*patch management*) con un proceso formal de aplicación prioritaria de actualizaciones de seguridad críticas, especialmente las clasificadas como de explotación remota sin interacción del usuario. |
| **Propiedad de la tríada que protege** | Disponibilidad (y, de forma indirecta, también protege contra el vector que habilitó la pérdida de disponibilidad en este caso). |
| **Por qué habría funcionado en este caso concreto** | El parche MS17-010 estuvo disponible públicamente **dos meses** antes del ataque (14/03/2017 vs. 12/05/2017). El propio informe del NAO (2017) señala que el NHS conocía el riesgo de sistemas desactualizados y no había actuado sobre advertencias previas. Aplicar ese parche específico en ese período habría cerrado la vía de entrada de WannaCry en los equipos afectados del NHS, sin necesidad de ningún otro control adicional. |

### Control 2

| | |
|---|---|
| **Qué es** | Segmentación de red (microsegmentación) que limite la propagación lateral de SMB entre estaciones de trabajo, de forma que un equipo infectado no pueda escanear y contagiar automáticamente a toda la red interna. |
| **Propiedad de la tríada que protege** | Disponibilidad. |
| **Por qué habría funcionado en este caso concreto** | Lo que volvió a WannaCry devastador no fue solo que explotara una vulnerabilidad, sino que **se auto-propagaba por la red local** escaneando otros hosts con SMBv1 expuesto (CISA, Alert TA17-132A). En una red del NHS sin segmentación entre departamentos/hospitales, un solo equipo sin parchear pudo contagiar a muchos otros dentro de la misma red plana. Con segmentación (VLANs separadas, reglas de firewall interno que restrinjan el tráfico SMB entre segmentos no relacionados), el radio de impacto de un único equipo comprometido se habría limitado drásticamente, reduciendo la cantidad de sistemas indisponibles aunque el parche no se hubiera aplicado a tiempo en todos lados. |

---

## A.6 — Fuentes consultadas (Parte A)

1. [PRIMARIA] CISA (2017, 12 de mayo; revisado 15 de mayo). *Alert TA17-132A: Indicators Associated With WannaCry Ransomware*. Cybersecurity and Infrastructure Security Agency. https://www.cisa.gov/ncas/alerts/TA17-132A
2. [PRIMARIA] National Audit Office (Reino Unido). (2017, 27 de octubre). *Investigation: WannaCry cyber attack and the NHS*. https://www.nao.org.uk/reports/investigation-wannacry-cyber-attack-and-the-nhs/
3. [SECUNDARIA] Check Point Research. (s.f.). *WannaCry Ransomware*. https://www.checkpoint.com/cyber-hub/threat-prevention/ransomware/wannacry-ransomware/
4. [SECUNDARIA] Global Security (recogiendo declaración oficial de Europol). (2017, 14 de mayo). *Europol says Global Cyberattack Affects 150 Countries*. https://www.globalsecurity.org/security/library/news/2017/05/sec-170514-voa01.htm

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

*Todas las salidas de abajo son reales: se copiaron tal cual de la terminal, no se transcribieron a mano.*

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
$ echo "código de salida: $?"

Directorio:  data/muestra
Manifiesto:  manifest.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          0

INTEGRIDAD VERIFICADA — sin diferencias contra el manifiesto.
código de salida: 0
```

### Detección de la modificación de un byte

```
$ printf 'X' >> data/muestra/transferencia.txt
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"

Directorio:  data/muestra
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

Detectó el único byte agregado al final del archivo, lo clasificó como `MODIFICADO` y terminó con código `1`, como exige la prueba obligatoria del enunciado.

### Detección de archivo faltante y de archivo nuevo

```
$ rm data/muestra/app.bin
$ echo "contenido plantado" > data/muestra/backdoor.sh
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
$ echo "código de salida: $?"

Directorio:  data/muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     0
  FALTANTE       1
  NUEVO          1

Hallazgos:
  [FALTANTE] app.bin
  [NUEVO] backdoor.sh

INTEGRIDAD COMPROMETIDA — 2 hallazgo(s).
código de salida: 1
```

Borramos `app.bin` (clasificado `FALTANTE`) y plantamos `backdoor.sh`, un archivo que no estaba en el manifiesto original (clasificado `NUEVO`) — exactamente el escenario de un atacante que borra evidencia y deja un archivo propio.

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

**Distancia obtenida:** 139 bits de 256 (54.30 %)

¿Coincide con lo esperado? Sí: cambiar un solo carácter (`0` por `1` en el último dígito del importe) produjo una diferencia en el **54.3% de los bits** del digest — más de la mitad, y cercano al 50% esperado teóricamente para un cambio mínimo de entrada. Antes de correrlo esperábamos un valor en torno al 50%, no un número pequeño como "1 bit distinto por 1 carácter distinto": esa es justamente la trampa que el enunciado advierte, y es la que confirma por qué contar sobre bytes crudos (y no sobre caracteres hexadecimales) es necesario para ver el efecto avalancha real.

### HMAC

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.
```

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 0000000000000000000000000000000000000000000000000000000000000000

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 0000000000000000000000000000000000000000000000000000000000000000

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
```

---

## B.2 — Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Exclusión del archivo de manifiesto del recorrido | Comparamos `ruta.resolve()` contra `salida.resolve()` (y, en `verificar`, contra `ruta_manifiesto.resolve()`), no la ruta tal cual se recibió por argumento. | Si solo comparáramos las rutas sin resolver, un usuario que pasara `--salida ./manifest.sha256` desde otro directorio de trabajo podría terminar indexando el propio manifiesto (reportándose como `NUEVO` en cada corrida), porque la comparación de strings fallaría aunque apunten al mismo archivo. `resolve()` normaliza a una ruta absoluta y canónica antes de comparar. |
| Qué pasa si el directorio está vacío | No lo tratamos como error: `generar_manifiesto()` simplemente devuelve un diccionario vacío `{}`, y `verificar_manifiesto()` con un manifiesto vacío reporta 0 en las cuatro categorías. | Un directorio vacío es un estado válido, no una falla. Lanzar una excepción ahí sería inconsistente con el resto del programa, que distingue errores reales (directorio inexistente) de estados simplemente "sin contenido". |
| Cómo tratamos directorios anidados vacíos | `Path.rglob("*")` los devuelve, pero los filtramos con `ruta.is_file()` antes de hashear. | Un directorio no tiene contenido para hashear; solo los archivos regulares entran al manifiesto, tal como pide el enunciado. |
| Orden de las claves del manifiesto | Usamos `dict(sorted(manifiesto.items()))` al final de `generar_manifiesto()`, en vez de ir insertando ya ordenado. | Es más simple construir el diccionario en el orden en que `rglob()` lo entrega y ordenar una sola vez al final, que reordenar en cada inserción. El resultado es el mismo y el código queda más legible. |

---

## B.3 — Preguntas de análisis

### 1. El manifiesto por sí solo no alcanza

Un atacante con acceso de escritura al directorio donde viven tanto los archivos como `manifest.sha256` puede, en efecto, modificar un archivo y simplemente volver a correr `generar` sobre el directorio ya alterado: el nuevo manifiesto va a reflejar fielmente el contenido modificado, y una verificación posterior va a dar `OK` en todo, porque está comparando el archivo alterado contra un manifiesto calculado **a partir de ese mismo archivo ya alterado**. El esquema, tal como está, no distingue entre "el manifiesto es confiable" y "el manifiesto existe": asume que el manifiesto mismo nunca fue tocado por quien no debía, pero no lo verifica.

Lo que falta es una forma de que el manifiesto **no pueda ser regenerado silenciosamente** por cualquiera que tenga acceso de escritura al directorio. Dos cambios posibles: (a) firmar el manifiesto con una clave privada que el atacante no tiene (criptografía asimétrica: cualquiera puede verificar la firma con la clave pública, pero solo quien tiene la clave privada —idealmente guardada fuera del sistema que se protege— puede generar una firma válida), o (b) almacenar el manifiesto (o al menos su propio hash) en un sistema separado con acceso restringido —por ejemplo, un servidor de logs centralizado, un bucket con políticas de solo-apéndice, o un sistema de control de versiones con permisos distintos a los del directorio monitoreado—, de forma que comprometer el directorio de datos no implique automáticamente poder comprometer también el registro de referencia.

### 2. Qué agrega HMAC y qué no

Un hash simple (SHA-256 sobre el mensaje, sin clave) prueba que un dato no cambió, pero **cualquiera** puede calcular ese mismo hash: no demuestra quién lo generó. HMAC incorpora una clave secreta compartida al cálculo, de modo que solo quien conoce esa clave puede producir un tag válido para un mensaje dado. Eso agrega **autenticidad del origen** (certeza de que el mensaje fue producido por alguien que posee la clave) además de integridad (certeza de que no cambió desde que se calculó el tag).

Lo que HMAC **no** resuelve es el **no repudio**. Como la clave es **simétrica** —la misma clave sirve tanto para generar el tag como para verificarlo—, cualquiera de las dos partes que la conocen (quien envía y quien recibe) podría haber generado ese tag. Si A y B comparten la clave, A no puede usar un HMAC válido para demostrarle a un tercero que fue B (y no A mismo) quien produjo el mensaje — porque A también tenía la capacidad de producir exactamente ese mismo tag. Eso es lo que distingue HMAC de una firma digital con criptografía asimétrica: en una firma, solo el firmante tiene la clave privada, así que la firma sí sirve como evidencia frente a terceros. HMAC prueba "alguien con la clave lo hizo", no "específicamente B lo hizo y no A".

### 3. MD5 y SHA-1

A ambos se les rompió la **resistencia a colisiones**: la propiedad que garantiza que es computacionalmente inviable encontrar dos entradas distintas que produzcan el mismo digest. Para MD5, ataques prácticos de colisión (Wang et al., 2004 y refinamientos posteriores) permiten construir pares de archivos distintos con el mismo hash MD5 en tiempo razonable con hardware común. Para SHA-1, Google y CWI Amsterdam publicaron en 2017 el ataque "SHAttered", una colisión práctica y verificable (dos archivos PDF distintos con el mismo digest SHA-1), demostrando que la resistencia a colisiones ya no se sostenía en la práctica, no solo en teoría.

Eso no significa que estén "rotos para todo uso". Donde la seguridad depende de que nadie pueda fabricar una colisión intencional (firmas digitales, certificados, verificación de que un archivo descargado es el que el autor publicó y no uno sustituido con el mismo hash), MD5 y SHA-1 ya no son aceptables — es exactamente el escenario que un atacante podría explotar. Pero en usos donde no hay un adversario activo tratando de fabricar colisiones —por ejemplo, como *checksum* para detectar corrupción accidental de datos durante una transferencia, no un ataque deliberado— siguen siendo funcionalmente aceptables, porque ahí lo que importa es la resistencia a cambios **accidentales**, no a colisiones **construidas a propósito**. La recomendación de la industria (y la de este mismo lab, usando SHA-256) es migrar a SHA-2 o SHA-3 en cualquier contexto de seguridad.

**Fuente:** Stevens, M., Bursztein, E., Karpman, P., Albertini, A., & Markov, Y. (2017). *The first collision for full SHA-1*. Google Security Blog / CWI Amsterdam. https://shattered.io/

### 4. Comparación en tiempo constante

Comparar dos cadenas con `==` en la mayoría de los lenguajes (incluido Python para tipos como `bytes` o `str` comparados byte a byte) hace una comparación que **se detiene en el primer byte distinto**. Eso significa que el tiempo que tarda la comparación depende de **cuántos bytes iniciales coinciden** entre el tag recibido y el tag correcto. Un atacante que puede medir ese tiempo con precisión (por ejemplo, mandando miles de intentos con distintos primeros bytes y midiendo microsegundos de diferencia en la respuesta del servidor) puede usar esa diferencia de tiempo como un **oráculo**: si un intento tarda un poquito más que otro, probablemente el primer byte de ese intento coincidió con el tag real, aunque el resto esté mal. Repitiendo esto byte por byte, un atacante puede reconstruir el tag válido completo sin conocer la clave secreta, pura y exclusivamente observando tiempos de respuesta — esto se llama **ataque de temporización** (timing attack).

`hmac.compare_digest()` evita esto comparando **siempre todos los bytes**, sin cortar la ejecución apenas encuentra una diferencia: el tiempo que tarda la función es (aproximadamente) el mismo sin importar en qué posición esté el primer byte distinto, o si no hay ninguna diferencia. Al eliminar la correlación entre "tiempo de respuesta" y "cuántos bytes coinciden", se elimina el canal de información que el ataque de temporización necesita para funcionar.

### 5. SHA-256 para contraseñas: mala idea

SHA-256 es rápido **a propósito**: fue diseñado para hashear grandes volúmenes de datos (archivos, bloques de una blockchain, manifiestos como el de este lab) con la menor latencia posible, y eso es exactamente lo que lo hace una mala elección para contraseñas. Si un atacante obtiene una base de contraseñas hasheadas con SHA-256, puede probar **miles de millones de contraseñas candidatas por segundo** en hardware común (y órdenes de magnitud más con GPUs o hardware especializado), porque cada intento de hash es computacionalmente barato. Eso vuelve viable un ataque de fuerza bruta o de diccionario a gran escala contra contraseñas reales, que en general no son aleatorias ni tienen mucha entropía.

Lo que se usa en su lugar son funciones de **derivación de claves diseñadas específicamente para ser lentas y costosas en memoria**: **Argon2id**, **bcrypt** y **scrypt**. Estas funciones incorporan un parámetro de "costo" ajustable (iteraciones, memoria requerida, o ambas) que hace que calcular un solo hash tome, a propósito, un tiempo medible (milisegundos, no microsegundos) y/o una cantidad considerable de memoria RAM. La propiedad clave que tienen y que SHA-256 no tiene es el **costo computacional configurable y deliberadamente alto** (especialmente en memoria, en el caso de Argon2id y scrypt, lo que además dificulta paralelizar el ataque en hardware especializado tipo ASIC/GPU). Esa lentitud es irrelevante para el uso legítimo (un login verifica una sola contraseña por vez, así que unos cientos de milisegundos no se notan), pero multiplica por órdenes de magnitud el costo de un ataque de fuerza bruta a gran escala, que necesita probar miles de millones de candidatos.

---

# Cierre

## Dificultades encontradas

La parte más delicada fue `avalancha`: la advertencia del enunciado sobre contar bits y no caracteres hexadecimales es literal y hay que tomarla en serio — es muy fácil escribir `sum(c1 != c2 for c1, c2 in zip(hex_a, hex_b))` y que el programa corra sin errores pero dé un número sistemáticamente incorrecto, porque dos dígitos hexadecimales distintos pueden diferir en 1 bit o en 4. Trabajar directamente sobre `digest()` (bytes crudos) en vez de `hexdigest()`, y usar el XOR de bytes seguido de `int.bit_count()`, resolvió esto de forma limpia.

En `generar_manifiesto()` y `verificar_manifiesto()`, el punto que requirió más cuidado fue excluir el propio archivo de manifiesto del recorrido usando rutas **resueltas** (`Path.resolve()`), no comparación directa de los argumentos recibidos — dos formas distintas de escribir la misma ruta (relativa vs. absoluta, o con `./` de más) no son iguales como *strings*, pero sí lo son una vez resueltas.

## Distribución del trabajo

| Integrante | Aportes |
|---|---|
| Santiago Cocchi (@santicocchi) | *(completar aporte real)* |
| Franco Ferraro (@francovalentin08) | *(completar aporte real)* |
| Francisco Mossello (@FranMossello) | Implementación de los 4 TODO de `integridad.py`, ejecución de toda la evidencia de B.1, investigación y redacción de la Parte A (caso WannaCry) y del mini-research. |
| Tomas Spat (@TomiSpat) | *(completar aporte real)* |
| Santiago Torres (@santy500) | *(completar aporte real)* |

> **Nota sobre el historial de commits.** La rúbrica de este laboratorio exige commits de **múltiples cuentas reales** como evidencia de trabajo grupal (causal de rechazo automático #1). El contenido de esta entrega se produjo en una sola sesión de trabajo con asistencia de IA, y por lo tanto el historial de commits de esta rama solo tiene un autor (@FranMossello). Antes de abrir el Pull Request, el resto del grupo tiene que revisar el contenido, hacer los ajustes que consideren necesarios y **confirmarlos con sus propios commits** desde sus propias cuentas de GitHub — tanto para cumplir el requisito de la rúbrica como porque la distribución de aportes de la tabla de arriba tiene que reflejar trabajo real de cada integrante, no una lista completada por quien no lo hizo.

## Declaración de uso de asistentes de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| Claude Code (Anthropic) | Implementación de los 4 TODO de `integridad.py`; ejecución real de todos los comandos de evidencia (generar, verificar con sus 4 casos, avalancha, mac); búsqueda y verificación de fuentes para la Parte A y el mini-research; redacción del informe. | Todo `src/integridad.py` (los 4 bloques TODO), toda la sección de evidencia de B.1 (ejecutada de verdad, no inventada), la Parte A (hechos verificados con búsquedas web contra fuentes primarias) y el mini-research. | El código se validó corriendo `python3 src/verificar.py` (4/4 pruebas en verde) y ejecutando manualmente cada subcomando y pegando la salida real de la terminal (no transcripta a mano). Las fuentes de la Parte A y el research se verificaron con búsquedas web que confirmaron que cada URL citada existe y resuelve al contenido referenciado (CISA TA17-132A, el informe de la National Audit Office, etc.), evitando el riesgo conocido de que un asistente de IA fabrique citas con formato correcto pero contenido inexistente. |

**Declaración:**

El integrante declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del código y del análisis, independientemente de la asistencia recibida.

---

## Fuentes consultadas (general)

Ver sección A.6 para las fuentes de la Parte A. Las fuentes del mini-research están en `research.md`.
