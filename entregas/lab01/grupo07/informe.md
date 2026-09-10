# Laboratorio 01 — Informe

## Identificación

| | |
|---|---|
| **Grupo** | 07 |
| **Caso asignado (Parte A)** | 1 — **Stuxnet** (2010), por `7 mod 6 = 1` |
| **Tema del mini-research** | 2 — La cadena de suministro de software como superficie de ataque (SolarWinds/SUNBURST y Log4Shell) |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Lorenzo Blanc | 15034 | @LoloBlanc |
| Fernando Cagliero | 15136 | @Ferca19 |
| Guadalupe Gómez | 15397 | @guadagomezgg8 |
| Lautaro Mariño | 15163 | @lautaromarino0 |

---

# PARTE A — Análisis del incidente bajo la lente CIA

**Caso:** 1 — **Stuxnet** (2010). Asignado por la regla del enunciado:
`número_de_grupo mod 6` → `7 mod 6 = 1`.

## A.1 — Cronología

| Fecha | Hecho | Fuente |
|---|---|---|
| Jun. 2009 | Se compila la muestra más antigua conocida de Stuxnet. | Symantec [3] |
| Fines 2009 – ppios. 2010 | Natanz reemplaza unas 1.000 centrífugas IR-1 de las ~9.000 desplegadas; el OIEA registra 11 cascadas fuera de línea. | ISIS [1] [2] |
| Mar. 2010 | Aparece la variante que explota CVE-2010-2568: un `.LNK` malicioso ejecuta código con solo mostrarse el ícono. Es el vector que cruza la red aislada por USB. | Symantec [3] |
| 17 jun. 2010 | VirusBlokAda detecta el gusano y lo reporta como *RootkitTmphider*: descubrimiento público del incidente. | Symantec [3] |
| 16 y 22 jul. 2010 | VeriSign revoca los certificados robados de Realtek y de JMicron, usados para firmar los drivers del rootkit. | Symantec [3] |
| 2 ago. 2010 | Microsoft publica MS10-046 fuera del ciclo mensual para corregir CVE-2010-2568. | Microsoft [6] |
| Sep. 2010 | Se publica el análisis que identifica el objetivo real: los PLC Siemens S7, no las PC Windows. | Langner [4] |
| Nov. 2010 | Se acota el blanco a variadores de frecuencia que operan entre 807 Hz y 1210 Hz. | Symantec [3] |
| 2013 | Se documenta una segunda rutina, anterior, contra el S7-417: ataque de sobrepresión que oculta el sabotaje reproduciendo 21 s de lecturas grabadas. | Langner [5] |

*Los números entre corchetes remiten a la lista de fuentes de A.6.*

---

## A.2 — Activo afectado

**Activo principal:**

La **lógica de control cargada en los PLC Siemens SIMATIC S7-315 y S7-417 que
gobiernan las cascadas de centrífugas IR-1 de la planta de enriquecimiento de
combustible (FEP) de Natanz, Irán**, y —como extensión inseparable de esa
lógica— el proceso físico de enriquecimiento que esos controladores regulan.

**Por qué es el principal:**

Porque es el único activo que el atacante buscó deliberadamente. Stuxnet se
propagó a más de un centenar de miles de equipos en todo el mundo, pero el
payload de sabotaje sólo se arma si el host tiene Step7/WinCC instalado **y**
si el PLC gobierna variadores de frecuencia Fararo Paya o Vacon operando entre
807 Hz y 1210 Hz (Falliere et al., 2011). En cualquier otro equipo el gusano se
queda inerte. Las PC Windows infectadas fueron el **medio de transporte**, no el
objetivo: confundirlas con el activo es el error de análisis más común en este
caso.

**Otros activos afectados** (en orden de relevancia):

1. **La integridad de los valores de proceso presentados al operador** en las
   estaciones WinCC/HMI. En la rutina contra el S7-417 el atacante grababa 21
   segundos de lecturas de sensores y las reproducía en bucle, de modo que el
   tablero mostraba un proceso normal mientras se saboteaba (Langner, 2013).
2. **Las claves privadas de firma de código de Realtek Semiconductor y JMicron
   Technology**, robadas y usadas para firmar los drivers del rootkit; ambos
   certificados debieron revocarse en julio de 2010.
3. **Información de inventario de los equipos infectados colateralmente**
   (nombre de equipo, dominio, versión de SO, dirección IP y presencia de
   Step7/WinCC), enviada a los servidores de mando y control
   `www.mypremierfutbol.com` y `www.todaysfutbol.com`.
4. **Las centrífugas IR-1** como activo físico, destruidas por el efecto de la
   manipulación.

---

## A.3 — Matriz CIA

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | **Parcial** | Hubo exfiltración documentada, pero instrumental y periférica al objetivo. Cada host infectado enviaba a los C&C `www.mypremierfutbol.com` y `www.todaysfutbol.com` el nombre del equipo, el dominio, la versión del SO, la IP y si tenía Step7/WinCC instalado (Falliere et al., 2011). En paralelo, el atacante comprometió las **claves privadas de firma** de Realtek y JMicron —un secreto criptográfico ajeno— para firmar `mrxnet.sys` y `mrxcls.sys`; VeriSign las revocó el 16 y el 22 de julio de 2010. No hay evidencia de que se hayan sustraído datos de enriquecimiento, planos ni datos personales desde Natanz: por eso «Parcial» y no «Sí». |
| **Integridad** | **Sí** | Es el eje del ataque y hay dato alterado identificable en tres capas. (1) **Software:** Stuxnet renombra `s7otbxdx.dll` a `s7otbxsx.dll` y la reemplaza por su propia versión, con lo que se interpone en toda comunicación Step7↔PLC; puede escribir bloques en el controlador y devolverle al ingeniero la versión limpia cuando éste lee el proyecto (Falliere et al., 2011). (2) **Lógica de control:** inyecta bloques propios y altera los bloques de organización del PLC, cambiando el programa que ejecuta el controlador. (3) **Valores de proceso:** modifica las consignas de frecuencia enviadas a los variadores —lleva el rotor de las ~63.000 rpm nominales a 84.600 rpm durante quince minutos y después casi a la detención, 120 rpm (Langner, 2013)— y, en la rutina del S7-417, sustituye las lecturas reales de los sensores por 21 segundos grabados y reproducidos en bucle. |
| **Disponibilidad** | **Sí** | La violación de integridad se materializó en pérdida de servicio del activo, con evidencia externa e independiente del atacante: alrededor de **1.000 centrífugas IR-1 de las ~9.000 desplegadas** en Natanz fueron retiradas y reemplazadas entre fines de 2009 y comienzos de 2010, y los datos de salvaguardias del OIEA muestran **11 cascadas A26 fuera de línea**, de las cuales **6 seguían fuera de línea en agosto de 2010** (Albright et al., 2010; 2011). |

**Justificación ampliada de la propiedad más discutible:**

La más difícil de determinar fue la **confidencialidad**, y el motivo es que las
dos respuestas fáciles son incorrectas.

Marcar «No» es lo intuitivo: Stuxnet es el arma de sabotaje por antonomasia, no
una operación de espionaje; no se llevó ni un byte de datos de enriquecimiento.
Pero «No» exige que no haya habido pérdida alguna de información, y sí la hubo:
el gusano reporta a sus C&C un perfil del equipo infectado —nombre, dominio, SO,
IP, presencia de Step7/WinCC—, es decir, hace reconocimiento y lo exfiltra.
Además, el robo de las claves privadas de Realtek y JMicron es una violación de
confidencialidad de manual: un secreto que sólo el titular debía conocer terminó
en poder de un tercero, y la prueba de que se lo consideró comprometido es que
ambos certificados se revocaron.

Marcar «Sí» a secas es el error opuesto: sobredimensiona el hecho y sugiere que
hubo una fuga de información del activo protegido, que es exactamente lo que no
ocurrió. «Parcial» es la única respuesta que se sostiene con la evidencia: la
confidencialidad se violó, pero sobre activos accesorios y como medio para
sostener el ataque a la integridad, no como fin.

Vale registrar además una decisión sobre la **disponibilidad**. Si se aplica la
tríada en su lectura más estrecha —sólo sobre información— podría argumentarse
que destruir centrífugas es un daño físico y no una pérdida de disponibilidad.
Descartamos esa lectura: en sistemas de control industrial el activo protegido
incluye el proceso que el sistema gobierna, y de hecho la guía de referencia
para OT invierte el orden de prioridades habitual y pone la disponibilidad en
primer lugar (NIST, 2023). Bajo ese marco, dejar seis cascadas fuera de línea
durante meses es pérdida de disponibilidad en sentido pleno.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

```
amenaza  →  explota  →  vulnerabilidad  →  sobre  →  activo  →  produce  →  impacto
```

| Elemento | En este caso |
|---|---|
| **Amenaza** *(quién / qué, con qué motivación)* | Un actor estatal con capacidad de operación sostenida: presupuesto para quemar cuatro vulnerabilidades de día cero en una sola campaña, capacidad de robar claves de firma en dos empresas distintas y —lo más caro de conseguir— conocimiento de ingeniería de las centrífugas IR-1 y de su régimen de operación. **Motivación:** retrasar el programa de enriquecimiento iraní sin recurrir a un ataque cinético y sin atribución. La autoría nunca fue reconocida oficialmente; la investigación periodística la adjudica a una operación conjunta de EE.UU. e Israel denominada *Olympic Games* (Sanger, 2012). |
| **Vulnerabilidad** *(la debilidad concreta que se explotó)* | No una, sino una cadena, y conviene separar las dos clases. **La habilitante, de diseño y específica del dominio:** los PLC S7-300/400 aceptan la descarga de bloques de lógica **sin autenticar el origen ni verificar la integridad del programa**, y Step7 depende de una única biblioteca de usuario (`s7otbxdx.dll`) para leer lo que hay cargado en el controlador, sin ninguna verificación independiente. **Las de acceso, de propósito general:** CVE-2010-2568 (MS10-046), ejecución de código al renderizar el ícono de un acceso directo en un medio extraíble —es la que atraviesa el *air gap*—, CVE-2010-2729 (MS10-061, cola de impresión) y dos elevaciones de privilegio locales. A ellas se suma que la confianza depositada en la firma de código se volvió en contra al robarse las claves de Realtek y JMicron. |
| **Activo** *(sobre qué recayó)* | La lógica de control de los PLC S7-315/S7-417 de las cascadas IR-1 de Natanz y el proceso de enriquecimiento que esa lógica gobierna. |
| **Impacto** *(consecuencia sobre el negocio o las personas)* | Destrucción física de ~1.000 centrífugas IR-1, cascadas fuera de servicio durante meses y retraso del programa de enriquecimiento. Un impacto de segundo orden, más caro de reparar que el hardware: el operador perdió la capacidad de confiar en su propia instrumentación, porque el mismo sistema encargado de informarle el estado del proceso era el que le mentía. |

**Redacción:**

Un actor estatal con recursos de nivel militar (**amenaza**), cuya motivación era
frenar el enriquecimiento de uranio iraní sin acción militar visible, explotó
mediante un acceso directo `.LNK` alojado en un medio extraíble la falla de
validación del Shell de Windows CVE-2010-2568 (**vulnerabilidad de acceso**) para
atravesar la separación física de la red de Natanz y alcanzar las estaciones de
ingeniería Step7. Una vez ahí explotó una segunda debilidad, de diseño y bastante
más grave que las de Windows: que el controlador S7 **acepta lógica de control
sin autenticar su origen** y que Step7 no verifica de forma independiente qué hay
efectivamente cargado en él (**vulnerabilidad habilitante**), sobre los PLC que
gobiernan las cascadas de centrífugas IR-1 (**activo**). El resultado fue la
manipulación de las consignas de frecuencia de los rotores mientras el HMI seguía
mostrando valores normales, lo que **produjo** el **impacto**: unas mil
centrífugas destruidas, seis cascadas fuera de línea todavía en agosto de 2010 y
un operador que ya no podía creerle a su propio tablero.

Conviene marcar las distinciones que el encadenamiento exige. La **amenaza** es
el actor con capacidad e intención, no el gusano. Stuxnet es el **exploit** —el
instrumento con el que la amenaza se materializa—, y un exploit no es una
vulnerabilidad: es lo que la aprovecha. La **vulnerabilidad** es la debilidad
preexistente, que aquí no fue principalmente un bug de Windows sino una decisión
de diseño de la plataforma de control. Y el **impacto** no es «el ataque» sino su
consecuencia medible sobre el activo: centrífugas destruidas y producción
detenida, no «hubo un ataque informático».

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | **Firma criptográfica y verificación en el propio PLC de la lógica de control descargada.** El controlador ejecuta únicamente bloques cuya firma digital valide contra una clave pública grabada en su firmware, con la clave privada custodiada fuera de la estación de ingeniería (HSM o equipo desconectado); además, expone un digest del programa efectivamente cargado por un canal que no atraviesa la biblioteca de comunicaciones de Step7. |
| **Propiedad de la tríada que protege** | **Integridad** (de la lógica de control), con efecto derivado sobre la **disponibilidad** del proceso. |
| **Por qué habría funcionado en este caso concreto** | Porque ataca exactamente el mecanismo de Stuxnet, no una generalidad. El corazón del ataque fue escribir bloques propios en un PLC que **no pide credenciales ni verifica el origen del código** y después ocultarlos interponiendo su propia `s7otbxdx.dll` entre Step7 y el controlador (Falliere et al., 2011). Con verificación de firma **en el controlador**, los bloques inyectados serían rechazados aunque la estación de ingeniería estuviera totalmente comprometida —y ése es el punto: el control no depende de que el Windows esté sano, que es justamente lo que Stuxnet dio por sentado. Y como el digest del programa cargado se lee por un canal ajeno a la DLL secuestrada, la mitad «ocultamiento» del ataque tampoco funcionaría: el ingeniero vería que lo que corre en el PLC no es lo que él descargó. |

### Control 2

| | |
|---|---|
| **Qué es** | **Verificación independiente (*out-of-band*) del proceso físico.** Instrumentar las variables críticas —velocidad de rotor, presión, vibración— con sensores y adquisición que **no pasen por el PLC ni por el HMI del sistema de control**: un registrador o historiador en paralelo, con alarma automática por discrepancia entre la lectura independiente y la que informa el sistema de control. |
| **Propiedad de la tríada que protege** | **Disponibilidad** (permite detener el proceso antes de la destrucción) y, de manera derivada, **detección** de la pérdida de integridad. |
| **Por qué habría funcionado en este caso concreto** | Porque el ataque no duró meses por falta de gente mirando, sino porque **lo que miraban se lo dictaba el atacante**. En la rutina contra el S7-417 se grababan 21 segundos de valores de sensores y se reproducían en bucle durante el sabotaje, y en la del S7-315 el rotor pasaba de ~63.000 a 84.600 rpm sin que el tablero lo reflejara (Langner, 2013). Una lectura de velocidad o de vibración tomada **por fuera de esa cadena** habría mostrado la discrepancia ya en la primera corrida de quince minutos, y la cascada se habría podido detener mucho antes de acumular mil centrífugas rotas. No se trata de «poner más sensores»: el principio es no derivar la evidencia de integridad del mismo componente que se sospecha comprometido —el mismo razonamiento por el que, en la Parte B de este laboratorio, el manifiesto no puede vivir dentro del directorio que pretende proteger. |

---

## A.6 — Fuentes consultadas (Parte A)

1. Albright, D., Brannan, P. y Walrond, C. (2010, 22 de diciembre). *Did Stuxnet
   take out 1,000 centrifuges at the Natanz enrichment plant?* Institute for
   Science and International Security.
   https://isis-online.org/isis-reports/did-stuxnet-take-out-1000-centrifuges-at-the-natanz-enrichment-plant/
   — **Primaria** (análisis técnico construido sobre datos de salvaguardias del OIEA).

2. Albright, D., Brannan, P. y Walrond, C. (2011, 15 de febrero). *Stuxnet
   malware and Natanz: Update of ISIS December 22, 2010 report*. Institute for
   Science and International Security.
   https://isis-online.org/uploads/isis-reports/documents/stuxnet_update_15Feb2011.pdf
   — **Primaria**.

3. Falliere, N., O Murchu, L. y Chien, E. (2011). *W32.Stuxnet dossier*
   (versión 1.4). Symantec Security Response.
   https://docs.broadcom.com/doc/security-response-w32-stuxnet-dossier-11-en
   — **Primaria** (ingeniería inversa de las muestras por el equipo que las analizó).

4. Langner, R. (2011). Stuxnet: Dissecting a cyberwarfare weapon. *IEEE Security
   & Privacy, 9*(3), 49–51. https://doi.org/10.1109/MSP.2011.67
   — **Arbitrada** (revista con revisión por pares del IEEE).

5. Langner, R. (2013, noviembre). *To kill a centrifuge: A technical analysis of
   what Stuxnet's creators tried to achieve*. The Langner Group. El sitio
   original (`langner.com`) hoy redirige al producto de la empresa; se consultó
   la copia archivada, verificada el 09/09/2026, en
   https://archive.org/details/to-kill-a-centrifuge
   — **Primaria**.

6. Microsoft. (2010, 2 de agosto). *Microsoft Security Bulletin MS10-046 —
   Critical: Vulnerability in Windows Shell could allow remote code execution
   (2286198)*.
   https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-046
   — **Primaria** (boletín del fabricante).

7. National Institute of Standards and Technology. (2010). *CVE-2010-2568
   detail*. National Vulnerability Database.
   https://nvd.nist.gov/vuln/detail/CVE-2010-2568
   — **Primaria**.

8. National Institute of Standards and Technology. (2023). *SP 800-82 Rev. 3:
   Guide to Operational Technology (OT) security*.
   https://csrc.nist.gov/pubs/sp/800/82/r3/final
   — **Primaria** (usada para el criterio de prioridad de la tríada en entornos OT).

9. Sanger, D. E. (2012, 1 de junio). Obama order sped up wave of cyberattacks
   against Iran. *The New York Times*. Reproducido en ICRC Casebook:
   https://casebook.icrc.org/case-study/iran-victim-cyber-warfare
   — **Secundaria** (periodística). Se usa **únicamente** para la atribución, que
   nunca fue reconocida oficialmente por ningún Estado y que por lo tanto se
   presenta como versión de prensa, no como hecho establecido.

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

### Generación del manifiesto

```
$ python src/integridad.py generar --dir data/muestra --salida manifest.sha256
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

Exclusión del propio manifiesto. Dos corridas seguidas escribiendo la salida
dentro del directorio recorrido: en la segunda el archivo ya existe y aun así
queda fuera del índice.

```
$ python src/integridad.py generar --dir data/muestra --salida data/muestra/manifest.sha256
Manifiesto generado: data\muestra\manifest.sha256
Directorio base:     data\muestra
Archivos indexados:  4

$ python src/integridad.py generar --dir data/muestra --salida data/muestra/manifest.sha256
Manifiesto generado: data\muestra\manifest.sha256
Directorio base:     data\muestra
Archivos indexados:  4
```

Directorio vacío.

```
$ mkdir data/vacio
$ python src/integridad.py generar --dir data/vacio --salida prueba_vacio.json
Manifiesto generado: prueba_vacio.json
Directorio base:     data\vacio
Archivos indexados:  0

$ cat prueba_vacio.json
{}
```

### Verificación sobre un directorio íntegro

```
$ python src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data\muestra
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
$ python src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data\muestra
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

```
$ rm data/muestra/politica_seguridad.md
$ echo "backdoor" > data/muestra/backdoor.sh
$ python src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             2
  MODIFICADO     1
  FALTANTE       1
  NUEVO          1

Hallazgos:
  [MODIFICADO] transferencia.txt
  [FALTANTE] politica_seguridad.md
  [NUEVO] backdoor.sh

INTEGRIDAD COMPROMETIDA — 3 hallazgo(s).

$ echo "código de salida: $?"
código de salida: 1
```

### Efecto avalancha

```
$ python src/integridad.py avalancha --a "transferencia: $1000" --b "transferencia: $1001"

mensaje A: "transferencia: $1000"
  SHA-256: 341511c4c817d55f30c81e212d0e82b0b16dd5a58d49fe5e45c9d5c998ab794a
mensaje B: "transferencia: $1001"
  SHA-256: 5fb87fd7adf8a226f61c666a3ed140b147501b8a1b8e1822e57fc4b3925323d9

Distancia de Hamming: 139 de 256 bits (54.30 %)
Efecto avalancha: para entradas distintas se espera un valor cercano al 50 %.
```

**Distancia obtenida:** 139 bits de 256 (54.30 %)

El resultado coincide con lo esperado: al cambiar un solo carácter se modificó
aproximadamente la mitad de los bits del digest, en este caso un 54.30 %.

### HMAC

```
$ python src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

```
$ python src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.

$ echo "código de salida: $?"
código de salida: 0

$ python src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 0000000000
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 0000000000

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.

$ echo "código de salida: $?"
código de salida: 1

```

---

## B.2 — Decisiones de implementación

*Qué decisiones tuvieron que tomar que el enunciado no resolvía por ustedes.
Ejemplos: cómo trataron los enlaces simbólicos, qué hicieron con los archivos
vacíos, cómo excluyeron el manifiesto del recorrido, qué pasa si el directorio
está vacío. Una o dos oraciones por decisión.*

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Recorrido de directorios | Usamos `rglob("*")` para recorrer el directorio de forma recursiva y procesamos únicamente los elementos que son archivos mediante `is_file()`. | Para incluir los archivos que se encuentran dentro de subdirectorios y evitar intentar calcular hashes sobre directorios. |
| Exclusión del manifiesto | Comparamos cada archivo recorrido con la ruta de salida del manifiesto usando `resolve()`, y si coinciden lo excluimos. `resolve()` normaliza ambas rutas a una forma absoluta para compararlas de manera confiable, ya que una proviene del argumento de la CLI y la otra es construida por `rglob()`. | El manifiesto no debe incluirse a sí mismo porque al escribirlo su contenido cambia y, por lo tanto, también cambiaría su propio hash. |
| Representación de las rutas | Usamos `relative_to(directorio)` para guardar rutas relativas y `as_posix()` para utilizar siempre `/` como separador. | Sin `as_posix()`, en Windows una ruta podía quedar como `logs\acceso.log`, y esa clave con barra invertida no sería compatible al verificar el manifiesto en Linux. |
| Orden de las entradas | Ordenamos alfabéticamente las claves del manifiesto y las listas obtenidas durante la verificación. | Para que los resultados sean deterministas y evitar diferencias de orden innecesarias al comparar ejecuciones o manifiestos. |
| Clasificación durante la verificación | Comparamos los archivos presentes en disco con los registrados en el manifiesto y, cuando una ruta está en ambos, comparamos sus hashes para clasificarlos como OK o MODIFICADO. Las diferencias de conjuntos permiten detectar los FALTANTE y NUEVO. | De esta forma la verificación detecta no solo archivos modificados, sino también archivos eliminados o agregados. |
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

El manifiesto por sí solo no establece una raíz de confianza. Si un atacante
puede escribir tanto los archivos protegidos como `manifest.sha256`, puede
modificar un archivo, calcular su nuevo SHA-256 y reemplazar el manifiesto.
La verificación volvería a informar `OK`, pero solo porque el atacante cambió
la referencia junto con el archivo.

El esquema debe guardar la referencia en un lugar que el atacante no pueda
modificar, por ejemplo un repositorio o servidor separado con permisos de solo
lectura, o protegerla criptográficamente. Una alternativa es calcular un
HMAC del manifiesto con una clave almacenada fuera del directorio controlado;
una opción más adecuada cuando se necesita verificar el origen y conservar una
prueba independiente es firmarlo digitalmente con una clave privada y validar
la firma con la clave pública. En ambos casos, el atacante puede modificar el
archivo, pero no puede generar una referencia válida sin el secreto o la clave
privada.

---

### 2. Qué agrega HMAC y qué no

*¿Qué propiedad de seguridad aporta HMAC que un hash simple no aporta? Y la
parte importante: ¿qué **no** resuelve HMAC? Pensá en el no repudio y en
quién conoce la clave.*

**Respuesta:**

HMAC agrega autenticidad del origen además de integridad frente a quien no
conoce la clave secreta. Un hash simple permite detectar cambios solo si el
atacante no puede modificar también el hash, porque cualquiera que conozca el
mensaje puede recalcular su digest. En cambio, un tag HMAC válido solo puede
producirse con la clave compartida, por lo que el receptor puede comprobar que
el mensaje no fue alterado por alguien externo al grupo que conoce la clave.

HMAC no cifra el mensaje ni protege su confidencialidad, y tampoco garantiza
disponibilidad o que el mensaje sea reciente: para evitar repeticiones habría
que incorporar un nonce, contador o marca temporal y validarlo. Además, no
proporciona no repudio, porque tanto quien genera como quien verifica conocen
la misma clave y cualquiera de ellos podría crear un tag válido. Si la clave
se filtra, el atacante puede falsificar mensajes y manifiestos; para una
atribución pública e independiente se necesita una firma digital con clave
privada y clave pública de verificación.

---

### 3. MD5 y SHA-1

*Ambos siguen apareciendo en software en producción. ¿Qué propiedad
criptográfica se les rompió, exactamente? ¿Hay algún uso en el que todavía
sean aceptables, o ninguno? Fundamentá con al menos una fuente.*

**Respuesta:**

La propiedad criptográfica que se rompió es la resistencia a colisiones: ya no
es computacionalmente inviable encontrar dos entradas diferentes que produzcan
el mismo digest. En MD5 se demostraron colisiones prácticas desde 2004, y en
SHA-1 se consiguió una colisión pública en 2017. Esto no significa que se haya
recuperado cualquier mensaje a partir de su hash ni que se haya roto de la misma
forma la resistencia a preimagen; el problema central es que un atacante puede
fabricar dos contenidos distintos con la misma huella y aprovecharlo, por
ejemplo, en una firma o certificado.

Por ese motivo no deben usarse MD5 ni SHA-1 para generar nuevas firmas,
certificados o controles de integridad frente a un atacante. MD5 puede seguir
apareciendo como checksum no criptográfico o para detectar errores accidentales
cuando no existe un adversario, pero ese uso no brinda seguridad. SHA-1 conserva
algunos usos de compatibilidad, como verificar firmas antiguas ya existentes o
ciertos usos aprobados de legado, pero no debe generar nueva protección
criptográfica; para desarrollos nuevos corresponde migrar a SHA-256 o SHA-3.

**Fuente:**

NIST. (2006). *Cryptographic hash standards: Where do we go from here?*
https://www.nist.gov/publications/cryptographic-hash-standards-where-do-we-go-here

NIST. (2017). *Research results on SHA-1 collisions*.
https://csrc.nist.gov/News/2017/Research-Results-on-SHA-1-Collisions

NIST. (2022). *NIST transitioning away from SHA-1 for all applications*.
https://csrc.nist.gov/News/2022/nist-transitioning-away-from-sha-1-for-all-apps

---

### 4. Comparación en tiempo constante

*¿Por qué comparar un tag de autenticación con `==` puede filtrar información
al atacante, y cómo lo evita `hmac.compare_digest()`? Describí el ataque
concreto que esto previene.*

**Respuesta:**

Una comparación ingenua con `==` puede detenerse en el primer carácter que no
coincide. Por eso, si el tag enviado comparte un prefijo más largo con el tag
correcto, la ejecución puede tardar ligeramente más. Un atacante que pueda
repetir consultas y medir esos tiempos puede probar candidatos y aprender qué
prefijo es correcto, recuperando el tag byte por byte o carácter por carácter.

`hmac.compare_digest()` está diseñada para comparar secretos sin ese retorno
temprano dependiente de la posición de la primera diferencia, reduciendo la
información temporal disponible para ese ataque. Así se evita que un endpoint
que verifica HMAC funcione como un oráculo de tiempo; aun así, deben cuidarse
también otros canales laterales y limitarse los intentos de consulta.

---

### 5. SHA-256 para contraseñas: mala idea

*SHA-256 es una función de hash criptográfica sólida. ¿Por qué, entonces, es
una mala elección para almacenar contraseñas? ¿Qué se usa en su lugar y qué
propiedad tienen esas funciones que SHA-256 no tiene?*

**Respuesta:**

SHA-256 es sólida como función de hash general, pero justamente es demasiado
rápida para almacenar contraseñas. Si un atacante obtiene la base de datos,
puede probar enormes cantidades de candidatos por segundo en forma offline y
comparar cada SHA-256 con el valor guardado. Además, SHA-256 no incorpora por sí
misma una sal única ni un costo configurable; reutilizarla directamente permite
precomputación y hace visibles las contraseñas repetidas entre usuarios.

Para contraseñas se usan funciones diseñadas para ser lentas y costosas, como
Argon2id, scrypt o bcrypt. Deben emplear una sal aleatoria y diferente por
contraseña, y ajustar un factor de trabajo que haga cada intento más caro. Las
funciones modernas agregan además resistencia al paralelismo mediante consumo de
memoria configurable, algo que SHA-256 no ofrece. OWASP recomienda preferir
Argon2id, usar scrypt cuando no esté disponible y reservar bcrypt principalmente
para sistemas heredados. Así, una filtración sigue siendo grave, pero el costo
de probar millones de candidatos aumenta considerablemente.

---

# Cierre

## Dificultades encontradas

Durante la implementación de la Parte B, la principal dificultad fue distinguir
la distancia de Hamming sobre los bits crudos del digest de una comparación de
caracteres hexadecimales. Lo resolvimos trabajando con los bytes obtenidos
mediante `digest()`, aplicando XOR y contando los bits activos.

También tuvimos que diferenciar los tres estados de la verificación HMAC:
tag no verificado, tag válido y tag inválido. Para comprobarlo ejecutamos la
CLI con un tag correcto y otro alterado, y verificamos los códigos de salida.

En la Parte A, la dificultad fue separar confidencialidad, integridad y
disponibilidad sin marcar automáticamente las tres propiedades por la gravedad
del incidente. Para resolverlo, vinculamos cada determinación con evidencia
concreta de Stuxnet y verificamos las fuentes utilizadas.

---

## Distribución del trabajo

*Quién hizo qué. Tiene que ser consistente con el historial de commits.*

| Integrante | Aportes |
|---|---|
| Guadalupe Gómez | Estructura inicial del directorio del grupo. Implementación de `generar_manifiesto()` y `verificar_manifiesto()` (TODO 1 y 2). Pruebas de ejecución y evidencia de la sección B.1. Sección B.2. `INTEGRANTES.md`. |
| Lorenzo Blanc | Implementación de `distancia_hamming_bits()` y `calcular_mac()` (TODO 3 y 4). Pruebas de distancia de Hamming y HMAC. Evidencia de ejecución de avalancha y HMAC. Respuestas P1, P2 y P4. |
| Fernando Cagliero | Elección del tema y redacción del mini-research sobre cadena de suministro: SolarWinds/SUNBURST, Log4Shell, SBOM y SLSA. Respuestas P3 y P5. Verificación de fuentes y revisión de la declaración de uso de IA. |
| Lautaro Mariño | Parte A completa sobre el caso Stuxnet (2010): cronología con fuentes (A.1), identificación y priorización del activo (A.2), matriz CIA con evidencia y justificación de la propiedad más discutible (A.3), encadenamiento amenaza→vulnerabilidad→activo→impacto (A.4), los dos controles mitigantes (A.5) y la verificación de las nueve fuentes en formato APA (A.6). |

---

## Declaración de uso de asistentes de IA

> **Obligatoria.** No está prohibido usar asistentes de IA. Lo que se evalúa es
> que entiendan lo que entregan. La omisión de esta declaración es **causal de
> rechazo automático** de la entrega. Una declaración honesta no baja la nota.

**¿El grupo usó asistentes de IA en este trabajo?**  Sí 

*Si la respuesta es No, firmen igual la sección y pasen al final.*

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| Claude (Anthropic) | Explicación de funciones de `pathlib` (`rglob`, `is_file`, `relative_to`, `as_posix`, `resolve`) y guía para implementar los TODO 1 y 2. Formateo de las salidas de terminal para la sección B.1. | `src/integridad.py`: funciones `generar_manifiesto()` y `verificar_manifiesto()`. Sección B.1 del informe. | El código se escribió y se probó de forma incremental: cada paso se ejecutó en la terminal antes de agregar el siguiente. Se verificaron los casos de directorio íntegro, modificación de un byte, archivo faltante, archivo nuevo, directorio vacío y manifiesto dentro del directorio recorrido. Las salidas pegadas en B.1 son reales. |
| OpenAI Codex | Explicación conceptual, implementación y depuración de los TODO 3 y 4; revisión de respuestas de análisis; apoyo para P3 y P5. | `src/integridad.py`: `distancia_hamming_bits()` y `calcular_mac()`; evidencia B.1; respuestas P1, P2, P3, P4 y P5. | Se verificó con pruebas directas de casos idénticos, bits opuestos, longitudes inválidas, HMAC válido e inválido, ejecución de la CLI, consulta de fuentes originales, `py_compile` y `git diff --check`. |
| Claude (Anthropic) — Cowork | Lectura del repositorio y de la rúbrica para determinar el alcance pendiente; búsqueda y contraste de fuentes sobre Stuxnet; asistencia en la redacción y estructuración de la Parte A. | Secciones A.1 a A.6 del informe (caso Stuxnet). | Se entró a cada URL citada y se verificó que resuelve y que contiene el dato afirmado: dossier de Symantec v1.4 en Broadcom, informes ISIS de dic-2010 y feb-2011, «To Kill a Centrifuge» en langner.com, boletín MS10-046 en Microsoft Learn y CVE-2010-2568 en el NVD del NIST. Se descartaron cifras que no pudieron confirmarse contra una fuente. Se contrastó además la atribución del incidente, que se declara explícitamente como versión periodística y no como hecho establecido. |

**Declaración:**

*El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del análisis,
independientemente de la asistencia recibida.*

---

## Fuentes consultadas (general)

*Todas las fuentes del trabajo, en formato APA. Las de la Parte A pueden
repetirse acá o referenciarse a la sección A.6.*

1. NIST. (2006). *Cryptographic hash standards: Where do we go from here?*
   https://www.nist.gov/publications/cryptographic-hash-standards-where-do-we-go-here
2. NIST. (2017). *Research results on SHA-1 collisions*.
   https://csrc.nist.gov/News/2017/Research-Results-on-SHA-1-Collisions
3. OWASP Foundation. (s. f.). *Password storage cheat sheet*.
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
4. Las fuentes de la Parte A (nueve referencias sobre el caso Stuxnet, con su
   marcación de primaria / arbitrada / secundaria) están listadas en la sección
   **A.6 — Fuentes consultadas (Parte A)**.
