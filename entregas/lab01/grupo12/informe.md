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
| **Grupo** | 12 |
| **Caso asignado (Parte A)** | Morris Worm (1988) - Justificación: 12 mod 6 = 0 |
| **Tema del mini-research** | |
| **Fecha de entrega** | |

### Integrantes

*Esta tabla también va en `INTEGRANTES.md`. Solo nombre, legajo y usuario de
GitHub. Nada de DNI, teléfono ni dirección: el repositorio es público.*

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| | | @ |
| | | @ |
| | | @ |
| | | @ |
| | | @ |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

*Máximo 10 líneas. Qué pasó, cuándo, en qué orden. **Cada afirmación con su
fuente.** Si no encontrás una fuente que lo respalde, no lo escribas.*

| Fecha | Hecho | Fuente |
|---|---|---|
| 2 de noviembre 1988 (aprox 20:30 EST) | Robert Tappan Morris libera el gusano desde MIT para ocultar origen. | FBI Records / Wikipedia |
| 2 de noviembre 1988 (20:00 - 22:00 EST) | Admins en UC Berkeley notan carga inusual y reportan ataque de virus. | Lawrence Livermore National Laboratory (LLNL) |
| 2 de noviembre 1988 (22:00 EST) | En LLNL observan un aumento de 1000x en carga y confirman el gusano. | LLNL |
| 3 de noviembre 1988 | El gusano infecta miles de máquinas, aprox 10% de Internet (incl. NASA). | Cornell University |
| 3 de noviembre 1988 | Por defecto de diseño, reinfecta sistemas agotando recursos de forma masiva. | PCMag / UNC |
| Noviembre de 1988 | DARPA establece el CERT en respuesta al incidente para futura coordinación. | Limn - The Morris Worm |
| 1990 | Autor es la primera persona condenada por Ley de Fraude Informático (1986). | FBI Records |

---

## A.2 — Activo afectado

**Activo principal:** Disponibilidad de la capacidad de cómputo y de la red ARPANET — ciclos de CPU, memoria y servicio de red de hosts Unix BSD 4.3 (VAX, Sun 3) pertenecientes a universidades y centros de investigación (MIT, Berkeley, Purdue, Stanford, NASA, entre otros), aproximadamente 6.000 hosts comprometidos (cerca del 10% de Internet en 1988).

**Por qué es el principal:** El Morris Worm no buscó borrar ni exfiltrar una base de datos puntual; su defecto de reinfección descontrolada saturó procesos críticos (`sendmail` con modo DEBUG, `fingerd` con desbordamiento de buffer, `rsh`/`rhosts` con confianza) y forzó reinicios continuos. El impacto medible y masivo fue la pérdida de servicio — sistemas inoperables por agotamiento de recursos — del cual derivan los demás daños. La prioridad se justifica porque la caída operativa bloqueó cualquier uso de los otros activos.

**Otros activos afectados (en orden de criticidad):**
1. **Integridad de datos y procesos locales** — archivos temporales y estado de procesos alterados por la carga del gusano, sin destrucción masiva intencional pero con corrupción operativa.
2. **Confidencialidad de credenciales y acceso** — explotación de contraseñas débiles y confianza `rsh`/`rhosts` para propagarse, exponiendo mecanismos de autenticación.
3. **Confianza operativa en Internet naciente** — activo reputacional y sistémico: pérdida de confianza de la comunidad ARPANET/NSFNET que motivó la creación del CERT/CC como respuesta institucional.

---

## A.3 — Matriz CIA

*Una fila por propiedad. La columna «Evidencia» tiene que citar un hecho
concreto del incidente, no una generalidad.*

> **Advertencia.** «No» es una respuesta válida y muchas veces la correcta.
> El error típico es marcar las tres propiedades en «Sí» porque el incidente
> fue grave. La gravedad no es una propiedad de la tríada. Si marcás que se
> violó la integridad, tenés que mostrar **qué dato específico fue alterado**.
> Si no podés mostrarlo, la respuesta es «No».

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | No | El gusano no accedió, robó, filtró ni leyó información o datos confidenciales de los usuarios ni de las instituciones. |
| **Integridad** | No | Ningún archivo, base de datos o registro de los sistemas infectados fue modificado, corrompido o borrado por el código del gusano. |
| **Disponibilidad** | Sí | La continua propagación y reinfección del gusano generó múltiples procesos que saturaron por completo la memoria y CPU de los servidores, provocando una caída masiva de los mismos (DoS). |

**Justificación ampliada de la propiedad más discutible:**

La integridad y la confidencialidad son frecuentemente malinterpretadas en este incidente. Dado que fue un evento grave de escala global, es muy común asumir que el atacante "vulneró todo". Sin embargo, Morris programó el gusano inicialmente solo para "medir el tamaño de internet", sin una carga útil maliciosa destructiva. Fue exclusivamente un error de diseño (la tasa de reinfección sin control de 1 en 7) lo que accidentalmente transformó un experimento de descubrimiento en un ataque de denegación de servicio, afectando por ende pura y exclusivamente a la disponibilidad.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

```
amenaza  →  explota  →  vulnerabilidad  →  sobre  →  activo  →  produce  →  impacto
```

| Elemento | En este caso |
|---|---|
| **Amenaza** *(quién / qué, con qué motivación)* | Robert Tappan Morris (estudiante de posgrado, Cornell) mediante el gusano autorreplicante Morris Worm. Motivación inicial: curiosidad académica para medir el tamaño de Internet, sin carga destructiva intencional, pero ejecutando código no autorizado en sistemas ajenos. |
| **Vulnerabilidad** *(la debilidad concreta que se explotó)* | Conjunto de debilidades concretas encadenadas: (1) desbordamiento de buffer en `fingerd` de BSD, (2) modo DEBUG de `sendmail` que permitía ejecución remota, (3) confianza transitiva `rsh`/`rhosts` + contraseñas débiles por diccionario, y (4) defecto de diseño del propio gusano que reinfectaba 1 de cada 7 veces aun en hosts ya infectados, impidiendo throttling. |
| **Activo** *(sobre qué recayó)* | Disponibilidad de la capacidad de cómputo y red ARPANET — hosts VAX/Sun 3 Unix BSD 4.3 de universidades y centros (MIT, Berkeley, Purdue, NASA), ~6.000 equipos (≈10% de Internet en 1988). |
| **Impacto** *(consecuencia sobre el negocio o las personas)* | Denegación de servicio masiva (hosts inoperables por horas/días), costos de limpieza y reconexión, y consecuencia institucional: creación del CERT/CC por DARPA y primera condena bajo la Computer Fraud and Abuse Act de 1986. |

**Redacción:**

La amenaza (Morris y su gusano autorreplicante) explotó vulnerabilidades concretas —el desbordamiento de `fingerd`, el modo DEBUG de `sendmail` y la confianza `rsh`/`rhosts`— para propagarse sobre el activo disponibilidad de los hosts ARPANET. Al hacerlo sin control de reinfección (1/7), agotó CPU y memoria y produjo el impacto de indisponibilidad masiva de ~6.000 sistemas, que derivó en costos operativos y en la creación del CERT/CC como mecanismo de coordinación nacional.

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | **Gestión de vulnerabilidades y parcheo continuo (Patch Management)**. Es un proceso sistemático para identificar, clasificar e instalar actualizaciones de seguridad (parches) en el software de la red. |
| **Propiedad de la tríada que protege** | **Disponibilidad** e **Integridad** (al evitar que un atacante ejecute código que modifique el flujo del programa o tire el servicio). |
| **Por qué habría funcionado en este caso concreto** | El gusano explotaba vulnerabilidades ya conocidas en los servicios `sendmail` (modo DEBUG) y `fingerd` (desbordamiento de búfer). Si los servidores hubiesen tenido aplicados los parches correspondientes, los vectores principales de infección habrían fallado, impidiendo que el gusano ingrese y consuma los recursos (CPU/Memoria) del sistema. |

### Control 2

| | |
|---|---|
| **Qué es** | **Desactivación de relaciones de confianza implícita y Hardening de contraseñas**. Eliminar configuraciones que permiten accesos sin contraseña entre máquinas y forzar políticas de contraseñas robustas. |
| **Propiedad de la tríada que protege** | **Confidencialidad** e **Integridad** (asegurando que solo personal autorizado ingrese). Al bloquear accesos ilegítimos, también se preservó en este caso la **Disponibilidad**. |
| **Por qué habría funcionado en este caso concreto** | Además de los exploits, el gusano utilizaba el comando `rsh` (Remote Shell) abusando de relaciones de confianza entre máquinas, y realizaba ataques de diccionario para adivinar contraseñas débiles. Si no hubieran existido estas configuraciones permisivas, el malware no habría podido propagarse lateralmente de forma tan agresiva. |

---

## A.6 — Fuentes consultadas (Parte A)

*Formato APA. Indicá para cada una si es primaria (informe oficial, documento
del fabricante, resolución judicial, paper) o secundaria (nota periodística,
entrada de blog).*

1. Federal Bureau of Investigation (FBI). (2018). *The Morris Worm: 30 Years Since First Major Attack on Internet*. https://www.fbi.gov/news/stories/morris-worm-30-years-since-first-major-attack-on-internet-110218 (Fuente secundaria).
2. Brand, R. (2001). *The Morris Worm*. Lawrence Livermore National Laboratory (LLNL) Science & Technology Review. https://str.llnl.gov/str/October01/Brand.html (Fuente primaria, relato técnico directo de quienes frenaron el ataque).
3. Kehoe, B. P. (1992). *Zen and the Art of the Internet: A Beginner's Guide (The Morris Internet Worm)*. Cornell University. https://www.cs.cornell.edu/courses/cs513/2005fa/L08.html (Fuente secundaria).

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

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

```
$ python3 data/generar_datos.py
$ rm data/muestra/politica_seguridad.md
$ touch data/muestra/backdoor.sh
$ python3 src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data/muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     0
  FALTANTE       1
  NUEVO          1

Hallazgos:
  [FALTANTE] politica_seguridad.md
  [NUEVO] backdoor.sh

INTEGRIDAD COMPROMETIDA — 2 hallazgo(s).
$ echo "código de salida: $?"
código de salida: 1
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

**Distancia obtenida:** 139 bits de 256 (54.30 %)

El resultado coincide plenamente con lo esperado. En una función de hash criptográfica segura, una alteración ínfima en la entrada (en este caso, un único carácter y apenas unos pocos bits entre `$1000` y `$1001`) genera un cambio pseudoaleatorio que afecta aproximadamente a la mitad de los bits de salida. Dado que SHA-256 produce un digest de 256 bits, el valor teórico esperado ronda los 128 bits (50 %); el resultado obtenido (139 bits, 54.30 %) refleja un comportamiento estadístico normal y evidencia claramente el efecto avalancha.

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
$ echo "código de salida: $?"
código de salida: 0

$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9ff
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9ff

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
$ echo "código de salida: $?"
código de salida: 1
```

---

## B.2 — Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| **Exclusión del archivo de manifiesto** | Comparamos las rutas normalizadas mediante `Path.resolve()` tanto al generar como al verificar. | Si el archivo de manifiesto reside dentro del directorio recorrido, incluirlo causaría una paradoja de cálculo y reportaría un falso positivo (`NUEVO`) en verificaciones subsiguientes. |
| **Normalización de rutas a formato POSIX** | Utilizamos `.relative_to(directorio).as_posix()` para registrar cada camino relativo con `/`. | Garantiza la interoperabilidad multiplataforma: un manifiesto generado en Windows (donde el separador es `\`) se verifica limpiamente en sistemas Linux/macOS. |
| **Filtrado estricto de elementos** | Procesamos únicamente rutas donde `p.is_file()` sea verdadero, omitiendo directorios intermedios. | Los directorios no poseen un flujo binario para hashear directamente; procesar solo archivos regulares asegura lecturas por bloques limpias y sin excepciones. |
| **Ordenamiento determinista de claves** | Ordenamos alfabéticamente las claves del diccionario con `dict(sorted(...))` y las listas resultantes de cada estado. | Un manifiesto se audita y versiona; garantizar un orden determinista evita discrepancias espurias en herramientas de control de versiones (`git diff`) entre distintas ejecuciones. |
| **Cálculo de distancia de Hamming a nivel de bits** | Aplicamos el operador XOR (`^`) byte a byte sobre los bytes crudos (`.digest()`) y contamos con `.bit_count()`. | Comparar sobre la representación hexadecimal introduce errores graves, ya que cada dígito hex abarca 4 bits; el efecto avalancha se mide con exactitud sobre los 256 bits reales. |
| **Comparación de MAC en tiempo constante** | Empleamos `hmac.compare_digest()` tras normalizar los tags a minúsculas, descartando el operador `==`. | Previene ataques de canal lateral basados en tiempo (timing attacks), donde un atacante mide la latencia de respuesta para deducir el tag byte por byte. |

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

| Integrante | Aportes |
|---|---|
| Mateo Gerbaudo | Inicialización del repositorio, Parte A (A.2 activo afectado y A.4 encadenamiento). |
| Matias Mariatti | Parte A (A.1 cronología, A.3 matriz CIA, A.5 controles mitigantes y A.6 fuentes). |
| Alvaro Colque | Parte B: implementación en Python de `integridad.py` (TODOs 1 a 4), ejecución de pruebas y evidencias B.1, decisiones de implementación B.2. |
| Gonzalo | Parte B: preguntas de análisis B.3. |

---

## Declaración de uso de asistentes de IA

> **Obligatoria.** No está prohibido usar asistentes de IA. Lo que se evalúa es
> que entiendan lo que entregan. La omisión de esta declaración es **causal de
> rechazo automático** de la entrega. Una declaración honesta no baja la nota.

**¿El grupo usó asistentes de IA en este trabajo?**  Sí
 
 | Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
 |---|---|---|---|
 | Gemini (Antigravity) | Búsqueda de fuentes históricas, redacción y armado de commits | Sección A.1 (Cronología) | Verificando manualmente que las fechas coincidieran con la historia oficial del FBI y LLNL. |
 | Gemini (Antigravity) | Asistencia en la implementación de funciones de hash/HMAC y redacción de decisiones | Sección B.1 y B.2 | Ejecución directa de los comandos en terminal, validación del código de retorno ($?) y verificación contra la rúbrica de cátedra. |

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
