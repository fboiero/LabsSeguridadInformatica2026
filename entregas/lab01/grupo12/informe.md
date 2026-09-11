# Laboratorio 01 — Informe

---

## Identificación

| | |
|---|---|
| **Grupo** | 12 |
| **Caso asignado (Parte A)** | Morris Worm (1988) - Justificación: 12 mod 6 = 0 |
| **Tema del mini-research** | Tema 3 — La disponibilidad, la propiedad descuidada de la tríada |
| **Fecha de entrega** | 2026-05-11 |

### Integrantes

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Gerbaudo, Mateo | 14157 | @gerbaudo19 |
| Mariatti, Matias | 13293 | @matiasmariatticasc |
| Colque Condo, Luis Alvaro | 14994 | @ColqueAlvaro |
| Rodriguez, Gonzalo | 15310 | @Gonza149 |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha | Hecho | Fuente |
|---|---|---|
| 2 de noviembre 1988 (aprox 20:30 EST) | Robert Tappan Morris libera el gusano desde MIT para ocultar origen. | FBI (2018) |
| 2 de noviembre 1988 (20:00 - 22:00 EST) | Admins en UC Berkeley notan carga inusual y reportan ataque de virus. | Brand (2001) LLNL |
| 2 de noviembre 1988 (22:00 EST) | En LLNL observan un aumento de 1000x en carga y confirman el gusano. | Brand (2001) LLNL |
| 3 de noviembre 1988 | El gusano infecta miles de máquinas, aprox 10% de Internet (incl. NASA). | Kehoe (1992) Cornell |
| 3 de noviembre 1988 | Por defecto de diseño, reinfecta 1/7 aun en hosts ya infectados, agotando recursos. | Spafford (1988) Purdue / Brand (2001) |
| Noviembre de 1988 | DARPA establece el CERT/CC en respuesta al incidente. | Brand (2001) LLNL |
| 1990 | Autor es la primera persona condenada bajo Computer Fraud and Abuse Act (1986). | FBI (2018) |

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

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | No | El gusano no exfiltró ni publicó datos de usuario; sí recolectó credenciales de `/etc/passwd` y explotó `rhosts` para propagarse, pero sin filtración masiva de información confidencial (FBI, 2018; Brand, 2001). Se marca No porque no hubo divulgación de datos personales a terceros. |
| **Integridad** | No | No hubo borrado/corrupción de archivos de usuario o bases de datos; hubo alteración volátil de estado (procesos/tablas en memoria) por sobrecarga, sin modificación persistente de datos de negocio. |
| **Disponibilidad** | Sí | Reinfección 1/7 provocó agotamiento de CPU/memoria y caída masiva de ~6.000 hosts (DoS) documentada por LLNL (Brand, 2001). |

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
| **Qué es** | **Gestión de vulnerabilidades y parcheo continuo (Patch Management)**. Proceso sistemático para identificar, clasificar e instalar parches de seguridad. |
| **Propiedad de la tríada que protege** | **Disponibilidad** (principal, al evitar caída por agotamiento; secundariamente integridad del flujo de ejecución). |
| **Por qué habría funcionado en este caso concreto** | Parchear `sendmail` (desactivar DEBUG) y `fingerd` (corregir buffer overflow) cerraba los dos vectores remotos iniciales descritos por Spafford (1988) y Brand (2001), impidiendo el ingreso y la consiguiente saturación de CPU/memoria. |

### Control 2

| | |
|---|---|
| **Qué es** | **Eliminación de confianza implícita `rsh`/`rhosts` y hardening de contraseñas**. Desactivar `.rhosts`/hosts.equiv y exigir contraseñas robustas. |
| **Propiedad de la tríada que protege** | **Confidencialidad** (credenciales) e **Integridad** de acceso; al bloquear propagación lateral preserva indirectamente **Disponibilidad**. |
| **Por qué habría funcionado en este caso concreto** | El gusano propagaba vía `rsh` con `rhosts` y diccionario de 432 palabras (Brand, 2001). Sin trust transitivo ni contraseñas débiles, el salto lateral se cortaba aun si el exploit inicial funcionaba. |

---

## A.6 — Fuentes consultadas (Parte A)

1. Federal Bureau of Investigation (FBI). (2018). *The Morris Worm: 30 Years Since First Major Attack on Internet*. https://www.fbi.gov/news/stories/morris-worm-30-years-since-first-major-attack-on-internet-110218 (Fuente secundaria).
2. Brand, R. (2001). *The Morris Worm*. Lawrence Livermore National Laboratory (LLNL) Science & Technology Review. https://str.llnl.gov/str/October01/Brand.html (Fuente primaria, relato técnico directo de quienes frenaron el ataque).
3. Kehoe, B. P. (1992). *Zen and the Art of the Internet: A Beginner's Guide (The Morris Internet Worm)*. Cornell University. https://www.cs.cornell.edu/courses/cs513/2005fa/L08.html (Fuente secundaria).
4. Spafford, E. H. (1988). *The Internet Worm Program: An Analysis* (Purdue CS-TR 823). Purdue University. https://spaf.cerias.purdue.edu/tech-reps/823.pdf (Fuente primaria, análisis forense del código del gusano).

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
$ python3 src/integridad.py generar --dir data/muestra --salida manifest.sha256
Manifiesto generado: manifest.sha256
Directorio base:     data/muestra
Archivos indexados:  4
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

### 1. El manifiesto por sí solo no alcanza

**Respuesta:**

SHA-256 es una función pública, por lo que cualquiera puede recalcular el digest de un archivo modificado y sobrescribir el manifiesto. Al verificar, `verificar` compara el hash recalculado contra el hash guardado, pero ambos valores quedan bajo control del atacante, así que el resultado será `OK`. El esquema actual solo detecta corrupción accidental o errores de copia, sin tener en cuenta a un adversario activo con el mismo privilegio de escritura.

Para que el ataque no funcione las opciones son: firmar digitalmente el manifiesto con una clave privada, reemplazar el hash simple por un HMAC-SHA256 con una clave guardada fuera del directorio verificado, o almacenar el manifiesto en un medio inmutable o servidor remoto. En la práctica esto es guardar el manifiesto en otro host, en un commit firmado de Git. Sin ese ancla externa de confianza, `generar + verificar` no aporta seguridad frente a manipulación intencional.

---

### 2. Qué agrega HMAC y qué no

**Respuesta:**

HMAC-SHA256 agrega tanto autenticidad como integridad. El tag se calcula como `HMAC(K, mensaje)` usando una clave secreta `K` compartida. Con un hash simple cualquiera puede recalcular `SHA-256(mensaje)` y crear un valor válido. Con HMAC solo quien conoce `K` puede producir un tag que el verificador acepte. Por eso el subcomando `mac` prueba a la vez que el mensaje no fue alterado y que lo generó alguien del grupo que posee el secreto.

HMAC al ser simétrico, el emisor y verificador conocen la misma `K` dando por entendido que cualquiera de los dos pudo haber creado el tag. Ante un tercero o un juez no se puede probar quién lo generó, entonces se necesita firma digital asimétrica con clave privada exclusiva del firmante. HMAC tampoco aporta confidencialidad, ni protege contra replay (un par mensaje/tag válido anterior puede reenviarse), ni sirve de nada si la clave se filtra o se comparte por un canal inseguro.

---

### 3. MD5 y SHA-1

**Respuesta:**

Hoy es factible hallar `M1 != M2` con mismo digest (Stevens et al., 2017; Leurent & Peyrin, 2020). En MD5 hay colisiones en segundos y de prefijo elegido usadas por Flame para forjar certificados (Turner & Chen, 2011). En SHA-1 SHAttered demostró la primera colisión completa con ~2^63 evaluaciones, y SHAmbles (2020) logró colisión de prefijo elegido, invalidando su uso en firmas y certificados (Polk et al., 2011). La resistencia a preimagen/segunda preimagen sigue en ~2^128 (MD5) y ~2^160 (SHA-1), pero el margen colapsó y los estándares las declaran inseguras para uso criptográfico.

Siguen aceptables para corrupción accidental, checksums no críticos, tablas hash o IDs de contenido. Git usa SHA-1 con detección de colisiones mientras migra a SHA-256, porque allí el atacante no forja commits a voluntad. Son inaceptables para firmas, TLS, contraseñas o cualquier protocolo donde colisión permita suplantación.

**Fuentes:**

Stevens, M., Bursztein, E., Karpman, P., Albertini, A. y Markov, Y. (2017). *The first collision for full SHA-1*. Google / CWI Amsterdam. https://shattered.io. Leurent, G. y Peyrin, T. (2020). SHA-1 is a Shambles: First chosen-prefix collision on SHA-1. En *Advances in Cryptology – EUROCRYPT 2020*. https://sha-mbles.github.io. Turner, S. y Chen, L. (2011). *RFC 6151: Updated Security Considerations for the MD5 Message-Digest Algorithm*. IETF. https://www.rfc-editor.org/rfc/rfc6151. Polk, T., Chen, L., Turner, S. y Hoffman, P. (2011). *RFC 6194: Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms*. IETF. https://www.rfc-editor.org/rfc/rfc6194.

---

### 4. Comparación en tiempo constante

**Respuesta:**

El operador `==` sobre `str` o `bytes` en Python implementa una comparación con retorno temprano: recorre ambos operandos byte a byte y devuelve `False` en cuanto encuentra la primera diferencia. El tiempo que tarda la comparación depende entonces de cuántos bytes iniciales del tag adivinó correctamente el atacante (Grassi et al., 2017). Se prueban los 256 valores del primer byte y se queda con el que tarda un poco más en responder, luego repite con el segundo byte, y así reconstruye el tag válido sin conocer la clave. Con suficientes muestras y promediado estadístico este ataque de canal lateral funciona incluso a través de la red, y es especialmente grave en verificadores de HMAC, tokens de sesión o enlaces de restablecimiento.

`hmac.compare_digest()` lo evita recorriendo siempre la totalidad de ambos operandos, ejecutando el mismo número de operaciones elementales y sin retorno temprano, de modo que el tiempo de ejecución no depende del contenido comparado. Elimina la fuga por tiempo y cierra ese oráculo concreto. Por eso la rúbrica del laboratorio exige `compare_digest()` en el subcomando `mac` y penaliza el uso de `==`.

---

### 5. SHA-256 para contraseñas: mala idea

**Respuesta:**

Si la base guarda directamente `SHA-256(password)`, quien la roba puede probar diccionarios, listas filtradas y fuerza bruta a gran velocidad, en paralelo contra todos los usuarios (OWASP, 2024; Grassi et al., 2017). Además, sin sal única por usuario, dos cuentas con la misma contraseña comparten el mismo digest, lo que permite tablas arcoíris y cracking masivo amortizado.

En su lugar se usan funciones de derivación de clave específicas para contraseñas, con sal aleatoria única por usuario y costo configurable. La recomendación actual de OWASP es Argon2id, scrypt, bcrypt o PBKDF2 con un número alto de iteraciones. La propiedad que tienen y SHA-256 no tiene es que cada verificación cuesta, por ejemplo, unos 100 ms y varios MB de RAM, lo que lo vuelve inviable para probar miles de millones de candidatos y neutraliza la ventaja de GPUs y ASICs. NIST SP 800-63B y OWASP Password Storage Cheat Sheet exigen siempre función lenta con sal única y, opcionalmente, un pepper secreto del servidor (Grassi et al., 2017; OWASP, 2024).

---

# Cierre

## Dificultades encontradas

La mayor dificultad fue alinear el análisis conceptual con la implementación. En la Parte A costó precisar el activo principal del Morris Worm sin caer en generalidades y decidir la matriz CIA: la tentación era marcar las tres propiedades como violadas por la gravedad, hasta entender que integridad y confidencialidad requieren evidencia de dato alterado o filtrado concreto, no solo impacto. Se resolvió volviendo a fuentes primarias (FBI, LLNL) y distinguiendo disponibilidad (DoS por reinfección 1/7) de efectos colaterales.

En la Parte B los desafíos fueron técnicos: lograr que `generar` excluya el propio `manifest.sha256` con `Path.resolve()`, garantizar rutas POSIX con `as_posix()` para que el manifest sea portable Windows/Linux, y sobre todo implementar `distancia_hamming_bits` sobre bytes crudos y no sobre hex (error que inicialmente daba valores ~30 en lugar de ~128). La comparación HMAC con `hmac.compare_digest()` en lugar de `==` se entendió al investigar timing attacks. La división de trabajo por pares (A vs B) y commits frecuentes por cada integrante evitó pisadas y permitió verificar cada subcomando con la prueba obligatoria de un byte (`printf 'X' >> transferencia.txt`) antes de integrar.

---

## Distribución del trabajo

| Integrante | Legajo | Aportes |
|---|---|---|
| Gerbaudo, Mateo | 14157 | Inicialización del repositorio, Parte A (A.2 activo afectado y A.4 encadenamiento). |
| Mariatti, Matias | 13293 | Parte A (A.1 cronología, A.3 matriz CIA, A.5 controles mitigantes y A.6 fuentes). |
| Colque Condo, Luis Alvaro | 14994 | Parte B: implementación en Python de `integridad.py` (TODOs 1 a 4), ejecución de pruebas y evidencias B.1, decisiones de implementación B.2. |
| Rodriguez, Gonzalo | 15310 | Parte B: preguntas de análisis B.3 (5 preguntas) y revisión general del informe. |

---

## Declaración de uso de asistentes de IA

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

Ver sección A.6 para fuentes de Parte A. Adicionalmente, para Parte B y preguntas de análisis:

1. National Institute of Standards and Technology. (2015). *FIPS PUB 180-4: Secure Hash Standard (SHS)*. U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.180-4 [PRIMARIA]
2. Krawczyk, H., Bellare, M., & Canetti, R. (1997). *RFC 2104: HMAC — Keyed-Hashing for Message Authentication*. IETF. https://www.rfc-editor.org/rfc/rfc2104 [PRIMARIA]
3. Stevens, M., Bursztein, E., Karpman, P., Albertini, A., & Markov, Y. (2017). *The first collision for full SHA-1* (SHAttered). Google / CWI Amsterdam. https://shattered.io [PRIMARIA]
4. Leurent, G., & Peyrin, T. (2020). SHA-1 is a Shambles: First chosen-prefix collision on SHA-1. En *Advances in Cryptology – EUROCRYPT 2020*. https://sha-mbles.github.io [ARBITRADA]
5. Turner, S., & Chen, L. (2011). *RFC 6151: Updated Security Considerations for the MD5 Message-Digest Algorithm*. IETF. https://www.rfc-editor.org/rfc/rfc6151 [PRIMARIA]
6. Grassi, P. A., Garcia, M. E., & Fenton, J. L. (2017). *NIST Special Publication 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management*. https://doi.org/10.6028/NIST.SP.800-63B [PRIMARIA]
7. OWASP. (2024). *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html [SECUNDARIA]
8. Federal Bureau of Investigation. (2018). *The Morris Worm: 30 Years Since First Major Attack on Internet*. https://www.fbi.gov/news/stories/morris-worm-30-years-since-first-major-attack-on-internet-110218 [SECUNDARIA]
