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

SHA-256 es una función pública, por lo que cualquiera puede recalcular el digest de un archivo modificado y sobrescribir el manifiesto. Al verificar, `verificar` compara el hash recalculado contra el hash guardado, pero ambos valores quedan bajo control del atacante, así que el resultado será `OK`. El esquema actual solo detecta corrupción accidental o errores de copia, sin tener en cuenta a un adversario activo con el mismo privilegio de escritura.

Para que el ataque no funcione las opciones son: firmar digitalmente el manifiesto con una clave privada, reemplazar el hash simple por un HMAC-SHA256 con una clave guardada fuera del directorio verificado, o almacenar el manifiesto en un medio inmutable o servidor remoto. En la práctica esto es guardar el manifiesto en otro host, en un commit firmado de Git. Sin ese ancla externa de confianza, `generar + verificar` no aporta seguridad frente a manipulación intencional.

---

### 2. Qué agrega HMAC y qué no

*¿Qué propiedad de seguridad aporta HMAC que un hash simple no aporta? Y la
parte importante: ¿qué **no** resuelve HMAC? Pensá en el no repudio y en
quién conoce la clave.*

**Respuesta:**

HMAC-SHA256 agrega tanto autenticidad como integridad. El tag se calcula como `HMAC(K, mensaje)` usando una clave secreta `K` compartida. Con un hash simple cualquiera puede recalcular `SHA-256(mensaje)` y crear un valor válido. Con HMAC solo quien conoce `K` puede producir un tag que el verificador acepte. Por eso el subcomando `mac` prueba a la vez que el mensaje no fue alterado y que lo generó alguien del grupo que posee el secreto.

HMAC al ser simétrico, el emisor y verificador conocen la misma `K` dando por entendido que cualquiera de los dos pudo haber creado el tag. Ante un tercero o un juez no se puede probar quién lo generó, entonces se necesita firma digital asimétrica con clave privada exclusiva del firmante. HMAC tampoco aporta confidencialidad, ni protege contra replay (un par mensaje/tag válido anterior puede reenviarse), ni sirve de nada si la clave se filtra o se comparte por un canal inseguro.

---

### 3. MD5 y SHA-1

*Ambos siguen apareciendo en software en producción. ¿Qué propiedad
criptográfica se les rompió, exactamente? ¿Hay algún uso en el que todavía
sean aceptables, o ninguno? Fundamentá con al menos una fuente.*

**Respuesta:**

Hoy es computacionalmente factible encontrar dos entradas distintas `M1 != M2` con el mismo digest. En MD5 hay colisiones en segundos y de prefijo elegido usadas en la práctica por el malware Flame para forjar certificados. En SHA-1 el proyecto SHAttered demostró la primera colisión completa con unas 2^63 evaluaciones, y en 2020 el ataque SHAmbles logró colisiones de prefijo elegido, lo que invalida su uso en firmas digitales y certificados. La resistencia a preimagen y segunda preimagen (recuperar la entrada dado el digest) sigue costando del orden de 2^128 en MD5 y 2^160 en SHA-1 y no está rota en la práctica, pero el margen de seguridad colapsó y los estándares las declaran inseguras para uso criptográfico.

Siguen siendo aceptables para la detección de corrupción accidental, checksums no críticos, tablas hash internas o identificadores de contenido. Git sigue usando SHA-1 con detección de colisiones mientras completa su migración a SHA-256, porque en ese contexto la amenaza no es un atacante forjando commits a voluntad. Son inaceptables para firmas digitales, certificados TLS, almacenamiento de contraseñas y cualquier protocolo donde la colisión permita suplantación.

**Fuentes:**

Stevens, M., Bursztein, E., Karpman, P., Albertini, A. y Markov, Y. (2017). *The first collision for full SHA-1*. Google Security Blog / CWI Amsterdam. https://shattered.io. Leurent, G. y Peyrin, T. (2020). SHA-1 is a Shambles: First chosen-prefix collision on SHA-1. En *Advances in Cryptology – EUROCRYPT 2020*. https://sha-mbles.github.io. Turner, S. y Chen, L. (2011). *RFC 6151: Updated Security Considerations for the MD5 Message-Digest Algorithm*. IETF. https://www.rfc-editor.org/rfc/rfc6151. Polk, T., Chen, L., Turner, S. y Hoffman, P. (2011). *RFC 6194: Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms*. IETF. https://www.rfc-editor.org/rfc/rfc6194.

---

### 4. Comparación en tiempo constante

*¿Por qué comparar un tag de autenticación con `==` puede filtrar información
al atacante, y cómo lo evita `hmac.compare_digest()`? Describí el ataque
concreto que esto previene.*

**Respuesta:**

El operador `==` sobre `str` o `bytes` en Python implementa una comparación con retorno temprano: recorre ambos operandos byte a byte y devuelve `False` en cuanto encuentra la primera diferencia. El tiempo que tarda la comparación depende entonces de cuántos bytes iniciales del tag adivinó correctamente el atacante. Se prueban los 256 valores del primer byte y se queda con el que tarda un poco más en responder, luego repite con el segundo byte, y así reconstruye el tag válido sin conocer la clave. Con suficientes muestras y promediado estadístico este ataque de canal lateral funciona incluso a través de la red, y es especialmente grave en verificadores de HMAC, tokens de sesión o enlaces de restablecimiento.

`hmac.compare_digest()` lo evita recorriendo siempre la totalidad de ambos operandos, ejecutando el mismo número de operaciones elementales y sin retorno temprano, de modo que el tiempo de ejecución no depende del contenido comparado. Elimina la fuga por tiempo y cierra ese oráculo concreto. Por eso la rúbrica del laboratorio exige `compare_digest()` en el subcomando `mac` y penaliza el uso de `==`.

---

### 5. SHA-256 para contraseñas: mala idea

*SHA-256 es una función de hash criptográfica sólida. ¿Por qué, entonces, es
una mala elección para almacenar contraseñas? ¿Qué se usa en su lugar y qué
propiedad tienen esas funciones que SHA-256 no tiene?*

**Respuesta:**

Si la base guarda directamente `SHA-256(password)`, quien la roba puede probar diccionarios, listas de contraseñas filtradas y fuerza bruta a una gran velocidad, en paralelo contra todos los usuarios a la vez. Además, sin sal única por usuario, dos cuentas con la misma contraseña comparten el mismo digest, lo que permite tablas arcoíris y cracking masivo amortizado.

En su lugar se usan funciones de derivación de clave específicas para contraseñas, con sal aleatoria única por usuario y costo configurable. La recomendación actual de OWASP es Argon2id, scrypt, bcrypt o PBKDF2 con un número alto de iteraciones. La propiedad que tienen y SHA-256 no tiene es que cada verificación cuesta, por ejemplo, unos 100 ms y varios MB de RAM, lo que lo vuelve inviable para probar miles de millones de candidatos y neutraliza la ventaja de GPUs y ASICs. NIST SP 800-63B y OWASP Password Storage Cheat Sheet exigen siempre función lenta con sal única y, opcionalmente, un pepper secreto del servidor.

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

**¿El grupo usó asistentes de IA en este trabajo?**  Sí
 
 *Si la respuesta es No, firmen igual la sección y pasen al final.*
 
 | Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
 |---|---|---|---|
 | Gemini (Antigravity) | Búsqueda de fuentes históricas, redacción y armado de commits | Sección A.1 (Cronología) | Verificando manualmente que las fechas coincidieran con la historia oficial del FBI y LLNL. |

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
