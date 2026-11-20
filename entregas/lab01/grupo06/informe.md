# Laboratorio 01 — Informe

---

## Identificación

|                             |                                                                  |
| --------------------------- | ---------------------------------------------------------------- |
| **Grupo**                   | 06                                                               |
| **Caso asignado (Parte A)** | Morris Worm (1988)                                               |
| **Tema del mini-research**  | Tema 3 — La disponibilidad, la propiedad descuidada de la tríada |
| **Fecha de entrega**        | 16/10/2026                                                       |

### Integrantes

| Nombre y apellido  | Legajo | Usuario de GitHub |
| ------------------ | ------ | ----------------- |
| Martín Beccereca   | 15154  | @martinbeccereca  |
| María Belén Benito | 14625  | @belubenito603    |
| Alejo De Miguel    | 15138  | @AlejoDM          |
| Tomás Giudici      | 14977  | @TomasGiudici     |
| Carolina Suppo     | 15057  | @carosuppo        |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha                      | Hecho                                                                                                                                                                                                                                                      | Fuente                                                                                                                                                                                                                                                                                                                             |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1988-11-02 (noche)         | Robert Tappan Morris, estudiante de posgrado de Cornell, libera el gusano desde una máquina del MIT para disimular su origen real.                                                                                                                         | [_United States v. Morris_, 928 F.2d 504 (2d Cir. 1991)](https://law.resource.org/pub/us/case/reporter/F2/928/928.F2d.504.90-1336.774.html)                                                                                                                                                                                        |
| 1988-11-02/03              | El gusano se propaga explotando cuatro vectores: el modo debug de `sendmail`, desbordamiento de búfer en `fingerd`, relaciones de confianza (`rsh`), credenciales por diccionario (`rexec`).                                                               | [Spafford, E. H., _"The Internet Worm Program: An Analysis"_ (CSD-TR-823)](https://www.cerias.purdue.edu/techreports-ssl/public/823.pdf)                                                                                                                                                                                           |
| 1988-11 (horas siguientes) | Morris programó deliberadamente que 1 de cada 7 respuestas afirmativas de infección previa fuera ignorada para evitar que simularan estar infectados; subestimó la multiplicación resultante, agotando CPU y procesos (~6.000 de ~60.000 hosts afectados). | [_United States v. Morris_, 928 F.2d 504 (2d Cir. 1991)](https://law.resource.org/pub/us/case/reporter/F2/928/928.F2d.504.90-1336.774.html); [Lawrence Livermore National Laboratory, _"The 1988 Morris worm, the internet's first cyberattack"_](https://st.llnl.gov/news/look-back/1988-morris-worm-internets-first-cyberattack) |
| 1988-11 (días siguientes)  | DARPA encarga al Software Engineering Institute de Carnegie Mellon la creación de un centro de coordinación de emergencias informáticas; nace así el CERT/CC, en respuesta directa a este incidente.                                                       | [Carnegie Mellon University SEI, _"History of Innovation"_](https://www.sei.cmu.edu/history-of-innovation/)                                                                                                                                                                                                                        |
| 1990-05-16                 | El tribunal de distrito (juez Howard G. Munson, Distrito Norte de Nueva York) dicta sentencia: 3 años de libertad condicional, 400 horas de servicio comunitario y una multa de USD 10.050.                                                                | [_United States v. Morris_, 928 F.2d 504 (2d Cir. 1991)](https://law.resource.org/pub/us/case/reporter/F2/928/928.F2d.504.90-1336.774.html)                                                                                                                                                                                        |
| 1991-03-07                 | La Corte de Apelaciones del Segundo Circuito confirma la condena.                                                                                                                                                                                          | [_United States v. Morris_, 928 F.2d 504 (2d Cir. 1991)](https://law.resource.org/pub/us/case/reporter/F2/928/928.F2d.504.90-1336.774.html)                                                                                                                                                                                        |

---

## A.2 — Activo afectado

**Activo principal:** Los recursos de cómputo (tiempo de CPU, memoria RAM y entradas en la tabla de procesos) de estaciones Sun-3 y minicomputadoras VAX ejecutando variantes vulnerables de Unix BSD (4.3BSD y derivadas) conectadas a Internet en noviembre de 1988.

**Por qué es el principal:** Fue el recurso que el gusano saturó de forma directa. Debido a la lógica deliberada de reinfección (1 de cada 7 veces ignoraba si ya estaba presente), los equipos ejecutaban decenas de copias del programa en paralelo hasta agotar la memoria y bloquear el sistema operativo. Como resume el Lawrence Livermore National Laboratory (LLNL), _"the Morris worm did not damage or destroy files, it slowed systems to a crawl"_. Las fallas explotadas en `sendmail`, `fingerd`, `rsh` y contraseñas débiles sirvieron como vías de entrada, pero el impacto final recayó sobre la capacidad operativa de los equipos.

**Otros activos afectados:** La conectividad de la red en su conjunto. Para frenar la propagación y limpiar los equipos, administradores de universidades y centros de investigación optaron por desconectar temporalmente sus enlaces de ARPANET, interrumpiendo el intercambio de correo y archivos durante horas o días.

---

## A.3 — Matriz CIA

| Propiedad            | ¿Se violó?                                                              | Evidencia concreta                                                                                                                                                                                                                                                                                                                                                                                                                               |
| -------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Confidencialidad** | Afectación de credenciales; sin exfiltración documentada hacia terceros | El gusano accedió y leyó archivos locales como `/etc/passwd` (intentando descifrar contraseñas mediante listas de palabras) y tablas de red para propagarse. Las fuentes consultadas (Spafford, 1988) no documentan exfiltración hacia terceros; sí describen lectura de archivos locales y obtención no autorizada de credenciales.                                                                                                             |
| **Integridad**       | No respecto de los datos de usuario; sí respecto del estado del sistema | A nivel de datos y archivos de usuario, ningún documento fue destruido, corrompido ni modificado deliberadamente (_"the Morris worm did not damage or destroy files"_, LLNL). A nivel del sistema operativo existieron modificaciones no autorizadas transitorias (creación de archivos en `/tmp`, inyección de código en `fingerd` y alteración de tablas de procesos), pero el impacto predominante del ataque recayó sobre la disponibilidad. |
| **Disponibilidad**   | Sí                                                                      | La replicación excesiva del gusano consumió recursos de CPU, memoria y tabla de procesos. Como consecuencia, miles de máquinas (~6.000 de las ~60.000 conectadas a Internet) quedaron inutilizables o severamente degradadas, obligando a numerosas instituciones a desconectarse de la red para desinfectar sus equipos.                                                                                                                        |

**Justificación ampliada de la propiedad más discutible:**

Al analizar la **integridad** en el grupo, evaluamos si la creación de copias del gusano y de archivos temporales en `/tmp` debía clasificarse como una alteración de integridad. Si se evalúa el estado global del sistema operativo, existieron cambios no autorizados asociados a la infección (procesos en ejecución y desbordamiento de búfer en memoria). Sin embargo, bajo la óptica de los activos de información protegidos, las fuentes consultadas no describen rutinas destinadas a destruir o modificar deliberadamente datos de usuarios. Morris programó el gusano para replicarse sin destruir datos. Lo que se vio comprometido de manera masiva fue el funcionamiento operativo de los equipos por el consumo extremo de CPU y procesos. Por ello, clasificamos la respuesta como **«No respecto de los datos de usuario; sí respecto del estado del sistema»**, reconociendo que el impacto predominante del incidente recayó sobre la **disponibilidad**.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

| Elemento                                                     | En este caso                                                                                                                                                                                                                                                |
| ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Amenaza** _(quién / qué, con qué motivación)_              | El Morris Worm, desarrollado y liberado por Robert Tappan Morris con el objetivo declarado de demostrar deficiencias de seguridad en las redes de computadoras, aunque su propagación terminó teniendo consecuencias mucho mayores a las previstas.         |
| **Vulnerabilidad** _(la debilidad concreta que se explotó)_  | Fallas de seguridad en servicios de sistemas Unix BSD, principalmente el modo debug de `sendmail` y un desbordamiento de búfer en `fingerd`, además del abuso de relaciones de confianza entre hosts y contraseñas débiles susceptibles de ser adivinadas.  |
| **Activo** _(sobre qué recayó)_                              | Los recursos de cómputo y la capacidad operativa de las máquinas Unix conectadas a Internet: CPU, memoria, procesos y, de forma secundaria, la conectividad de red.                                                                                         |
| **Impacto** _(consecuencia sobre el negocio o las personas)_ | Saturación de recursos, degradación severa del rendimiento, caída o inutilización temporal de equipos y pérdida de disponibilidad de servicios en universidades, organismos gubernamentales, instalaciones militares y otros centros conectados a Internet. |

**Redacción:**

La amenaza estuvo representada por el Morris Worm y su capacidad de propagarse automáticamente entre equipos conectados a Internet. Para hacerlo, explotó vulnerabilidades concretas presentes en sistemas Unix derivados de BSD, entre ellas fallas en `sendmail` y `fingerd`, relaciones de confianza entre hosts y contraseñas que podían ser adivinadas. Estas debilidades permitieron acceder sin autorización a otros equipos y ejecutar nuevas copias del gusano sobre los recursos de cómputo de las máquinas afectadas. Debido a que Morris subestimó la multiplicación producida por la lógica de reinfección (al programar que 1 de cada 7 respuestas afirmativas fuera ignorada), se ejecutaron múltiples copias en un mismo host, consumiendo CPU, memoria y procesos hasta degradar severamente o impedir su funcionamiento normal. El impacto principal fue, por lo tanto, la pérdida de disponibilidad de los sistemas y servicios afectados.

---

## A.5 — Dos controles mitigantes

### Control 1

|                                                     |                                                                                                                                                                                                                                                                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Qué es**                                          | Aplicar parches y deshabilitar o restringir las funcionalidades vulnerables de servicios como `sendmail` y `fingerd`, especialmente el modo debug de `sendmail` que permitía ejecutar comandos de manera no autorizada.                                                                                            |
| **Propiedad de la tríada que protege**              | Principalmente **Disponibilidad** e **Integridad**.                                                                                                                                                                                                                                                                |
| **Por qué habría funcionado en este caso concreto** | Dos de los mecanismos utilizados por el Morris Worm para ingresar a otros equipos dependían directamente de vulnerabilidades presentes en `sendmail` y `fingerd`. Eliminar esas fallas habría cerrado importantes vías de propagación y reducido la cantidad de equipos que el gusano podía comprometer y saturar. |

### Control 2

|                                                     |                                                                                                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Qué es**                                          | Eliminar relaciones de confianza implícitas entre hosts (archivos `.rhosts` y `/etc/hosts.equiv`) y exigir contraseñas resistentes frente a ataques de diccionario.                                                                                                                                                                                                             |
| **Propiedad de la tríada que protege**              | **Confidencialidad**, **Integridad** y, en este incidente, especialmente **Disponibilidad**.                                                                                                                                                                                                                                                                                    |
| **Por qué habría funcionado en este caso concreto** | El gusano explotaba dos vías distintas de autenticación: `rsh` aprovechaba la confianza configurada en `.rhosts` para ejecutar comandos sin pedir clave, mientras que `rexec` utilizaba credenciales obtenidas al probar listas de palabras contra `/etc/passwd`. Restringir la confianza ciega y fortalecer las contraseñas habría neutralizado ambos vectores de propagación. |

---

## A.6 — Fuentes consultadas (Parte A)

1. United States Court of Appeals for the Second Circuit. (1991). _United States v. Morris, 928 F.2d 504 (2d Cir. 1991)._ **Fuente primaria: resolución judicial.**

2. Spafford, E. H. (1988). _The Internet Worm Program: An Analysis_ (Technical Report CSD-TR-823). Purdue University, Department of Computer Sciences. **Fuente primaria/técnica: informe técnico elaborado a partir del análisis del gusano.**

3. Lawrence Livermore National Laboratory. (s. f.). _The 1988 Morris worm, the internet's first cyberattack._ **Fuente secundaria/institucional.**

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

### Generación del manifiesto

_Terminal: Bash_

```bash
$ python3 src/integridad.py generar --dir data/muestra --salida manifest.sha256

Manifiesto generado: manifest.sha256
Directorio base:     data\muestra
Archivos indexados:  4
```

### Verificación sobre un directorio íntegro

_Terminal: Bash_

```bash
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

### Detección de la incorporación de un byte

_Terminal: Bash_

```bash
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

_Terminal: PowerShell_

```powershell
PS > python data/generar_datos.py
PS > python src/integridad.py generar --dir data/muestra --salida manifest.sha256
PS > Remove-Item data/muestra/politica_seguridad.md
PS > python src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
PS > Write-Output "código de salida: $LASTEXITCODE"

Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             3
  MODIFICADO     0
  FALTANTE       1
  NUEVO          0

Hallazgos:
  [FALTANTE] politica_seguridad.md

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
código de salida: 1

PS > python data/generar_datos.py
PS > python src/integridad.py generar --dir data/muestra --salida manifest.sha256
PS > Set-Content -Path data/muestra/nuevo.txt -Value "archivo nuevo"
PS > python src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
PS > Write-Output "código de salida: $LASTEXITCODE"

Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          1

Hallazgos:
  [NUEVO] nuevo.txt

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
código de salida: 1
```

### Efecto avalancha

_Terminal: Bash_

```bash
$ python3 src/integridad.py avalancha --a 'transferencia: $1000' --b 'transferencia: $1001'

mensaje A: "transferencia: $1000"
  SHA-256: 341511c4c817d55f30c81e212d0e82b0b16dd5a58d49fe5e45c9d5c998ab794a
mensaje B: "transferencia: $1001"
  SHA-256: 5fb87fd7adf8a226f61c666a3ed140b147501b8a1b8e1822e57fc4b3925323d9

Distancia de Hamming: 139 de 256 bits (54.30 %)
Efecto avalancha: para entradas distintas se espera un valor cercano al 50 %.
```

**Distancia obtenida:** 139 bits de 256 (54.30 %)

_¿Coincide con lo esperado? ¿Qué esperaban antes de correrlo?_

Sí, coincide con lo esperado. Antes de ejecutar la prueba esperábamos que, al cambiar un solo carácter del mensaje, aproximadamente la mitad de los 256 bits del hash SHA-256 fueran diferentes, es decir, un valor cercano al 50 % (128 bits). Se obtuvo una distancia de 139 bits (54,30 %), por lo que el resultado es razonablemente cercano a lo esperado y demuestra el efecto avalancha.

### HMAC

_Terminal: Bash_

```bash
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

```bash
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
$ echo "código de salida: $?"

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.
código de salida: 0
```

```bash
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9gr
$ echo "código de salida: $?"

mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9gr

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
código de salida: 1
```

---

## B.2 — Decisiones de implementación

| Decisión                        | Qué hicimos                                                                                                                            | Por qué                                                                                                                                |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Enlaces simbólicos              | Excluimos los enlaces simbólicos del recorrido.                                                                                        | El manifiesto representa únicamente archivos regulares contenidos en el directorio y evita seguir referencias hacia archivos externos. |
| Exclusión del manifiesto        | Comparamos las rutas resueltas del archivo recorrido y del manifiesto antes de calcular el hash.                                       | Así evitamos que el manifiesto se incluya a sí mismo o aparezca como un archivo nuevo durante la verificación.                         |
| Directorio vacío                | Se devuelven las cuatro categorías aunque todas estén vacías.                                                                          | Mantiene siempre la misma estructura de retorno y permite verificar correctamente un directorio sin archivos.                          |
| Cálculo de distancia de Hamming | Comparamos los digests byte por byte mediante XOR y contamos la cantidad de bits diferentes.                                           | La consigna requiere medir la diferencia en bits, no solamente en bytes.                                                               |
| Comparación del tag             | Utilizamos hmac.compare_digest() en lugar de == para verificar el tag recibido.                                                        | compare_digest() está diseñado para realizar una comparación resistente a diferencias de tiempo y evitar filtraciones mediante timing. |
| Verificación opcional           | Si no se proporciona un tag esperado, calculamos y devolvemos solamente el HMAC; si se proporciona, además realizamos la verificación. | Permite utilizar la misma función tanto para generar un tag como para verificar uno recibido.                                          |

---

## B.3 — Preguntas de análisis

### 1. El manifiesto por sí solo no alcanza

_Un atacante con acceso de escritura al directorio también puede escribir
`manifest.sha256`. ¿Qué le impide modificar un archivo y regenerar el
manifiesto para que todo dé `OK`? ¿Qué habría que cambiar en el esquema para
que ese ataque no funcione?_

**Respuesta:**

Un manifiesto de hashes permite detectar modificaciones solamente si podemos confiar en que el propio manifiesto no fue alterado. Si un atacante tiene permisos para modificar tanto los archivos protegidos como manifest.sha256, nada le impide cambiar un archivo y luego regenerar el manifiesto con el nuevo hash. Al verificarlo posteriormente, el digest calculado coincidiría con el valor manipulado y el sistema informaría incorrectamente que la integridad está verificada.

Para evitarlo, el manifiesto debe protegerse de forma independiente. Por ejemplo, podría almacenarse en una ubicación de solo lectura para el atacante o autenticarse mediante un HMAC manteniendo la clave secreta fuera del alcance del atacante. Otra alternativa es firmarlo digitalmente manteniendo la clave privada igualmente fuera del alcance del atacante. De esta manera, modificar y regenerar el manifiesto ya no sería suficiente, porque el atacante también tendría que producir una autenticación o firma válida.

### 2. Qué agrega HMAC y qué no

_¿Qué propiedad de seguridad aporta HMAC que un hash simple no aporta? Y la
parte importante: ¿qué **no** resuelve HMAC? Pensá en el no repudio y en
quién conoce la clave._

**Respuesta:**

Un hash simple, como SHA-256, permite detectar modificaciones en un mensaje si se dispone de un hash de referencia que no pueda ser alterado por un atacante. Sin embargo, si un atacante puede modificar tanto el mensaje como el hash almacenado, puede recalcular el hash correspondiente y la modificación podría no ser detectada.

HMAC agrega una clave secreta compartida al proceso de autenticación. Por lo tanto, un atacante que no conozca la clave no puede generar un HMAC válido para un mensaje modificado. De esta forma, HMAC proporciona integridad y autenticación del mensaje.

HMAC no proporciona no repudio, porque las partes que conocen la misma clave secreta pueden generar tags válidos. Para obtener no repudio se utilizan mecanismos como las firmas digitales, donde la clave privada pertenece exclusivamente al firmante.

### 3. MD5 y SHA-1

_Ambos siguen apareciendo en software en producción. ¿Qué propiedad
criptográfica se les rompió, exactamente? ¿Hay algún uso en el que todavía
sean aceptables, o ninguno? Fundamentá con al menos una fuente._

**Respuesta:**

La propiedad criptográfica que se considera rota en MD5 y SHA-1 es la resistencia a colisiones, es posible construir dos mensajes diferentes que produzcan el mismo valor hash. En MD5 existen ataques prácticos de colisión desde hace años, por lo que RFC 6151 indica que no debe utilizarse cuando se requiere resistencia a colisiones.

En SHA-1 también se demostraron colisiones prácticas. NIST señala que esta debilidad afecta especialmente a aplicaciones como las firmas digitales, donde la resistencia a colisiones es fundamental, y recomienda migrar a SHA-2 o SHA-3.

Esto no significa que se hayan demostrado ataques de preimagen prácticos para ambas funciones en su versión completa. En particular, el RFC 6194 (fechado en 2011) señalaba que no se conocían ataques de preimagen o segunda preimagen específicos contra SHA-1 completo; la debilidad crítica para su desuso criptográfico es la pérdida de resistencia a colisiones (como demostraron los proyectos SHAttered en 2017 y Shambles en 2020).

Todavía pueden existir usos no criptográficos o de compatibilidad heredada. Por ejemplo, el RFC 6151 considera aceptable MD5 cuando se utiliza únicamente como checksum para detectar errores accidentales de transmisión o almacenamiento, sin atribuirle ninguna garantía de seguridad. Para SHA-1, NIST estableció en 2022 la directriz formal de retirar y abandonar por completo su uso en todas las aplicaciones criptográficas federales antes del 31 de diciembre de 2030, recomendando migrar sistemáticamente a familias robustas como SHA-2 (SHA-256/512) o SHA-3.

**Fuente:**

1. RFC 6151 — Turner, S., & Chen, L. (2011). _Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms._ IETF. https://doi.org/10.17487/RFC6151
2. RFC 6194 — _Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms._ IETF. https://doi.org/10.17487/RFC6194
3. NIST — _Transitioning Away from SHA-1 for All Cryptographic Applications._ NIST CSRC Transition Announcement (2022). https://csrc.nist.gov/news/2022/transitioning-away-from-sha-1-for-all-apps

### 4. Comparación en tiempo constante

_¿Por qué comparar un tag de autenticación con `==` puede filtrar información
al atacante, y cómo lo evita `hmac.compare_digest()`? Describí el ataque
concreto que esto previene._

**Respuesta:**

El operador == no ofrece garantías de comparación en tiempo constante. Según el tipo de objeto y la implementación, su tiempo de ejecución puede depender del contenido comparado, lo que podría permitir ataques de temporización.

El ataque que esto previene es un **ataque de temporización (timing attack)** para forjar un tag de autenticación válido sin conocer la clave secreta. Si un servicio remoto verifica un HMAC usando `==`, un atacante puede enviar candidatos modificando sistemáticamente cada byte y midiendo estadísticamente los tiempos de respuesta para filtrar el ruido de red. Si existe una diferencia temporal medible asociada a la coincidencia de prefijos, el atacante puede ir deduciendo los bytes correctos uno por uno en lugar de tener que adivinar todo el tag simultáneamente.

`hmac.compare_digest()` mitiga este riesgo garantizando una comparación diseñada para evitar la evaluación en cortocircuito en función del contenido del secreto. Cabe señalar que esta protección se aplica a la comparación de contenidos, pero —como documenta la biblioteca estándar de Python— presupone que las secuencias comparadas tengan el mismo tipo y longitud conocida, dado que discrepancias en la longitud o el tipo sí pueden reflejarse en diferencias de tiempo.

**Fuente:**

1. Python Software Foundation. (s. f.). _hmac — Keyed-Hashing for Message Authentication (compare_digest)_. Python 3 Documentation. https://docs.python.org/3/library/hmac.html

### 5. SHA-256 para contraseñas: mala idea

_SHA-256 es una función de hash criptográfica sólida. ¿Por qué, entonces, es
una mala elección para almacenar contraseñas? ¿Qué se usa en su lugar y qué
propiedad tienen esas funciones que SHA-256 no tiene?_

**Respuesta:**

SHA-256 es un algoritmo seguro para verificar la integridad de archivos o firmas digitales, pero no resulta adecuado para almacenar contraseñas. El motivo principal es que fue diseñado para ser muy rápido y eficiente en hardware. Dado que los usuarios suelen elegir contraseñas de entropía limitada, un atacante que obtenga la base de datos de hashes puede aprovechar esa velocidad para **recuperar contraseñas mediante pruebas masivas de candidatos** (ataques de diccionario o fuerza bruta), calculando millones o miles de millones de hashes por segundo con placas de video (GPUs) o hardware dedicado (ASICs). Además, un hash simple no incluye intrínsecamente un valor de sal, lo que expone a los usuarios a búsquedas precalculadas mediante tablas arcoíris.

En su lugar, los estándares modernos de seguridad exigen el uso de funciones de derivación de claves basadas en contraseñas (KDF) y algoritmos específicos como **Argon2id** (RFC 9106), **bcrypt** o **scrypt**. Estas funciones poseen características diseñadas específicamente para encarecer los ataques:

1. **Costo de cómputo ajustable:** Permiten calibrar la cantidad de iteraciones o trabajo requerido, haciendo que validar un inicio de sesión legítimo tarde una fracción de segundo aceptable (por ejemplo, 100 ms), pero multiplicando drásticamente el tiempo necesario para probar millones de combinaciones en un ataque offline.
2. **Requerimiento intensivo de memoria (memory-hard):** Algoritmos como Argon2id y scrypt exigen asignar cantidades significativas de memoria RAM rápida para cada cálculo. Esto encarece considerablemente la paralelización masiva en GPUs y ASICs, cuyos núcleos disponen de memoria local limitada por hilo.
3. **Uso de sal (salt) único:** Siguiendo especificaciones como el RFC 9106, se suministra una sal criptográficamente aleatoria y única para cada contraseña. Esto garantiza que dos usuarios con la misma clave generen hashes distintos, anulando la eficacia de tablas precalculadas y forzando a probar los candidatos contra cada usuario de manera individual.

**Fuente:**

1. RFC 9106 — Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021). _Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications._ IETF. https://doi.org/10.17487/RFC9106
2. Biryukov, A., Dinu, D., & Khovratovich, D. (2016). _Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications_. In 2016 IEEE European Symposium on Security and Privacy (EuroS&P) (pp. 292-302). IEEE. https://doi.org/10.1109/EuroSP.2016.31

---

# Cierre

## Dificultades encontradas

- **Cálculo de la distancia de Hamming en bits:** Al principio intentamos comparar directamente las cadenas devueltas por `hexdigest()`, pero al probar con valores simples nos dimos cuenta de que estábamos midiendo caracteres hexadecimales distintos y no la diferencia en bits reales. Tuvimos que rehacer la función utilizando los bytes crudos devueltos por `digest()`, aplicando la operación XOR entre bytes y contando los bits en 1 con `.bit_count()`.
- **Manejo de rutas relativas y compatibilidad con Windows:** Al desarrollar sobre Windows, las rutas generadas por defecto incluían barras invertidas (`\`). Tuvimos que asegurarnos de utilizar `Path.relative_to()` junto con `.as_posix()` para que el manifiesto JSON mantuviera el formato con barras inclinadas (`/`), garantizando que pueda verificarse en Linux sin arrojar diferencias espurias.
- **Exclusión del manifiesto en la verificación:** En la primera versión de `verificar_manifiesto`, el archivo `manifest.sha256` se reportaba como un archivo `NUEVO` cada vez que se ejecutaba la verificación si se guardaba dentro del directorio evaluado. Lo resolvimos comparando las rutas normalizadas con `.resolve()` antes de agregar los archivos a la lista a verificar.

---

## Distribución del trabajo

| Integrante                          | Aportes                                                                                                                                                                                                                       |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Alejo De Miguel (@AlejoDM)          | Parte A, apertura: Investigación histórica del Morris Worm, redacción de A.1 (Cronología verificada) y A.2 (Activo afectado y justificación).                                                                                 |
| María Belén Benito (@belubenito603) | Parte A, cierre: Matriz CIA (A.3), Encadenamiento amenaza→vulnerabilidad→activo→impacto (A.4), Controles mitigantes específicos (A.5) y Fuentes A.6.                                                                          |
| Tomás Giudici (@TomasGiudici)       | Parte B, manifiesto: Implementación de `generar_manifiesto` y `verificar_manifiesto` en `src/integridad.py`, captura de evidencias obligatorias (manifiesto, verificación, prueba de 1 byte), decisiones de B.2 y Pregunta 1. |
| Carolina Suppo (@carosuppo)         | Parte B, criptografía: Implementación de `distancia_hamming_bits` y `calcular_mac` en `src/integridad.py`, captura de evidencias (avalancha y HMAC), decisiones de B.2 y Preguntas de análisis 2, 3 y 4.                      |
| Martín Beccereca (@martinbeccereca) | Mini-research (Tema 3: Disponibilidad y Ransomware), Pregunta de análisis 5 (SHA-256 vs KDFs para contraseñas), armado de `INTEGRANTES.md`, coordinación y cierre del informe, verificación contra rúbrica.                   |

---

## Declaración de uso de asistentes de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí

| Herramienta                                                     | Para qué se usó                                                               | Qué partes del entregable afectó                                                                                                                                        | Cómo se verificó que lo devuelto era correcto                                                                                                                              |
| --------------------------------------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Gemini 3.7 Flash / Gemini Deep Research / Claude Code / ChatGPT | Redacción, estructuración y revisión crítica de estilo y precisión conceptual | Parte A (A.1 cronología, A.2 activo, A.3 matriz CIA, A.4 encadenamiento, A.5 controles), Parte B (B.1 evidencias, B.2 decisiones, B.3.1 a B.3.5), Mini-research, cierre | Se contrastaron las observaciones con las fuentes accesibles (resolución judicial, Spafford, guías NIST) y se verificó el código y cálculos ejecutando las pruebas reales. |

**Declaración:**

El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del análisis,
independientemente de la asistencia recibida.

---

## Fuentes consultadas (general)

1. United States v. Morris, 928 F.2d 504 (2d Cir. 1991).
   https://law.resource.org/pub/us/case/reporter/F2/928/928.F2d.504.90-1336.774.html
2. Spafford, E. H. (1988). _The Internet Worm Program: An Analysis_ (Technical Report CSD-TR-823). Purdue University.
   https://www.cerias.purdue.edu/techreports-ssl/public/823.pdf
3. Carnegie Mellon University, Software Engineering Institute. (s.f.). _History of Innovation_.
   https://www.sei.cmu.edu/history-of-innovation/
4. Lawrence Livermore National Laboratory. (s.f.). _The 1988 Morris worm, the internet's first cyberattack_.
   https://st.llnl.gov/news/look-back/1988-morris-worm-internets-first-cyberattack
5. Cybersecurity and Infrastructure Security Agency, & Federal Bureau of Investigation. (2023). _#StopRansomware Guide_. CISA.
   https://www.cisa.gov/sites/default/files/2023-05/StopRansomware_Guide_508c%20(1).pdf
6. National Institute of Standards and Technology. (2010). _Contingency Planning Guide for Federal Information Systems_ (NIST Special Publication 800-34, Rev. 1). U.S. Department of Commerce.
   https://doi.org/10.6028/NIST.SP.800-34r1
7. Hernandez-Castro, J., Cartwright, A., & Cartwright, E. (2020). An economic analysis of ransomware and its welfare consequences. _Royal Society Open Science_, 7(3), 190023.
   https://doi.org/10.1098/rsos.190023
8. Samonas, S., & Coss, D. (2014). The CIA strikes back: Redefining confidentiality, integrity and availability in security. _Journal of Information System Security_, 10(3), 21-45.
   https://www.researchgate.net/publication/317011931_The_CIA_strikes_back_Redefining_confidentiality_integrity_and_availability_in_security
9. Biryukov, A., Dinu, D., & Khovratovich, D. (2016). _Argon2: New Generation of Memory-Hard Functions for Password Hashing and Other Applications_. In 2016 IEEE European Symposium on Security and Privacy (EuroS&P) (pp. 292-302). IEEE.
   https://doi.org/10.1109/EuroSP.2016.31
10. Turner, S., & Chen, L. (2011). _Updated Security Considerations for the MD5 Message-Digest and the HMAC-MD5 Algorithms_ (RFC 6151). IETF.
    https://doi.org/10.17487/RFC6151
11. Polk, T., Chen, L., Turner, S., & Hoffman, P. (2011). _Security Considerations for the SHA-0 and SHA-1 Message-Digest Algorithms_ (RFC 6194). IETF.
    https://doi.org/10.17487/RFC6194
12. Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021). _Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications_ (RFC 9106). IETF.
    https://doi.org/10.17487/RFC9106
13. Python Software Foundation. (s. f.). _hmac — Keyed-Hashing for Message Authentication (Python 3 Documentation)_.
    https://docs.python.org/3/library/hmac.html
14. National Institute of Standards and Technology. (2022). _Transitioning Away from SHA-1 for All Cryptographic Applications_. NIST CSRC.
    https://csrc.nist.gov/news/2022/transitioning-away-from-sha-1-for-all-apps
