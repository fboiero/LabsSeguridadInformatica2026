# Laboratorio 01 — Informe

## Identificación

|                             |                                                                   |
| --------------------------- | ----------------------------------------------------------------- |
| **Grupo**                   | 10                                                                |
| **Caso asignado (Parte A)** | Equifax (2017)                                                    |
| **Tema del mini-research**  | 2 — La cadena de suministro de software como superficie de ataque |
| **Fecha de entrega**        | Completar por el grupo                                            |

### Integrantes

| Nombre y apellido      | Legajo | Usuario de GitHub |
| ---------------------- | ------ | ----------------- |
| Belén Rocío Ramello    | 15226  | @belramello       |
| Carolina Paula Corazza | 15239  | @carocor1         |
| Chiara Agustina Kordek | 14719  | @chiarakordek     |
| Juan Pablo Saby        | 15026  | @JuanSaby         |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha      | Hecho                                                                                                                | Fuente                                        |
| ---------- | -------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| 2017-03-07 | Apache publicó una actualización de seguridad para CVE-2017-5638 en Apache Struts.                                   | [1] Apache Software Foundation, aviso S2-045. |
| 2017-03-15 | US-CERT emitió una alerta sobre la vulnerabilidad de Apache Struts y recomendó actualizar las versiones afectadas.   | [2] CISA/US-CERT, TA17-074A.                  |
| 2017-05-13 | El informe del Congreso sitúa en esta fecha el comienzo de la actividad de intrusión vinculada con la brecha.        | [3] U.S. House of Representatives (2018).     |
| 2017-07-29 | Equifax detectó actividad sospechosa e inició una investigación.                                                     | [3] U.S. House of Representatives (2018).     |
| 2017-07-30 | Equifax desconectó la aplicación web afectada durante la respuesta al incidente.                                     | [3] U.S. House of Representatives (2018).     |
| 2017-08-02 | Equifax notificó a autoridades mientras continuaba investigando el incidente.                                        | [3] U.S. House of Representatives (2018).     |
| 2017-09-07 | Equifax anunció públicamente una brecha que afectó información personal de aproximadamente 147 millones de personas. | [4] Equifax (2017); [5] FTC (2019).           |

## A.2 — Activo afectado

**Activo principal:** Información personal identificable de consumidores estadounidenses almacenada en sistemas de Equifax: nombres, fechas de nacimiento, direcciones y números de Seguro Social [3, 4].

**Por qué es el principal:** La combinación de identificadores personales es difícil de cambiar y puede facilitar fraude y robo de identidad durante un período prolongado. Es el activo prioritario porque la exposición afectó directamente a consumidores y fue el impacto central comunicado por Equifax [4].

**Otros activos afectados:** Números de tarjetas de crédito de aproximadamente 209.000 consumidores y documentos de disputas de crédito de aproximadamente 182.000 personas, según el anuncio de Equifax [4]. Estas categorías son subconjuntos y no deben sumarse sin revisar posibles solapamientos.

## A.3 — Matriz CIA

| Propiedad        | ¿Se violó?    | Evidencia concreta                                                                                                                                                                                                     |
| ---------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Confidencialidad | Sí            | Equifax informó acceso no autorizado y exposición de información personal de aproximadamente 147 millones de personas [4].                                                                                             |
| Integridad       | No demostrado | Las fuentes citadas documentan acceso y extracción de información, pero no identifican qué registro de consumidores habría sido alterado. Con la evidencia citada no se afirma una violación de integridad.            |
| Disponibilidad   | Parcial       | El informe del Congreso describe que Equifax desconectó la aplicación web de disputas durante la respuesta [3]. Esto afectó ese servicio, pero no demuestra que todos los servicios de Equifax quedaran indisponibles. |

**Justificación ampliada de la propiedad más discutible:** La disponibilidad es la más discutible porque hay que distinguir la desconexión de una aplicación específica de una indisponibilidad general. El informe del Congreso describe la desconexión de la aplicación web de disputas durante la respuesta [3], por lo que la interrupción se clasifica como parcial y acotada a ese servicio. La extracción no demuestra por sí sola indisponibilidad de bases de datos ni de todos los servicios. La integridad se deja como “no demostrado” porque las fuentes citadas no especifican datos alterados.

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

| Elemento                             | En este caso                                                                                                                                                                             |
| ------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Amenaza (quién/qué y motivación)     | Actor externo no identificado aquí con atribución específica; las fuentes citadas no bastan para afirmar motivación.                                                                     |
| Vulnerabilidad (debilidad explotada) | CVE-2017-5638 en Apache Struts: manejo inseguro de la cabecera `Content-Type` en el analizador multipart, que podía permitir ejecución remota de código en versiones vulnerables [1, 2]. |
| Activo                               | Información personal identificable de consumidores almacenada en sistemas de Equifax [3, 4].                                                                                             |
| Impacto                              | Exposición de datos personales a gran escala, con riesgo de fraude y robo de identidad para las personas afectadas [4, 5].                                                               |

**Redacción:** Un actor externo (amenaza) envió solicitudes construidas para activar el manejo vulnerable de `Content-Type` en Apache Struts (exploit), aprovechando CVE-2017-5638 (vulnerabilidad). El acceso alcanzó sistemas de Equifax que almacenaban información personal de consumidores (activo), cuya exposición afectó la confidencialidad y generó riesgos de fraude y robo de identidad (impacto) [1–5]. Las fuentes citadas no permiten atribuir aquí el ataque a un grupo concreto ni asegurar una motivación específica.

## A.5 — Dos controles mitigantes

### Control 1

| Campo                                           | Desarrollo                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Qué es                                          | Gestión de vulnerabilidades con inventario de componentes expuestos, plazos de remediación para vulnerabilidades críticas y comprobación técnica de que el parche de Apache Struts fue instalado.                                                                                                                                     |
| Propiedad de la tríada que protege              | Confidencialidad (y reduce la oportunidad de comprometer integridad o disponibilidad).                                                                                                                                                                                                                                                |
| Por qué habría funcionado en este caso concreto | Apache publicó una actualización para CVE-2017-5638 el 7 de marzo de 2017 y US-CERT emitió una alerta el 15 de marzo [1, 2]. Un proceso que identificara la instancia expuesta y verificara la actualización habría reducido la posibilidad de explotar ese vector; no garantiza prevenir otros accesos ni sustituye la segmentación. |

### Control 2

| Campo                                           | Desarrollo                                                                                                                                                                                                                                                    |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Qué es                                          | Segmentación entre la aplicación web expuesta y los repositorios de información de consumidores, con reglas de mínimo privilegio y límites de consultas/egreso.                                                                                               |
| Propiedad de la tríada que protege              | Confidencialidad.                                                                                                                                                                                                                                             |
| Por qué habría funcionado en este caso concreto | Si la aplicación hubiera sido comprometida, limitar sus conexiones a los datos estrictamente necesarios habría dificultado el acceso y la extracción masiva. Es una mitigación que reduce alcance, no una garantía de que ningún dato pudiera ser consultado. |

## A.6 — Fuentes consultadas (Parte A)

Las referencias primarias consultadas y asociadas a las afirmaciones de A.1–A.5 se listan abajo.

1. [PRIMARIA] Apache Software Foundation. (2017, March 7). _S2-045: Possible Remote Code Execution when using the Jakarta Multipart parser_. https://struts.apache.org/security/s2-045
2. [PRIMARIA] CISA/US-CERT. (2017, March 15). _TA17-074A: Apache Struts Vulnerability_. https://www.cisa.gov/news-events/alerts/2017/03/15/apache-struts-vulnerability
3. [PRIMARIA] U.S. House of Representatives, Committee on Oversight and Government Reform. (2018, March 6). _The Equifax Data Breach: Preventable Failure and Lessons Learned_. https://oversight.house.gov/sites/democrats.oversight.house.gov/files/documents/20180306-Equifax-Report.pdf
4. [PRIMARIA] Equifax Inc. (2017, September 7). _Equifax Announces Cybersecurity Incident Involving Consumer Information_. https://investor.equifax.com/news-and-events/news/2017/Equifax-Announces-Cybersecurity-Incident-Involving-Consumer-Information/default.aspx
5. [PRIMARIA] Federal Trade Commission. (2019, July 22). _FTC Sues Equifax for Data Breach that Exposed 147 Million People_. https://www.ftc.gov/news-events/news/press-releases/2019/07/ftc-sues-equifax-data-breach-exposed-147-million-people

---

# PARTE B — Integridad con funciones de hash

## B.1 — Evidencia de ejecución

> Evidencia copiada de las ejecuciones de Carolina en PowerShell, desde `entregas/lab01/grupo10/`.

### Generación del manifiesto

```text
$ python src/integridad.py generar --dir data/muestra --salida manifest.sha256
Manifiesto generado: manifest.sha256
Directorio base:     data\muestra
Archivos indexados:  4
```

### Verificación sobre un directorio íntegro

```text
$ python src/integridad.py verificar --dir data/muestra --manifiesto manifest.sha256
Directorio:  data\muestra
Manifiesto:  manifest.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          0

INTEGRIDAD VERIFICADA — sin diferencias contra el manifiesto.
Código de salida: 0
```

### Detección de modificación de un byte

```text
$ python src/integridad.py generar --dir data/prueba-modificado --salida manifiesto-modificado.sha256
Manifiesto generado: manifiesto-modificado.sha256
Directorio base:     data\prueba-modificado
Archivos indexados:  4
$ Add-Content data/prueba-modificado/transferencia.txt "X" -NoNewline
$ python src/integridad.py verificar --dir data/prueba-modificado --manifiesto manifiesto-modificado.sha256
Directorio:  data\prueba-modificado
Manifiesto:  manifiesto-modificado.sha256

  OK             3
  MODIFICADO     1
  FALTANTE       0
  NUEVO          0

Hallazgos:
  [MODIFICADO] transferencia.txt

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
Código de salida: 1

La prueba se realizó sobre la copia `data/prueba-modificado`; `data/muestra` quedó intacta.
```

### Detección de archivo faltante

```text
$ python src/integridad.py generar --dir data/prueba-faltante --salida manifiesto-faltante.sha256
Manifiesto generado: manifiesto-faltante.sha256
Directorio base:     data\prueba-faltante
Archivos indexados:  4
$ Remove-Item data/prueba-faltante/politica_seguridad.md
$ python src/integridad.py verificar --dir data/prueba-faltante --manifiesto manifiesto-faltante.sha256
Directorio:  data\prueba-faltante
Manifiesto:  manifiesto-faltante.sha256

  OK             3
  MODIFICADO     0
  FALTANTE       1
  NUEVO          0

Hallazgos:
  [FALTANTE] politica_seguridad.md

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
Código de salida: 1

La prueba se realizó sobre la copia `data/prueba-faltante`; `data/muestra` quedó intacta.
```

### Detección de archivo nuevo

```text
$ python src/integridad.py generar --dir data/prueba-nuevo --salida manifiesto-prueba.sha256
Manifiesto generado: manifiesto-prueba.sha256
Directorio base:     data\prueba-nuevo
Archivos indexados:  4
$ Set-Content data/prueba-nuevo/nuevo_archivo.txt "archivo agregado para la prueba"
$ python src/integridad.py verificar --dir data/prueba-nuevo --manifiesto manifiesto-prueba.sha256
Directorio:  data\prueba-nuevo
Manifiesto:  manifiesto-prueba.sha256

  OK             4
  MODIFICADO     0
  FALTANTE       0
  NUEVO          1

Hallazgos:
  [NUEVO] nuevo_archivo.txt

INTEGRIDAD COMPROMETIDA — 1 hallazgo(s).
Código de salida: 1

La prueba se realizó sobre la copia `data/prueba-nuevo`; `data/muestra` quedó intacta.
```

### Efecto avalancha

```text
$ python src/integridad.py avalancha --a "transferencia: `$1000" --b "transferencia: `$1001"
mensaje A: "transferencia: $1000"
  SHA-256: 341511c4c817d55f30c81e212d0e82b0b16dd5a58d49fe5e45c9d5c998ab794a
mensaje B: "transferencia: $1001"
  SHA-256: 5fb87fd7adf8a226f61c666a3ed140b147501b8a1b8e1822e57fc4b3925323d9

Distancia de Hamming: 139 de 256 bits (54.30 %)
Efecto avalancha: para entradas distintas se espera un valor cercano al 50 %.
Código de salida: 0
```

**Distancia obtenida:** 139 bits de 256 (54.30 %). Coincide con lo esperado para el efecto avalancha: aproximadamente la mitad de los bits cambia entre digests de entradas distintas. Antes de ejecutarlo, se esperaba un valor cercano al 50 %, no necesariamente 128 bits exactos en una sola comparación.

### HMAC

```text
$ python src/integridad.py mac --clave secreto --mensaje "transferir 1000"
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
$ python src/integridad.py mac --clave secreto --mensaje "transferir 1000" --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.
Código de salida: 0
$ python src/integridad.py mac --clave secreto --mensaje "transferir 1000" --verificar 0000000000000000000000000000000000000000000000000000000000000000
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 0000000000000000000000000000000000000000000000000000000000000000

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
Código de salida: 1
```

## B.2 — Decisiones de implementación

El recorrido incluye recursivamente los archivos regulares; los directorios no se guardan como entradas porque no se hashean. Probé una carpeta con un archivo de cero bytes: se incluyó en el manifiesto con el digest SHA-256 conocido para una entrada vacía y se verificó como `OK`. También probé un directorio sin archivos: generó `{}` y la verificación dejó las cuatro categorías en cero, con código de salida 0. Los enlaces simbólicos no tienen manejo especial implementado ni probado.

| Decisión                | Qué hicimos                                                                                                          | Por qué                                                                            |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Excluir el manifiesto   | Se excluye comparando su ruta resuelta con las rutas recorridas.                                                     | Evita autorreferencia cuando la salida está dentro del directorio.                 |
| Recorrido y rutas       | Se recorren archivos regulares recursivamente y se representan claves con `/`.                                       | Permite subdirectorios y portabilidad del manifiesto.                              |
| Archivos vacíos         | Probé `archivo-vacio.txt` (cero bytes): se indexó y se verificó como `OK`; su digest fue `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. | Los archivos regulares se hashean aunque su contenido esté vacío; el digest identifica esos cero bytes. |
| Directorio base vacío   | Probé un directorio sin archivos: `generar` produjo `{}` y `verificar` informó cero archivos en las cuatro categorías, con código de salida 0. | Solo se registran archivos regulares; no se hashean los directorios. |
| Escenarios destructivos | Las pruebas de modificación, faltante y archivo nuevo se realizaron sobre copias temporales del conjunto de muestra. | Evita alterar los datos de muestra originales y la contaminación entre escenarios. |

## B.3 — Preguntas de análisis

Las respuestas fundamentan el análisis con referencias técnicas y distinguen las garantías criptográficas de sus límites de implementación y operación.

### 1. El manifiesto por sí solo no alcanza

Un hash permite detectar cambios solo si el valor de referencia permanece confiable. Si un atacante puede escribir tanto en los archivos como en `manifest.sha256`, puede modificar un archivo y recalcular su digest: el verificador comparará contra una referencia que el mismo atacante sustituyó y mostrará `OK`. SHA-256 produce un resumen determinista del contenido, pero no autentica quién generó el manifiesto ni dónde se guardó [1]. Por eso, guardar el manifiesto junto a los archivos protegidos permite comparar estados, pero no constituye por sí solo una raíz de confianza.

Para impedirlo, hay que proteger la referencia mediante un límite de confianza separado del directorio vigilado. Una opción es firmar digitalmente el manifiesto: el verificador valida la firma con una clave pública confiable y la clave privada se mantiene fuera del alcance del proceso comprometible. Otra opción es guardar una copia inmutable o de solo lectura en un servicio externo con control de acceso y registro de cambios. HMAC también puede autenticar el manifiesto si emisor y verificador comparten un secreto protegido; si el atacante obtiene ese secreto, puede generar tags válidos [2]. La elección depende del modelo de amenazas y de cómo se protejan las claves y la referencia.

La solución no es únicamente cambiar SHA-256 por otro hash: cualquier hash público se puede recalcular. Hay que impedir que quien modifica los archivos pueda reemplazar también la referencia confiable. Una firma digital facilita la verificación por terceros sin compartir la clave privada; HMAC es más simple cuando un grupo cerrado comparte un secreto, pero cualquier poseedor de ese secreto puede crear tags. En ambos casos, la seguridad depende de la custodia de claves y del almacenamiento separado de la referencia [1, 2].

### 2. Qué agrega HMAC y qué no

Un hash simple es público: cualquier persona que cambie un mensaje también puede calcular su nuevo SHA-256, así que el digest no demuestra quién lo generó. HMAC combina una clave secreta con una función hash mediante un procedimiento estandarizado; quien no conoce la clave no debería poder producir un tag válido. El receptor que posee la misma clave recalcula el tag y lo compara con el recibido, lo que permite detectar modificaciones y autenticar el mensaje respecto del conjunto de participantes que conocen el secreto [2, 3]. En esta implementación se usa HMAC-SHA256 y la verificación se realiza con `hmac.compare_digest()`.

La autenticación es respecto del grupo que conoce la clave, no necesariamente de una persona individual. Si varios servicios comparten la misma clave, un tag válido demuestra que probablemente lo generó alguien con acceso a ella, pero no cuál participante. La protección de la clave, su distribución y la separación de permisos son entonces parte del diseño de seguridad; el MAC no resuelve por sí mismo esos problemas [2].

HMAC no cifra el contenido y, por lo tanto, no aporta confidencialidad. Tampoco proporciona no repudio: como emisor y receptor comparten la clave, cualquiera de ellos pudo generar el tag y un tercero no puede atribuirlo exclusivamente a uno. Si la clave se filtra, quien la obtiene también puede crear tags aceptables. En consecuencia, HMAC resuelve autenticidad simétrica e integridad solo bajo el supuesto de que el secreto está protegido; no resuelve identidad individual, distribución segura de claves ni seguridad de los dispositivos que las usan [2, 3].

### 3. MD5 y SHA-1

La propiedad criptográfica central debilitada en ambos algoritmos es la **resistencia a colisiones**: no se puede confiar en que sea inviable construir dos entradas distintas con el mismo digest para los usos que requieren resistencia frente a un adversario. En 2017, el trabajo SHAttered demostró una colisión práctica de SHA-1 usando dos archivos PDF distintos [6]. Para MD5 también existen colisiones prácticas. Esto no equivale a invertir el hash ni a recuperar cualquier entrada original: la resistencia a preimagen es una propiedad distinta de la resistencia a colisiones [4, 6].

La diferencia importa para interpretar el riesgo: una colisión significa que existen dos mensajes distintos con el mismo digest; no permite, en general, tomar un digest arbitrario y hallar su mensaje original. Los ataques de colisión son especialmente preocupantes cuando una aplicación permite que un atacante prepare ambos documentos y luego confía en que sus hashes sean distintos. El resultado de SHAttered convirtió esa preocupación para SHA-1 en una demostración práctica, no solo teórica [6].

Por eso MD5 y SHA-1 no son adecuados para firmas, certificados ni protocolos donde un atacante pueda elegir entradas y aprovechar colisiones. Un checksum heredado aún puede detectar errores accidentales en un contexto sin adversario, pero no autentica el archivo: quien sustituye el archivo también podría sustituir el checksum. Para descargas expuestas a manipulación se debe usar un algoritmo vigente y autenticar el valor esperado mediante una firma o un canal confiable. La aceptabilidad depende del objetivo y del estándar aplicable, no de que el algoritmo siga apareciendo en sistemas antiguos [4, 6].

**Fuentes:** Stevens, M., Bursztein, E., Karpman, P., Albertini, A., & Markov, Y. (2017). _The first collision for full SHA-1_. https://shattered.io/static/shattered.pdf [6]. NIST. (2019). _SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths_. https://doi.org/10.6028/NIST.SP.800-131Ar2 [4].

### 4. Comparación en tiempo constante

Una comparación ordinaria de cadenas puede detenerse en el primer byte distinto. Si un servidor acepta tags enviados por un usuario y revela tiempos suficientemente medibles, un atacante con muchas consultas puede probar candidatos y comparar sus duraciones: un prefijo correcto podría tardar algo más porque la rutina continúa comparando. Repitiendo el proceso y extendiendo el prefijo, intentaría reconstruir el tag byte por byte. El ataque depende de que exista un oráculo de verificación, se permitan suficientes intentos y la señal temporal supere el ruido de red y del sistema; no es una consecuencia automática de usar `==` en cualquier programa [3].

En una verificación de HMAC, conocer un prefijo correcto reduce el espacio de candidatos para el byte siguiente, y una diferencia de tiempo repetible puede convertirse en una señal para adivinarlo. `hmac.compare_digest()` evita que el tiempo dependa del contenido coincidente, mitigando ese canal lateral de comparación [3]. La aplicación igual debe controlar cuántas consultas acepta y evitar diferencias observables en las respuestas, ya que la función no protege otros tramos del procesamiento.

`hmac.compare_digest()` está diseñada para evitar que el tiempo de comparación dependa de cuántos bytes iniciales coinciden, por lo que es la primitiva apropiada para comparar tags en lugar de una comparación ordinaria [3]. No vuelve automáticamente constante todo el endpoint: diferencias de longitud, validaciones previas, mensajes de error y otras ramas pueden filtrar información. Conviene acompañarla de respuestas externas uniformes, límites de intentos y protección de la clave. La mitigación se dirige al canal lateral de comparación, no a todos los posibles canales laterales de la aplicación.

### 5. SHA-256 para contraseñas: mala idea

SHA-256 es adecuado para resumir datos y verificar integridad, pero su cálculo es deliberadamente rápido [1]. Si se filtra una base que guarda el hash directo de cada contraseña, el atacante puede probar candidatos fuera de línea a gran velocidad y comparar resultados con los hashes robados. El paralelismo de GPU y hardware especializado abarata aún más cada intento. Un salt único por contraseña evita que usuarios con la misma contraseña tengan el mismo hash y dificulta reutilizar tablas precalculadas, pero no encarece por sí solo cada conjetura [5].

El salt no necesita ser secreto: se almacena junto con el resultado y hace que cada contraseña tenga un cálculo independiente. Su función es evitar que una misma contraseña produzca el mismo valor en distintas cuentas y frustrar tablas precalculadas reutilizables; el costo de probar una contraseña candidata sigue siendo bajo si solo se aplica SHA-256 una vez [5]. Por eso, agregar salt a un hash rápido mejora una parte del problema, pero no sustituye una función de derivación de contraseñas.

Para almacenar contraseñas se usan funciones de derivación dedicadas, como Argon2id, scrypt, bcrypt o PBKDF2, con salt único y parámetros de costo adecuados. A diferencia de SHA-256, están pensadas para que cada intento sea configurablemente más caro; Argon2id y scrypt también permiten exigir memoria, lo que dificulta escalar ataques masivos con hardware paralelo. NIST recomienda emplear una función de derivación apropiada con salt y factor de costo [5]. Esto no vuelve invulnerables las contraseñas débiles: hay que elegir parámetros adecuados, actualizarlos y proteger cualquier secreto adicional utilizado [5].

---

# Cierre

## Dificultades encontradas

Durante la implementación hubo que distinguir la ruta base de los archivos de muestra y la ruta del manifiesto, y usar copias temporales en las pruebas de modificación, faltante y archivo nuevo. También se comprobó que una modificación de un byte cambia el estado y el código de salida. La validación asistida detectó que la terminal Windows requería salida UTF-8 para el autoevaluador.

## Distribución del trabajo

Distribución de aportes del grupo, basada en el trabajo realizado:

| Integrante             | Aportes realizados                                                               |
| ---------------------- | -------------------------------------------------------------------------------- |
| Belén Rocío Ramello    | Parte A |
| Carolina Paula Corazza | Implementación inicial de Parte B y pruebas locales.                             |
| Chiara Agustina Kordek | Revisión y pruebas |
| Juan Pablo Saby        | Mini-research |

## Declaración de uso de asistentes de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí. Entre las herramientas utilizadas se encuentra OpenCode, que brindó apoyo para la implementación y revisión.

| Herramienta                | Para qué se usó                                                                                     | Qué partes del entregable afectó                                                         | Cómo se verificó                                                                                  |
| -------------------------- | --------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| OpenCode / asistente de IA | Apoyo para implementar Parte B y preparar un plan de contribuciones entre los integrantes del grupo | Código de `src/integridad.py` y propuestas de revisión para `informe.md` y `research.md` | Autoevaluador del curso y pruebas adicionales locales llevadas a cabo por los propios integrantes |

**Declaración:** El grupo declara el uso de asistencia de IA indicado arriba. Cada integrante es responsable de comprender y respaldar sus propios aportes.

## Fuentes consultadas (general)

Referencias técnicas citadas en las respuestas de B.3:

1. [PRIMARIA] NIST. (2015). _FIPS PUB 180-4: Secure Hash Standard (SHS)._ https://doi.org/10.6028/NIST.FIPS.180-4
2. [PRIMARIA] Krawczyk, H., Bellare, M., & Canetti, R. (1997). _HMAC: Keyed-Hashing for Message Authentication_ (RFC 2104). IETF. https://www.rfc-editor.org/rfc/rfc2104
3. [PRIMARIA] Python Software Foundation. (s. f.). _hmac — Keyed-Hashing for Message Authentication_. https://docs.python.org/3/library/hmac.html
4. [PRIMARIA] NIST. (2019). _SP 800-131A Rev. 2: Transitioning the Use of Cryptographic Algorithms and Key Lengths_. https://doi.org/10.6028/NIST.SP.800-131Ar2
5. [PRIMARIA] NIST. (2025). _SP 800-63B-4: Digital Identity Guidelines — Authentication and Authenticator Management_. https://doi.org/10.6028/NIST.SP.800-63B-4
6. [PRIMARIA] Stevens, M., Bursztein, E., Karpman, P., Albertini, A., & Markov, Y. (2017). _The first collision for full SHA-1_. https://shattered.io/static/shattered.pdf
