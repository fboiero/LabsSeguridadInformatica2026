# Laboratorio 01 — Informe

## Identificación

| | |
|---|---|
| **Grupo** | 05 |
| **Caso asignado (Parte A)** | SolarWinds / SUNBURST (2020) — asignado por `5 mod 6 = 5` sobre la tabla del enunciado |
| **Tema del mini-research** | Tema 2 — La cadena de suministro de software como superficie de ataque |
| **Fecha de entrega** | 2026-09-08 |

### Integrantes

*Esta tabla también va en `INTEGRANTES.md`. Solo nombre, legajo y usuario de
GitHub. Nada de DNI, teléfono ni dirección: el repositorio es público.*

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Magni, Gastón | 14991 | @nosungam |
| Mosconi, Ignacio | 15288 | @ignamosconi |
| Presuttari, Matías | 14959 | @matiaspresuttari |
| Terreno, Valentino | 15079 | @vterreno |

---

# PARTE A — Análisis del incidente bajo la lente CIA

## A.1 — Cronología

| Fecha | Hecho | Fuente |
|---|---|---|
| Desde marzo de 2020 | SolarWinds distribuye versiones troyanizadas de Orion Platform (2019.4 HF5 a 2020.2 HF1): el backdoor SUNBURST fue insertado en el binario `SolarWinds.Orion.Core.BusinessLayer.dll` y firmado con el certificado legítimo de code-signing de la empresa. | CISA (2020/2021), Advisory AA20-352A |
| 13 de diciembre de 2020 | FireEye (hoy Mandiant) publica el hallazgo de la intrusión —detectada primero en su propia red— y bautiza el backdoor como SUNBURST. | FireEye/Mandiant (2020) |
| 13 de diciembre de 2020 | CISA emite la Directiva de Emergencia 21-01, ordenando a las agencias federales desconectar de inmediato las versiones comprometidas de Orion. | CISA, ED 21-01 (2020) |
| 16 de diciembre de 2020 | Se confirma que intrusos monitorearon cuentas de correo interno de los Departamentos del Tesoro y de Comercio (NTIA) de EE. UU., además de otros organismos (Estado, Energía/NNSA, Seguridad Nacional, Salud). | Mak, Slate (2020) |
| 15 de abril de 2021 | El gobierno de EE. UU. atribuye formalmente la campaña al Servicio de Inteligencia Exterior de Rusia (SVR). | CISA, AA20-352A (act. 2021) |

---

## A.2 — Activo afectado

**Activo principal:** la integridad del *pipeline* de compilación y firma de
código de SolarWinds Orion Platform — concretamente, la garantía de que el
binario `SolarWinds.Orion.Core.BusinessLayer.dll`, firmado con el certificado
de code-signing legítimo de la empresa, era exactamente el código que
SolarWinds había compilado y no contenía nada agregado sin autorización.

**Por qué es el principal:** es el activo cuyo compromiso funcionó como
vector único hacia todos los demás. Los atacantes no vulneraron a cada
víctima una por una: comprometieron la fábrica de software que ~18.000
organizaciones actualizaban de forma rutinaria y confiada, y esas
organizaciones instalaron el backdoor voluntariamente, creyendo que era una
actualización legítima firmada por su proveedor.

**Otros activos afectados** (secundarios, alcanzados *a través* del backdoor
una vez desplegado): las redes internas y cuentas de correo de organismos del
gobierno de EE. UU. —entre ellos los Departamentos del Tesoro y de Comercio
(NTIA), Estado, Energía/NNSA, Seguridad Nacional y Salud— y, en el caso de
FireEye, su propio conjunto interno de herramientas de Red Team.

---

## A.3 — Matriz CIA

| Propiedad | ¿Se violó? | Evidencia concreta |
|---|---|---|
| **Confidencialidad** | Sí | Se confirmó el monitoreo de cuentas de correo interno de los Departamentos del Tesoro y de Comercio (NTIA), y FireEye reportó la sustracción de sus herramientas de Red Team (Mak, Slate, 2020; FireEye/Mandiant, 2020). |
| **Integridad** | Sí | El dato alterado es identificable con precisión: el binario `SolarWinds.Orion.Core.BusinessLayer.dll` fue modificado para incluir el backdoor SUNBURST antes de ser firmado con el certificado legítimo de SolarWinds (CISA, AA20-352A, 2020/2021). Esta es, de hecho, la violación fundacional del incidente: sin ella no hay acceso a ningún otro activo. |
| **Disponibilidad** | No | El objetivo de la campaña fue la persistencia sigilosa a largo plazo (el backdoor operó sin ser detectado durante meses), no la interrupción de servicio. El propio mecanismo de comando y control —dominios por víctima que imitaban tráfico legítimo del protocolo de Orion, con esteganografía para ocultar los comandos— fue diseñado explícitamente para *no* generar señales de indisponibilidad que delataran la intrusión (CISA, AA20-352A, 2020/2021). |

**Justificación ampliada de la propiedad más discutible:**

La disponibilidad es la más discutible porque, superficialmente, un
incidente de esta magnitud "se siente" como si tuviera que afectar las tres
propiedades. Pero no hay evidencia de caídas de servicio, denegación de
acceso ni destrucción de datos asociadas a SUNBURST: es, por diseño, lo
opuesto a un ataque de disponibilidad. El error típico —marcar las tres
propiedades como violadas por la gravedad del hecho— es precisamente el que
el enunciado advierte que hay que evitar. Acá la respuesta correcta y
defendible es «No», y es lo que distingue a este incidente de, por ejemplo,
WannaCry, donde la disponibilidad sí fue el objetivo directo.

---

## A.4 — Encadenamiento amenaza → vulnerabilidad → impacto

| Elemento | En este caso |
|---|---|
| **Amenaza** *(quién / qué, con qué motivación)* | Un actor estatal avanzado (APT29/Nobelium), atribuido por el gobierno de EE. UU. al Servicio de Inteligencia Exterior de Rusia (SVR), con motivación de espionaje de largo plazo, no de lucro económico ni de disrupción. |
| **Vulnerabilidad** *(la debilidad concreta que se explotó)* | Controles insuficientes de integridad y aislamiento en el entorno de build/CI-CD de SolarWinds, que permitieron insertar código malicioso en el binario antes de la etapa de firma, sin que el proceso de firma detectara la discrepancia entre el código fuente auditado y el binario efectivamente firmado. |
| **Activo** *(sobre qué recayó)* | El pipeline de compilación y firma de Orion Platform, y transitivamente las redes de ~18.000 organizaciones que instalaron la actualización troyanizada. |
| **Impacto** *(consecuencia sobre el negocio o las personas)* | Acceso de espionaje no detectado durante meses a redes sensibles de múltiples agencias federales de EE. UU. y empresas privadas; sustracción de herramientas internas de FireEye; una respuesta de emergencia a escala nacional (Directiva 21-01 de CISA); y sanciones diplomáticas de EE. UU. contra Rusia en abril de 2021. |

**Redacción:**

Un actor estatal con motivación de espionaje (la amenaza) explotó controles
de integridad insuficientes en el entorno de compilación y firma de código
de SolarWinds (la vulnerabilidad) para insertar el backdoor SUNBURST en el
binario `SolarWinds.Orion.Core.BusinessLayer.dll` antes de que fuera firmado
con el certificado legítimo de la empresa. Ese binario comprometido —el
activo sobre el que recayó el ataque— se distribuyó como una actualización
de rutina a miles de clientes de Orion, entre ellos agencias del gobierno de
EE. UU., que lo instalaron confiando en la firma digital. El resultado fue
un impacto de espionaje sostenido y no detectado durante meses sobre redes
gubernamentales y privadas, seguido de una respuesta de emergencia federal y
consecuencias diplomáticas para el atacante identificado.

---

## A.5 — Dos controles mitigantes

### Control 1

| | |
|---|---|
| **Qué es** | Atestación de procedencia de build firmada criptográficamente (por ejemplo, bajo el marco SLSA — Supply-chain Levels for Software Artifacts), que ata cada binario publicado a su commit de origen y a un registro verificable del entorno de build que lo produjo, en infraestructura de build efímera y aislada de Internet. |
| **Propiedad de la tríada que protege** | Integridad. |
| **Por qué habría funcionado en este caso concreto** | El ataque dependió exactamente de que el binario firmado no coincidiera con el código fuente auditado, sin que nadie pudiera detectarlo. Con atestación de procedencia (SLSA nivel 2 o superior), el binario `SolarWinds.Orion.Core.BusinessLayer.dll` habría llevado un registro verificable de qué código fuente y qué build efectivamente lo generaron; una discrepancia entre ese registro y el commit auditado habría sido detectable antes de la firma, y no después de nueve meses de explotación. |

### Control 2

| | |
|---|---|
| **Qué es** | Filtrado de salida (egress filtering) y monitoreo de anomalías en tráfico DNS/HTTP saliente, con una lista de permitidos estricta para los destinos con los que el software de monitoreo de red (Orion) necesita comunicarse legítimamente. |
| **Propiedad de la tríada que protege** | Confidencialidad. |
| **Por qué habría funcionado en este caso concreto** | El backdoor SUNBURST se comunicaba con dominios por víctima bajo `avsvmcloud[.]com`, imitando el protocolo legítimo de Orion y usando esteganografía para ocultar los comandos (CISA, AA20-352A, 2020/2021). Un control de egreso que solo permitiera tráfico saliente hacia los endpoints oficiales y documentados de SolarWinds habría bloqueado o, como mínimo, expuesto en los logs esas conexiones no autorizadas, acortando de forma significativa los meses de acceso no detectado que permitieron el monitoreo de correo del Tesoro y de NTIA. |

---

## A.6 — Fuentes consultadas (Parte A)

1. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2020, 17 de diciembre; actualizado 2021, 15 de abril). *Advanced persistent threat compromise of government agencies, critical infrastructure, and private sector organizations* (Cybersecurity Advisory AA20-352A). U.S. Department of Homeland Security. https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
2. [PRIMARIA] Cybersecurity and Infrastructure Security Agency. (2020, 13 de diciembre). *Emergency Directive 21-01: Mitigate SolarWinds Orion code compromise*. U.S. Department of Homeland Security. https://www.cisa.gov/news-events/directives/ed-21-01-mitigate-solarwinds-orion-code-compromise-closed
3. [PRIMARIA] FireEye/Mandiant. (2020, 13 de diciembre). *Highly evasive attacker leverages SolarWinds supply chain to compromise multiple global victims with SUNBURST backdoor*. https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
4. [SECUNDARIA] Mak, A. (2020, 16 de diciembre). *What we know about the hack of Commerce, Treasury, and other departments*. Slate. https://slate.com/technology/2020/12/solarwinds-hack-commerce-treasury-breach.html

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
$ rm data/muestra/politica_seguridad.md
$ echo "esto es un archivo plantado" > data/muestra/backdoor.sh
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

*(Después de esta prueba se regeneraron los datos de muestra con
`python3 data/generar_datos.py` y se volvió a correr `generar` para dejar
`data/muestra` y `manifest.sha256` en un estado íntegro y consistente.)*

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

Coincide con lo esperado: antes de correrlo esperábamos un valor cercano al
50 % (128 de 256 bits), precisamente porque SHA-256 está diseñado para que un
cambio mínimo en la entrada (acá, cambiar un solo dígito de `$1000` a
`$1001`) se propague de forma impredecible por toda la función de
compresión, sin dejar ningún patrón reconocible en la salida. También
verificamos el caso trivial —dos mensajes idénticos— para confirmar que la
distancia da exactamente 0:

```
$ python3 src/integridad.py avalancha --a "igual" --b "igual"
Distancia de Hamming: 0 de 256 bits (0.00 %)
Los mensajes son idénticos: la distancia tiene que ser 0.
```

### HMAC

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000"
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
```

```
$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" \
    --verificar 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe

TAG VÁLIDO — el mensaje es auténtico e íntegro.

$ python3 src/integridad.py mac --clave "secreto" --mensaje "transferir 1000" \
    --verificar 0000000000000000000000000000000000000000000000000000000000000000
mensaje:      "transferir 1000"
HMAC-SHA256:  96bc66546d55627136aeaaefbcead75520a57e19539834d03e74d705b70ff9fe
tag recibido: 0000000000000000000000000000000000000000000000000000000000000000

TAG INVÁLIDO — el mensaje fue alterado o la clave no es la correcta.
```

---

## B.2 — Decisiones de implementación

| Decisión | Qué hicimos | Por qué |
|---|---|---|
| Comparación de rutas para excluir el manifiesto | Resolvimos tanto el directorio recorrido como la ruta del manifiesto con `Path.resolve()` antes de compararlas (`ruta.resolve() == salida_resuelta`), en vez de comparar cadenas de texto. | Dos rutas pueden apuntar al mismo archivo con distinta representación textual (relativa vs. absoluta, `./manifest.sha256` vs. `manifest.sha256`); comparar las rutas ya normalizadas evita que el manifiesto se autoincluya y se reporte `NUEVO` en cada corrida por un desajuste puramente textual. |
| Orden de las categorías en `verificar` | Calculamos `del_disco` y `del_manifiesto` como conjuntos y derivamos `OK`/`MODIFICADO` iterando la intersección ordenada, y `FALTANTE`/`NUEVO` con diferencia de conjuntos, cada lista ordenada alfabéticamente. | Un manifiesto y un reporte de verificación son artefactos que se comparan entre corridas; un orden no determinista haría que el mismo estado real produjera diffs distintos, lo cual es ruido que el enunciado pide evitar explícitamente. |
| Directorio vacío o sin archivos nuevos/faltantes | `generar_manifiesto` sobre un directorio vacío devuelve `{}` sin lanzar excepción, y `verificar_manifiesto` devuelve las cuatro claves con listas vacías si no hay hallazgos. | El contrato de la función exige devolver siempre las cuatro claves, y un diccionario vacío es un manifiesto válido (cero archivos indexados), no un error; tratarlo como error obligaría a cada consumidor a manejar un caso especial que no es distinto de "no hay archivos que reportar". |
| Enlaces simbólicos | No se les da tratamiento especial: `Path.is_file()` sigue el enlace y, si apunta a un archivo regular existente, se hashea el contenido al que apunta. Un enlace roto simplemente no pasa el filtro `is_file()` y se ignora. | El enunciado no pide tratamiento especial de symlinks y los datos de muestra no los usan; seguir el comportamiento por defecto de `pathlib` es la opción menos sorprendente y evita introducir lógica no pedida ni probada. |

---

## B.3 — Preguntas de análisis

### 1. El manifiesto por sí solo no alcanza

Un manifiesto de hashes sin protección adicional no resiste a un atacante
que ya tiene acceso de escritura al directorio, porque nada distingue
criptográficamente al manifiesto legítimo del que el propio atacante puede
generar. Si un atacante modifica `transferencia.txt` y después ejecuta
`integridad.py generar` sobre el mismo directorio, el nuevo manifiesto
contendrá el hash del archivo *ya alterado*, y `verificar` reportará `OK`
sin que haya forma de distinguir esa corrida de una legítima: el esquema no
tiene ningún elemento que el atacante no pueda también recalcular.

Lo que falta es un elemento que dependa de un secreto o de una autoridad
externa al propio directorio. Dos alternativas concretas: (a) firmar el
manifiesto con una clave privada asimétrica cuya clave pública se distribuye
por un canal separado y de solo lectura para quien opera sobre el
directorio (así, aunque el atacante reescriba archivos y regenere el
manifiesto, no puede producir una firma válida sin la clave privada); o (b)
calcular un HMAC del manifiesto con una clave que el proceso que verifica
mantiene fuera del alcance de escritura del atacante —por ejemplo, en un
sistema separado o en un HSM—. En ambos casos, la propiedad que se agrega es
exactamente la que motiva la Parte B.4: sin conocer un secreto (la clave
privada o la clave HMAC), regenerar un manifiesto que "valide" no alcanza.

### 2. Qué agrega HMAC y qué no

Un hash simple (SHA-256 a secas) prueba que un dato no cambió desde que se
calculó su digest, pero cualquiera puede recalcular ese digest: no prueba
*quién* lo generó. HMAC incorpora una clave secreta compartida al cálculo,
de modo que producir un tag válido requiere conocer esa clave. Eso agrega
**autenticidad de origen**: si el tag es válido, el mensaje fue generado (o
al menos autorizado) por alguien que conoce la clave, no por un tercero
arbitrario que solo tenía acceso al mensaje.

Lo que HMAC **no** resuelve es el no repudio. Como la clave es *simétrica* y
*compartida* entre quien genera el tag y quien lo verifica, cualquiera de
los dos extremos que conoce la clave podría haber producido ese mismo tag.
Si Alice y Bob comparten una clave HMAC y Bob recibe un mensaje con un tag
válido, Bob puede confiar en que el mensaje viene de alguien que conoce la
clave —pero no puede demostrarle a un tercero (un juez, un auditor) que fue
Alice y no el propio Bob quien lo generó, porque Bob también tiene la
capacidad de producir tags válidos. Para no repudio hace falta criptografía
asimétrica (firmas digitales), donde la clave de firma es privada de un
único firmante y la de verificación es pública.

### 3. MD5 y SHA-1

A ambos se les rompió la **resistencia a colisiones**: dejó de ser
computacionalmente inviable encontrar dos entradas distintas con el mismo
digest. Para MD5, Wang y Yu (2005) publicaron un ataque diferencial capaz de
producir colisiones en minutos de cómputo. Para SHA-1, Stevens et al. (2017)
—el ataque conocido como *SHAttered*— produjeron la primera colisión
práctica completa, con un costo estimado de cómputo en la nube del orden de
110.000 dólares de la época. Es importante notar qué propiedad *no* se
rompió en ninguno de los dos casos: la resistencia a preimagen (dado un
digest, encontrar *alguna* entrada que lo produzca) sigue siendo
computacionalmente inviable para ambos. Eso es relevante porque no toda
aplicación de un hash depende de resistencia a colisiones.

Sobre si queda algún uso aceptable: para integridad de datos y firmas
digitales, ninguno de los dos —es exactamente el escenario donde la
resistencia a colisiones importa, porque un atacante que puede fabricar dos
mensajes con el mismo hash puede hacer firmar uno inocuo y sustituirlo
después por el malicioso. El propio NIST formalizó el retiro de SHA-1: desde
2013 no se permite su uso en firmas digitales nuevas, y fijó el 31 de
diciembre de 2030 como fecha límite para eliminarlo por completo del
software y hardware federal (NIST/CSRC, 2022). El único uso donde MD5 o
SHA-1 siguen apareciendo sin ser un riesgo de seguridad directo es como
checksum no adversarial —por ejemplo, detectar corrupción accidental de un
archivo durante una transferencia—, donde nadie está intentando fabricar
activamente una colisión.

**Fuentes:** Wang, X., y Yu, H. (2005). *How to break MD5 and other hash
functions*. En R. Cramer (Ed.), *Advances in Cryptology — EUROCRYPT 2005*
(LNCS vol. 3494, pp. 19–35). Springer.
https://www.iacr.org/archive/eurocrypt2005/34940019/34940019.pdf ·
Stevens, M., Bursztein, E., Karpman, P., Albertini, A., y Markov, Y. (2017).
*The first collision for full SHA-1*. Cryptology ePrint Archive, Report
2017/190. https://eprint.iacr.org/2017/190.pdf · National Institute of
Standards and Technology. (2022). *NIST transitioning away from SHA-1 for
all applications*. CSRC. https://csrc.nist.gov/news/2022/nist-transitioning-away-from-sha-1-for-all-apps

### 4. Comparación en tiempo constante

El operador `==` sobre cadenas o bytes en la mayoría de las implementaciones
compara byte a byte y **retorna en cuanto encuentra la primera diferencia**.
Eso significa que el tiempo que tarda la comparación depende de *cuántos
bytes iniciales coinciden* entre el tag recibido y el esperado. Un atacante
que puede medir ese tiempo con precisión —típicamente por la red, con
suficientes repeticiones para promediar el ruido— puede explotarlo como un
oráculo: prueba un tag byte por byte, y cuando un byte hace que la
comparación tarde un poco más (porque coincidió con el valor correcto y
`==` siguió comparando un byte más antes de fallar), sabe que acertó ese
byte y pasa al siguiente. Esto es un **ataque de temporización**
(*timing attack*), y reduce la complejidad de forzar un tag de fuerza bruta
sobre el espacio completo (2²⁵⁶ para SHA-256) a, en el peor caso, 256
intentos por byte × 32 bytes: un problema completamente distinto en escala.

`hmac.compare_digest()` evita esto comparando **todos** los bytes de ambas
cadenas sin importar dónde ocurre la primera diferencia (tiempo de ejecución
que depende solo de la longitud de las entradas, no de su contenido), de
modo que no hay ninguna señal de temporización que un atacante pueda
explotar byte a byte.

### 5. SHA-256 para contraseñas: mala idea

SHA-256 es criptográficamente sólido en el sentido de resistencia a
colisiones y preimagen, pero esas no son las propiedades que importan para
almacenar contraseñas. Lo que importa ahí es la **resistencia a fuerza
bruta offline**: si una base de datos de hashes de contraseñas se filtra, un
atacante intenta adivinar la contraseña original probando candidatos y
comparando el hash resultante. SHA-256 está diseñado deliberadamente para
ser **rápido** —eso es una virtud para verificar la integridad de un
archivo de gigabytes, pero es exactamente la propiedad equivocada para
contraseñas—: hardware especializado (GPUs, ASICs) puede calcular miles de
millones de hashes SHA-256 por segundo, lo que vuelve viable probar
diccionarios enteros o incluso el espacio completo de contraseñas cortas en
tiempos razonables.

En su lugar se usan funciones de derivación de claves diseñadas para ser
**deliberadamente lentas y costosas en memoria**, como Argon2id, bcrypt o
scrypt. La propiedad que tienen y SHA-256 no tiene es un **factor de costo
ajustable** (número de iteraciones, memoria requerida, paralelismo) que se
puede incrementar con el tiempo a medida que el hardware se abarata, y en el
caso de Argon2id y scrypt, un uso de memoria alto que específicamente
penaliza los ataques paralelizados en GPU/ASIC —donde la memoria, no el
cómputo, es el recurso escaso—. Eso convierte un ataque de fuerza bruta
offline de "miles de millones de intentos por segundo" a, según el factor
de costo elegido, unos pocos cientos o miles de intentos por segundo por
GPU: varios órdenes de magnitud más caro para el atacante, sin cambiar nada
para el usuario legítimo que solo necesita calcular el hash una vez por
inicio de sesión.

---

# Cierre

## Dificultades encontradas

El punto donde más fácil es equivocarse silenciosamente es `avalancha`: si
se cuentan diferencias sobre la representación hexadecimal (comparando
caracteres) en vez de sobre los bytes crudos con XOR + `bit_count()`, el
programa corre sin errores y produce un número que *parece* razonable, pero
sistemáticamente subestima la distancia real en bits. La única forma de
confirmar que la implementación es correcta fue el caso trivial de dos
mensajes idénticos (debe dar exactamente 0) y verificar que, para mensajes
distintos, el resultado ronda el 50 % en varias corridas con entradas
distintas, no solo una.

El segundo punto de atención fue no romper el contrato de
`verificar_manifiesto`: es tentador devolver solo las claves que tienen
contenido y omitir las vacías, pero el código que consume el resultado
(`_cmd_verificar`, ya resuelto) espera las cuatro claves siempre presentes.
Correr la prueba obligatoria de un solo byte antes de dar por terminada la
Parte B fue lo que permitió confirmar que la clasificación `OK` vs.
`MODIFICADO` funcionaba de punta a punta, no solo en el caso trivial de un
directorio sin cambios.

## Distribución del trabajo

| Integrante | Aportes |
|---|---|
| Magni, Gastón | Copió el esqueleto del laboratorio a `entregas/lab01/grupo05/`; implementó `distancia_hamming_bits` (TODO 3/4, subcomando `avalancha`); redactó la sección de Cierre (dificultades encontradas y declaración de uso de IA). |
| Mosconi, Ignacio | Agregó `INTEGRANTES.md`; implementó `calcular_mac` con HMAC-SHA256 (TODO 4/4, subcomando `mac`); redactó el mini-research completo (Tema 2 — cadena de suministro de software). |
| Presuttari, Matías | Implementó `generar_manifiesto` (TODO 1/4, subcomando `generar`); redactó la Identificación y la Parte A completa del informe (análisis del incidente SolarWinds/SUNBURST bajo la lente CIA). |
| Terreno, Valentino | Implementó `verificar_manifiesto` (TODO 2/4, subcomando `verificar`); redactó la Parte B del informe (evidencia de ejecución de todos los subcomandos y las cinco preguntas de análisis). |

---

## Declaración de uso de asistentes de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| Claude Code (Anthropic, modelo Claude Sonnet 5) | Implementar los cuatro bloques `TODO` de `src/integridad.py`; investigar y redactar el análisis del incidente SolarWinds/SUNBURST de la Parte A; redactar las respuestas de la Parte B.3. | Los cuatro subcomandos de `integridad.py` (`generar`, `verificar`, `avalancha`, `mac`); las secciones A.1 a A.6; las respuestas B.3.1 a B.3.5. | El código se ejecutó en su totalidad contra los datos de muestra reales (evidencia pegada en B.1, incluida la prueba obligatoria de detección de un byte, que dio el resultado esperado), no solo se leyó. Cada afirmación factual de la Parte A y cada cita técnica de la Parte B.3 se verificó contra la fuente primaria original (páginas de CISA, el blog de FireEye/Mandiant, el paper de Stevens et al. en el Cryptology ePrint Archive, el paper de Wang y Yu en las actas de EUROCRYPT 2005, y la página de CSRC/NIST sobre el retiro de SHA-1) obteniendo el contenido de esas páginas directamente, no confiando en el conocimiento del modelo sin contrastar. |

**Declaración:**

El grupo declara que comprende el contenido íntegro de lo entregado y que
puede explicar y defender oralmente cualquier parte del código y del
análisis, independientemente de la asistencia recibida.

---

## Fuentes consultadas (general)

Ver [A.6](#a6--fuentes-consultadas-parte-a) para las fuentes de la Parte A.
Las fuentes técnicas de la Parte B están citadas en línea dentro de cada
respuesta de B.3.

1. Cybersecurity and Infrastructure Security Agency. (2020, 17 de diciembre; actualizado 2021, 15 de abril). *Advanced persistent threat compromise of government agencies, critical infrastructure, and private sector organizations* (AA20-352A). https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
2. Wang, X., y Yu, H. (2005). *How to break MD5 and other hash functions*. En *Advances in Cryptology — EUROCRYPT 2005* (LNCS vol. 3494, pp. 19–35). Springer. https://www.iacr.org/archive/eurocrypt2005/34940019/34940019.pdf
3. Stevens, M., Bursztein, E., Karpman, P., Albertini, A., y Markov, Y. (2017). *The first collision for full SHA-1*. Cryptology ePrint Archive, Report 2017/190. https://eprint.iacr.org/2017/190.pdf
