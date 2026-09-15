# Informe — Laboratorio 02 · Criptografía

> Copiala a `entregas/lab02/grupoXX/informe.md`. Borrá las notas en cursiva.

**Grupo:** 07
**Integrantes:** Lorenzo Blanc — @LoloBlanc · Fernando Cagliero — @Ferca19 · Guadalupe Gómez — @guadagomezgg8 · Lautaro Mariño — @lautaromarino0
**Fecha:** 12/09/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| OpenAI Codex | Explicación conceptual, implementación y depuración de B.2, y asistencia en la redacción de las respuestas B.2.1–B.2.3. | `src/cripto.py`: `mac_ingenuo()`, `mac_hmac()` y `verificar_mac()`; sección B.2 de `informe.md`. | Se verificó con `src/verificar.py`, comparación contra `hashlib` y `hmac` de la biblioteca estándar, ejecución de la CLI, `py_compile` y `git diff --check`. |
| Claude (Anthropic) — Cowork | Búsqueda y contraste de fuentes sobre derivación de claves (PBKDF2, bcrypt, scrypt, Argon2); asistencia en la redacción del mini-research y en el script de medición. | `research.md` (tema C) y `src/kdf_demo.py`. | Se accedió a cada una de las fuentes citadas y comprobó el dato afirmado en cada una; los tiempos publicados salen de ejecutar `python3 src/kdf_demo.py`; el texto fue revisado y reformulado antes de commitear. Detalle en la declaración al final de `research.md`. |

*El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del código y del análisis, independientemente de la asistencia recibida.*

## 1. Parte A — Análisis de la falla

**Caso:** Sony PlayStation 3 (ECDSA) — reutilización del nonce secreto al firmar

### A.1 — Qué prometía el sistema

La PlayStation 3 utilizaba firmas digitales para sostener una cadena de confianza: el software debía poder verificarse con una clave pública antes de ser aceptado por la plataforma. La promesa de este mecanismo era detectar modificaciones no autorizadas y autenticar que el software provenía del firmante legítimo; por lo tanto, las propiedades relevantes eran principalmente autenticidad e integridad, no confidencialidad. ([fail0verflow, 2010](https://www.cs.cmu.edu/~dst/GeoHot/1780_27c3_console_hacking_2010.pdf); [NIST, 2023](https://csrc.nist.gov/pubs/fips/186-5/final))

### A.2 — El mal uso

El problema no fue que ECDSA estuviera matemáticamente roto, sino que la implementación de Sony reutilizó el mismo valor secreto usado como nonce en más de una firma. En la notación de esta consigna llamamos `k` a ese nonce; la presentación original de fail0verflow usa `m` para el nonce y `k` para la clave privada, por lo que no deben confundirse. En ECDSA, reutilizar el nonce hace que dos firmas distintas compartan el mismo componente `r`, y permite relacionar algebraicamente sus valores `s` y los hashes de los mensajes. ([fail0verflow, 2010](https://www.cs.cmu.edu/~dst/GeoHot/1780_27c3_console_hacking_2010.pdf))

### A.3 — Propiedad rota y explotación

La propiedad rota de forma directa fue la autenticidad de las firmas y, como consecuencia, la integridad de los ejecutables aceptados por la cadena de confianza. Si un atacante observa dos firmas `(r, s1)` y `(r, s2)` sobre mensajes cuyos hashes son `z1` y `z2`, puede calcular `k = (z1 - z2) / (s1 - s2) mod n` y luego recuperar la clave privada `d = (s1 · k - z1) / r mod n`. Con esa clave puede generar firmas válidas sobre software elegido por él; el verificador seguirá aceptándolas porque solo comprueba la firma con la clave pública, no quién calculó realmente el archivo. ([fail0verflow, 2010](https://www.cs.cmu.edu/~dst/GeoHot/1780_27c3_console_hacking_2010.pdf))

La falla no permitía leer directamente información cifrada: el impacto principal estaba en la confianza del proceso de arranque y actualización. Al poder firmar código arbitrario, se podía presentar software modificado como si fuera legítimo, anulando la garantía de integridad que la firma debía proporcionar. ([fail0verflow, 2010](https://www.cs.cmu.edu/~dst/GeoHot/1780_27c3_console_hacking_2010.pdf); [NIST, 2023](https://csrc.nist.gov/pubs/fips/186-5/final))

### A.4 — Lo correcto

La implementación debe generar un nonce secreto, impredecible y nuevo para cada firma, y proteger tanto ese nonce como la clave privada; NIST establece explícitamente que ECDSA requiere un nuevo número aleatorio `k` para cada mensaje firmado. Como alternativa, puede usarse generación determinista de nonces conforme a RFC 6979, que evita depender de una nueva fuente aleatoria durante cada firma sin reutilizar el valor. ([NIST, 2010](https://csrc.nist.gov/files/pubs/fips/186-3/final/docs/fips_186-3.pdf); [Pornin, 2013](https://www.rfc-editor.org/rfc/rfc6979.html))

### Fuentes de la Parte A

- Chaos Computer Club. (2010, 29 de diciembre). *Console Hacking 2010* [Ficha de la presentación]. 27th Chaos Communication Congress. https://fahrplan.events.ccc.de/congress/2010/Fahrplan/events/4087.en.html
- fail0verflow. (2010, 29 de diciembre). *Console Hacking 2010: PS3 Epic Fail* [Presentación]. https://www.cs.cmu.edu/~dst/GeoHot/1780_27c3_console_hacking_2010.pdf
- National Institute of Standards and Technology. (2010). *Digital Signature Standard (DSS)* (FIPS PUB 186-3). https://csrc.nist.gov/files/pubs/fips/186-3/final/docs/fips_186-3.pdf
- National Institute of Standards and Technology. (2023). *Digital Signature Standard (DSS)* (FIPS 186-5). https://csrc.nist.gov/pubs/fips/186-5/final
- Pornin, T. (2013). *Deterministic usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)* (RFC 6979). RFC Editor. https://www.rfc-editor.org/rfc/rfc6979.html

## 2. Parte B.1 — Romper el XOR

**Clave hallada:** `0x37` (55 en decimal)

**Mensaje en claro:**

> Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

**Salida del comando:**

```
$ python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
clave=0x37
Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.
```

**Por qué falla el cifrado clásico:**

El cifrado se pudo romper porque la clave utilizada era de solo 1 byte, por lo que existen únicamente 2⁸ = 256 claves posibles. Esto hace que probar todas las combinaciones mediante fuerza bruta sea prácticamente instantáneo. Una vez generado cada candidato, se puede determinar cuál es el texto correcto mediante análisis de frecuencia: un texto en español contiene muchos espacios, vocales y letras frecuentes, por lo que el candidato correcto obtiene un puntaje mayor al comparar sus bytes con un conjunto de caracteres esperados. En cambio, al utilizar una clave incorrecta, los bytes resultantes presentan una distribución mucho menos compatible con el lenguaje natural.

El problema, entonces, no es que XOR sea una operación débil, sino que se utilizó una clave demasiado corta para ofrecer seguridad frente a un ataque de fuerza bruta. Esto también se relaciona con el principio de Kerckhoffs: el algoritmo puede ser conocido públicamente y la seguridad debe depender de la clave; en este caso, una clave de solo 8 bits no ofrece suficiente seguridad. Para evitar este problema sería necesario utilizar una clave suficientemente larga y generada de forma aleatoria; por ejemplo, una clave de 16 bytes tendría 2¹²⁸ posibilidades, haciendo inviable una búsqueda exhaustiva. Además, durante las pruebas observamos que dos claves diferentes podían producir el mismo texto con las mayúsculas y minúsculas invertidas, como ocurrió con `MEMO INTERNO PHANTOMCORP` y `Memo interno PhantomCorp`. Esto se debe a que, en ASCII, una letra mayúscula y su correspondiente minúscula difieren en un solo bit, por lo que dos claves que difieren en ese bit producen el mismo texto con el caso cambiado.

## 3. Parte B.2 — Autenticación

### B.2.1 — Por qué `sha256(clave || mensaje)` permite length-extension

La construcción ingenua calcula `SHA-256(K || M)`, donde `K` es la clave
secreta y `M` el mensaje. SHA-256 pertenece a la familia de funciones hash
iterativas Merkle-Damgård: procesa el mensaje por bloques y el digest final
representa el estado interno después de procesar también el padding. Por eso,
cuando un atacante conoce `M` y el MAC, puede usar ese digest como estado
inicial y continuar el cálculo con un sufijo elegido, sin conocer `K`.

En un caso concreto, si el servidor acepta un mensaje como `pago=100`, el
atacante puede intentar distintos largos posibles de `K`, calcular el padding
correspondiente y construir `pago=100 || padding || &admin=true`. Luego genera
un tag para ese mensaje extendido a partir del tag original y lo envía. El
servidor vuelve a calcular `SHA-256(K || mensaje_recibido)` y obtiene el mismo
resultado, aunque el atacante nunca haya recuperado ni adivinado la clave.

### B.2.2 — Cómo lo resuelve HMAC

HMAC no calcula el hash de la clave concatenada directamente con el mensaje.
Su estructura es, conceptualmente,
`H((K' XOR opad) || H((K' XOR ipad) || M))`, usando una clave normalizada y
dos valores de relleno distintos. Primero se calcula un hash interno con una
clave derivada y luego un hash externo que vuelve a incorporar material secreto.

El atacante solo observa el resultado externo; no recibe el estado interno que
correspondería a continuar `K || M`. Por eso no puede aplicar un sufijo y
obtener un tag válido mediante length-extension. HMAC además está diseñado y
analizado específicamente como un código de autenticación de mensajes, por lo
que es la construcción apropiada en lugar de inventar una concatenación de
clave y mensaje.

### B.2.3 — Qué ataque evita `compare_digest`

Una comparación normal con `==` puede detenerse en el primer carácter distinto.
Un atacante que consulte repetidamente un endpoint que verifica MAC podría
medir pequeñas diferencias de tiempo: una propuesta que acierta el primer
carácter del tag puede tardar más que una que falla inmediatamente. Repitiendo
el proceso, podría recuperar el tag carácter por carácter y finalmente enviar
un mensaje falsificado.

`hmac.compare_digest()` realiza una comparación adecuada para secretos y evita
ese retorno temprano dependiente del prefijo coincidente, reduciendo la
información temporal disponible para el atacante. En `verificar_mac()` se usa
para distinguir un tag válido de uno inválido sin convertir el tiempo de
respuesta en un oráculo útil.

## 4. Bitácora

```bash
python data/generar_datos.py
python src/cripto.py xor --texto hola --clave K
python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
python src/verificar.py
```
