# Informe — Laboratorio 02 · Criptografía

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 16 de octubre de 2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

Usamos asistentes de IA (Claude, de Anthropic, y Antigravity, de Google) como herramientas de apoyo durante el laboratorio, con estos fines:

- **Aprender y repasar conceptos** teóricos y criptográficos: resistencia a colisiones, ataques de prefijo elegido, funcionamiento de firmas sobre certificados X.509, construcción Merkle-Damgård, HMAC, ataques de extensión de longitud (*length-extension*) y ataques de canal lateral basados en tiempos (*timing attacks*).
- **Buscar y verificar información y fuentes** académicas y estándares (RFCs, FIPS, publicaciones de conferencias CRYPTO/EUROCRYPT) para las Partes A y B y el Mini-research.
- **Apoyo en el desarrollo y revisión de código**: diseño del algoritmo de puntuación por frecuencias para romper XOR de 1 byte, verificación de llamadas a la biblioteca estándar de Python (`hashlib`, `hmac`), y redacción técnica de los informes.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo verificamos el resultado |
|---|---|---|---|
| Claude (Anthropic) | Explicación de conceptos, búsqueda de fuentes primarias/arbitradas y redacción de borrador | Parte A | Entramos a cada una de las fuentes citadas para confirmar que existen, verificar los DOIs y constatar que afirman lo expresado en el texto. |
| Claude (Anthropic) y Antigravity (Google) | Asistencia en análisis de frecuencia, desarrollo de funciones criptográficas y redacción técnica | Parte B, Mini-research y Bitácora | Corrimos la suite `src/verificar.py` (4/4 OK), validamos los outputs con las herramientas de referencia de la cátedra y contrastamos cada respuesta conceptual con los estándares RFC 2104, RFC 6151 y FIPS 198-1. |

En ningún caso tomamos lo que devolvía la IA sin revisarlo: verificamos el contenido, lo contrastamos con las fuentes y nos aseguramos de entender lo que entregamos. El grupo declara que comprende el contenido íntegro de este trabajo.

## 1. Parte A — Análisis de la falla

**Caso:** 3 — MD5 / colisiones: uso de una función de hash rota para firmar certificados (asignado por `08 mod 5 = 3`).

Analizamos dos incidentes reales que comparten la misma falla. El principal es el certificado de CA falso obtenido de RapidSSL en 2008 [1], [2]. El segundo es el certificado de Microsoft falsificado por el malware Flame en 2012 [5], [6]. Los números entre corchetes remiten a las fuentes al final de esta sección.

### A.1 — Qué prometía el sistema

Una infraestructura de clave pública (PKI) promete **autenticidad**: si un certificado X.509 está firmado por una autoridad de certificación (CA) confiable, entonces la clave pública que contiene pertenece realmente a quien dice el certificado, y la CA verificó y aprobó exactamente ese contenido. Sobre esa promesa se apoyan HTTPS (el navegador confía en que `banco.com` es `banco.com`) y la firma de código (Windows confía en que un programa viene de Microsoft).

La firma de una CA no se aplica sobre el certificado completo, sino sobre su **hash**. Por eso la promesa de autenticidad depende de una propiedad de la función de hash: la **resistencia a colisiones**, es decir, que nadie pueda fabricar dos certificados distintos con el mismo hash. Si eso se puede, una firma legítima sobre un certificado sirve también para el otro. En los dos casos el hash usado era MD5 (algoritmo de firma `md5WithRSAEncryption`) [2], [6].

### A.2 — El mal uso

El problema no fue que «MD5 es un mal algoritmo». MD5 sigue funcionando como suma de verificación contra errores accidentales. El mal uso fue **seguir usando MD5 para firmas digitales, que es justo el uso que requiere resistencia a colisiones, años después de que se demostrara públicamente que esa propiedad estaba rota**. A eso se sumó firmar contenido **predecible** para el atacante.

- **Las advertencias eran públicas.** Las colisiones prácticas de MD5 se publicaron en 2004 y se formalizaron en 2005 [3]. En 2007 se demostraron colisiones de prefijo elegido y certificados X.509 colisionantes con identidades distintas [4]. Aun así, en 2008 seis CAs seguían emitiendo certificados firmados con MD5, y el 97 % de esos certificados venía de RapidSSL [2].
- **RapidSSL firmaba contenido predecible.** Emitía el certificado unos 6 segundos después de la compra, de forma automática, y con números de serie **secuenciales**. Así el atacante podía calcular de antemano, byte por byte, qué contenido iba a firmar la CA, que es el requisito del ataque [2].
- **Microsoft (caso Flame) repitió el patrón en 2012.** El servicio de licencias de Terminal Server firmaba certificados con MD5, con números de serie y períodos de validez predecibles. Además, por un error de configuración, esos certificados servían para **firmar código** aunque solo hacían falta para licencias [5], [6].

### A.3 — Propiedad rota y cómo se explotó

**Propiedad rota: autenticidad**, y con ella la integridad de lo que la firma garantiza. La confidencialidad no se ve afectada directamente: nadie descifró nada, se falsificó una identidad.

**Cómo se explotó (RapidSSL, 2008)** [1], [2]:

1. Los investigadores prepararon dos certificados con **prefijos distintos que eligieron ellos**. El primero era un certificado común para un sitio web, como el que RapidSSL firmaría sin dudar. El segundo era un certificado de **CA intermedia** (`CA = TRUE`), con la clave pública de los atacantes.
2. Con un ataque de **colisión de prefijo elegido** sobre MD5 calcularon unos bloques que, agregados a cada certificado, hacen que los dos tengan **el mismo hash MD5**. El cálculo corrió en más de 200 PlayStation 3 y tardó unas 18 horas [2].
3. Para que el certificado que firmaría la CA coincidiera exactamente con el que habían calculado, aprovecharon el número de serie secuencial y el tiempo de emisión fijo de RapidSSL [2].
4. Compraron el certificado de sitio web legítimo. RapidSSL lo firmó, es decir, firmó su hash MD5.
5. **Copiaron esa firma al certificado de CA falso.** Como los dos tienen el mismo hash, la firma es válida para ambos. El resultado fue una CA intermedia en la que confiaban todos los navegadores y que podía emitir certificados válidos para **cualquier** sitio, por ejemplo para hacer *man-in-the-middle* sobre HTTPS sin ninguna advertencia.

Los investigadores le pusieron al certificado falso una validez vencida a propósito (2004) para que no pudiera abusarse de él [2]. CERT/CC publicó la nota VU#836068 sobre el problema [7].

**Mismo ataque en un uso real y malicioso (Flame, 2012)** [5], [6], [8]: los atacantes usaron una **variante hasta entonces desconocida** del ataque de prefijo elegido sobre MD5 [8]. Fabricaron un certificado que encadenaba hasta la raíz de Microsoft y que funcionaba **en todas las versiones de Windows** [6]. Con él, el malware Flame quedaba firmado como si fuera software legítimo de Microsoft. Microsoft tuvo que invalidar toda la jerarquía de CAs de licencias de Terminal Server [5].

### A.4 — Lo correcto

Firmar certificados con una función de hash que siga siendo resistente a colisiones (SHA-256 o superior) y abandonar MD5 para firmas apenas se publicó su ruptura, como establece la RFC 6151 [9]. Como defensa adicional, agregar **aleatoriedad impredecible al contenido firmado**, por ejemplo números de serie aleatorios, para que el atacante no pueda anticipar qué va a firmar la CA [2].

### Fuentes (Parte A)

1. Stevens, M., Sotirov, A., Appelbaum, J., Lenstra, A., Molnar, D., Osvik, D. A. y de Weger, B. (2009). Short chosen-prefix collisions for MD5 and the creation of a rogue CA certificate. En S. Halevi (Ed.), *Advances in Cryptology — CRYPTO 2009* (LNCS 5677, pp. 55–69). Springer. https://doi.org/10.1007/978-3-642-03356-8_4 — **Arbitrada** (paper con revisión por pares).
2. Sotirov, A., Stevens, M., Appelbaum, J., Lenstra, A., Molnar, D., Osvik, D. A. y de Weger, B. (2008, 30 de diciembre). *MD5 considered harmful today: Creating a rogue CA certificate* [Presentación en el 25th Chaos Communication Congress, Berlín]. https://marc-stevens.nl/research/hashclash/rogue-ca/ — **Primaria** (publicación de los propios investigadores).
3. Wang, X. y Yu, H. (2005). How to break MD5 and other hash functions. En R. Cramer (Ed.), *Advances in Cryptology — EUROCRYPT 2005* (LNCS 3494, pp. 19–35). Springer. https://doi.org/10.1007/11426639_2 — **Arbitrada**.
4. Stevens, M., Lenstra, A. y de Weger, B. (2007). Chosen-prefix collisions for MD5 and colliding X.509 certificates for different identities. En M. Naor (Ed.), *Advances in Cryptology — EUROCRYPT 2007* (LNCS 4515, pp. 1–22). Springer. https://doi.org/10.1007/978-3-540-72540-4_1 — **Arbitrada**.
5. Microsoft. (2012, 3 de junio). *Microsoft Security Advisory 2718704: Unauthorized digital certificates could allow spoofing*. https://learn.microsoft.com/en-us/security-updates/securityadvisories/2012/2718704 — **Primaria** (documento del fabricante).
6. Ness, J. (2012, 6 de junio). Flame malware collision attack explained. *Microsoft Security Response Center Blog*. https://www.microsoft.com/en-us/msrc/blog/2012/06/flame-malware-collision-attack-explained/ — **Primaria** (análisis técnico del fabricante).
7. CERT Coordination Center. (2008, 31 de diciembre). *Vulnerability Note VU#836068: MD5 vulnerable to collision attacks*. https://kb.cert.org/vuls/id/836068 — **Primaria** (aviso oficial).
8. Stevens, M. (2013). Counter-cryptanalysis. En *Advances in Cryptology — CRYPTO 2013* (LNCS 8042, pp. 129–146). Springer. Versión de acceso abierto: https://eprint.iacr.org/2013/358 — **Arbitrada**.
9. Turner, S. y Chen, L. (2011). *Updated security considerations for the MD5 message-digest and the HMAC-MD5 algorithms* (RFC 6151). IETF. https://www.rfc-editor.org/rfc/rfc6151 — **Primaria** (estándar).

## 2. Parte B.1 — Romper el XOR

### B.1.1 — Resultados obtenidos

- **Clave hallada:** `0x37` (en base 10: `55`; en ASCII: caracter `'7'`).
- **Mensaje en claro recuperado:**
  > `Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.`

### B.1.2 — Por qué el cifrado clásico falla

El ejercicio demuestra que un cifrado simétrico elemental como el XOR de clave corta o de un solo byte es incapaz de ofrecer confidencialidad frente a un adversario pasivo. Las razones técnicas radican en:

1. **Espacio de claves minúsculo (búsqueda exhaustiva trivial):**
   Una clave de 1 byte tiene únicamente $2^8 = 256$ valores posibles. Para un atacante, evaluar todas las combinaciones posibles toma menos de 10 milisegundos en cualquier CPU contemporánea. La fuerza bruta no solo es factible sino prácticamente instantánea.

2. **Preservación de la distribución estadística del lenguaje:**
   El operador XOR ($\oplus$) es una biyección bit a bit determinista. Al aplicar la misma clave $K$ de 1 byte sobre cada byte $P_i$ del texto plano ($C_i = P_i \oplus K$), se genera un cifrado monoalfabético de sustitución directa. En consecuencia:
   - El caracter más común del texto original (el espacio en blanco `' '` o la letra `'e'` en español/inglés) se transforma siempre en el mismo byte en el texto cifrado ($C_{\text{espacio}} = 0x20 \oplus K$).
   - La frecuencia de aparición de cada byte cifrado es idéntica a la frecuencia del mensaje original.
   - En nuestro algoritmo `romper_xor_1byte`, bastó con asignar pesos a los caracteres de alta frecuencia del lenguaje natural (espacio, vocales `e, a, o, i, u`, consonantes usuales `s, r, n, l, d, t, c, m, p`, dígitos y signos de puntuación) y castigar severamente los bytes de control no imprimibles o anómalos. La clave correcta (`0x37`) emergió con el puntaje más alto de forma inequívoca sobre las 255 candidatas restantes.

3. **Falta absoluta de confusión y difusión (Principios de Shannon):**
   Los cifrados de bloque y de flujo modernos (como AES-GCM o ChaCha20) cumplen con las propiedades fundamentales formuladas por Claude Shannon en 1949:
   - **Confusión:** relación compleja y no lineal entre la clave y el texto cifrado (mediante S-Boxes y sustituciones). En el XOR simple, la relación es estrictamente lineal ($P = C \oplus K$), lo que facilita ataques algebraicos inmediatos.
   - **Difusión:** un cambio en un solo bit del texto plano o de la clave altera en promedio el 50 % de los bits del texto cifrado (efecto avalancha). En el XOR simple, no existe ninguna difusión: cada byte del criptograma depende exclusivamente de un byte del mensaje y del byte correspondiente de la clave. Un atacante no solo puede descifrar, sino alterar bytes puntuales en tránsito (*maleabilidad*) sin corromper el resto del mensaje.

4. **El Principio de Kerckhoffs y el One-Time Pad:**
   El principio de Kerckhoffs exige que la seguridad del sistema resida exclusivamente en el secreto de la clave y no en la oscuridad del algoritmo. El cifrado XOR solo es teóricamente inquebrantable (seguridad perfecta de Shannon) bajo el esquema de *One-Time Pad* (OTP o libreta de un solo uso), que exige de manera estricta cuatro requisitos simultáneos:
   - Clave con entropía perfecta (bits verdaderamente aleatorios).
   - Longitud de la clave igual o mayor a la longitud del mensaje ($|K| \ge |M|$).
   - Clave de un solo uso (jamás reutilizada ni parcial ni totalmente).
   - Secreto absoluto de la clave.
   Al utilizar una clave de 1 byte repetida, se viola de inmediato el principio de longitud y no reutilización, reduciendo la seguridad teórica del OTP a cero y permitiendo el criptoanálisis de frecuencia.

---

## 3. Parte B.2 — Autenticación

### B.2.1 — Longitud de mensaje y vulnerabilidad de `sha256(clave || mensaje)` (Length-Extension Attack)

El diseño ingenuo `MAC = sha256(clave || mensaje)` intenta proporcionar integridad y autenticidad combinando un secreto compartido con el mensaje antes de aplicar la función de hash. Sin embargo, esta construcción es gravemente insegura en funciones de hash basadas en la construcción Merkle-Damgård (como MD5, SHA-1, SHA-256 y SHA-512) debido al **ataque de extensión de longitud** (*length-extension attack*).

#### Causa estructural: Merkle-Damgård
En Merkle-Damgård, el mensaje se divide en bloques de tamaño fijo (64 bytes / 512 bits en SHA-256). Si la entrada no completa un bloque, se aplica un relleno estandarizado (*padding*):
1. Se agrega un bit `1` (byte `0x80`).
2. Se rellenan con ceros (`0x00`) los bytes necesarios.
3. Se añaden los últimos 8 bytes (64 bits) que codifican la longitud total de la entrada en bits.

El hash procesa bloque por bloque actualizando un estado interno compuesto por 8 registros de 32 bits ($a, b, c, d, e, f, g, h$), comenzando desde un Vector de Inicialización ($IV$) prefijado:
$$H_0 = IV, \quad H_i = f(H_{i-1}, B_i), \quad H_{\text{final}} = H_n$$
El aspecto determinante es que **el digest de salida de SHA-256 es exactamente el valor de los registros internos tras procesar el último bloque**, sin ninguna transformación final secreta.

#### Qué puede falsificar el atacante sin conocer la clave
Supongamos que una API autoriza solicitudes verificando `mac_ingenuo`:
- Mensaje original interceptado ($M$): `usuario=operador&accion=consultar_datos`
- MAC interceptado ($T$): `sha256(clave || M)`
- Longitud supuesta de la clave secreta: el atacante no conoce la clave $K$, pero si el largo de la clave es predecible o acotado (por ejemplo, entre 8 y 32 bytes), el atacante puede iterar sobre las longitudes posibles.

Conociendo $|K|$ y $|M|$, el atacante puede calcular de forma determinista el bloque de padding que el algoritmo aplicó internamente a $(K \parallel M)$:
$$\text{pad} = \text{padding}(|K| + |M|)$$

A continuación, el atacante desea añadir un comando malicioso adicional ($M_{\text{extra}}$), por ejemplo: `&rol=administrador&transferir=10000`.

El atacante procede del siguiente modo:
1. Toma el valor hexadecimal del MAC legítimo $T$ y lo descompone en los ocho registros internos de SHA-256 como su vector de estado inicial ($IV'$).
2. Alimenta a la función de compresión el fragmento $M_{\text{extra}}$ fijando como longitud total acumulada $|K| + |M| + |\text{pad}| + |M_{\text{extra}}|$.
3. El resultado es una nueva firma válida $T'$ calculada **sin haber necesitado conocer la clave secreta $K$ en ningún momento**.
4. El mensaje transmitido a la víctima es:
   $$M_{\text{falsificado}} = M \parallel \text{pad} \parallel M_{\text{extra}}$$

Cuando el servidor recibe $M_{\text{falsificado}}$ y $T'$, ejecuta:
$$\text{MAC}_{\text{servidor}} = \text{SHA-256}(K \parallel M_{\text{falsificado}}) = \text{SHA-256}(K \parallel M \parallel \text{pad} \parallel M_{\text{extra}})$$
Dado que la función de compresión procesará secuencialmente $K \parallel M \parallel \text{pad}$ (llegando internamente al estado $T$) y luego procesará $M_{\text{extra}}$, el valor resultante será idéntico a $T'$. La verificación resulta exitosa y el servidor procesa la instrucción ilegítima.

---

### B.2.2 — Cómo lo resuelve HMAC estructuralmente

HMAC (*Hash-based Message Authentication Code*), formalizado en la RFC 2104 y estandarizado en FIPS PUB 198-1, fue concebido por Mihir Bellare, Ran Canetti y Hugo Krawczyk en 1996 específicamente para prevenir este y otros ataques inherentes a las construcciones iterativas.

#### Estructura matemática
HMAC utiliza una arquitectura anidada en dos fases (doble hashing) con claves derivadas internas y externas:
$$\text{HMAC}(K, M) = H\Big((K' \oplus opad) \;\parallel\; H\big((K' \oplus ipad) \;\parallel\; M\big)\Big)$$

Donde:
- $H$ es la función de hash subyacente (SHA-256).
- $B$ es el tamaño de bloque de la función de hash (64 bytes para SHA-256).
- $K'$ es la clave normalizada a $B$ bytes:
  - Si $|K| > B$, se reemplaza por $K' = H(K)$ rellenada con ceros hasta completar $B$ bytes.
  - Si $|K| \le B$, se utiliza $K$ rellenada con ceros a la derecha hasta completar $B$ bytes.
- $ipad$ (*inner padding*) es una constante de $B$ bytes formada por la repetición del byte `0x36` (`0x363636...36`).
- $opad$ (*outer padding*) es una constante de $B$ bytes formada por la repetición del byte `0x5c` (`0x5c5c5c...5c`).

#### Por qué neutraliza el ataque de length-extension
1. **Ocultamiento del estado intermedio:**
   El mensaje $M$ solo se procesa en el hash interno:
   $$H_{\text{in}} = H((K' \oplus ipad) \parallel M)$$
   El atacante nunca tiene acceso al digest $H_{\text{in}}$ ni a los registros del estado tras absorber $M$. Lo único que viaja por la red es el hash externo:
   $$T = H((K' \oplus opad) \parallel H_{\text{in}})$$
2. **Imposibilidad de extender el hash externo:**
   Si el atacante intentara un ataque de length-extension sobre el hash externo visible $T$, la extensión se aplicaría a la entrada del hash externo, es decir, sobre $(K' \oplus opad) \parallel H_{\text{in}} \parallel \text{pad} \parallel M_{\text{extra}}$. Esto agregaría datos después del digest $H_{\text{in}}$, pero **no puede alterar ni inyectar datos dentro del mensaje $M$**, que ya fue condensado y sellado irrevocablemente dentro de $H_{\text{in}}$.
3. **Imposibilidad de extender el hash interno:**
   Para aplicar length-extension sobre $H_{\text{in}}$ y añadir datos a $M$, el atacante necesitaría conocer el valor exacto de $H_{\text{in}}$ como vector de inicialización. Pero $H_{\text{in}}$ está protegido por la segunda capa de hash con la clave externa $(K' \oplus opad)$. Debido a la resistencia a la preimagen de la función de hash, recuperar $H_{\text{in}}$ a partir de $T$ es computacionalmente inviable.
4. **Independencia criptográfica de claves derivadas:**
   Las máscaras $ipad$ (`0x36`) y $opad$ (`0x5c`) presentan una distancia Hamming significativa (difieren en múltiples bits en cada byte), lo que garantiza que las dos claves derivadas $(K' \oplus ipad)$ y $(K' \oplus opad)$ actúen como dos claves criptográficas pseudoaleatorias independientes e inconexas, modelando a HMAC como una función pseudoaleatoria (PRF) demostrablemente segura.

---

### B.2.3 — Comparación en tiempo constante y `hmac.compare_digest`

#### Ataque que evita: Ataque de canal lateral por análisis de tiempo (*Timing Attack*)
El operador de igualdad convencional de cadenas y arreglos en los lenguajes de programación estándar (por ejemplo, `==` en Python o `memcmp` en C) implementa una comparación lexicográfica optimizada para rendimiento mediante **evaluación en cortocircuito** (*short-circuit evaluation*).

El comparador examina los datos byte a byte de izquierda a derecha. En el instante preciso en que detecta el primer byte discordante, **aborta inmediatamente el bucle** y retorna `False`. Si los primeros bytes coinciden, continúa evaluando las posiciones subsiguientes.

#### Mecánica de explotación paso a paso
Supongamos un servicio que recibe un mensaje junto a un token MAC en hexadecimal (64 caracteres correspondientes a 32 bytes de SHA-256):

```python
# CÓDIGO VULNERABLE A TIMING ATTACK:
if mac_calculado == mac_recibido:
    ejecutar_pago()
```

Un atacante sin conocimiento de la clave simétrica envía mensajes con MACs fabricados y mide con alta resolución el tiempo transcurrido hasta recibir la respuesta de error HTTP 403 / "MAC inválido". Los tiempos que siguen son **valores ilustrativos**, no mediciones reales: lo que importa es que la diferencia existe y se puede detectar estadísticamente.

1. **Deducción del primer byte:**
   El atacante envía 256 peticiones fijando el primer byte desde `0x00` hasta `0xFF` y rellenando los 31 bytes restantes con ceros.
   - En 255 de los intentos, el primer byte es incorrecto: la función `==` compara 1 byte y aborta en tiempo $t_0 \approx 10.15 \, \mu\text{s}$.
   - En el intento donde el primer byte coincide con el secreto real (por ejemplo, `0x7B`), la función compara el primer byte, pasa al segundo byte, nota la diferencia y aborta en tiempo $t_1 \approx 10.42 \, \mu\text{s}$.
2. **Mitigación del ruido de red:**
   Aunque la fluctuación de red (*jitter*) añada ruido, el atacante envía múltiples muestras para cada byte y aplica filtros estadísticos (promedios, medianas o histogramas de distribución). La diferencia temporal acumulada se vuelve estadísticamente visible y distinguible del ruido.
3. **Reconstrucción incremental del secreto:**
   Fijando el primer byte `0x7B`, el atacante repite el proceso para el segundo byte, luego para el tercero, y así sucesivamente.
4. **Colapso de la complejidad:**
   En lugar de afrontar una búsqueda exhaustiva inalcanzable de $256^{32} = 2^{256}$ operaciones, el atacante extrae la firma completa en apenas $256 \times 32 = 8192$ consultas. Una vez obtenido el MAC válido para un mensaje de su elección, compromete la autenticidad del sistema.

#### La solución: `hmac.compare_digest`
`hmac.compare_digest(esperado, recibido)` implementa una comparación en **tiempo constante**:
- Recorre invariablemente todos y cada uno de los bytes de la secuencia, acumulando las diferencias mediante operaciones binarias a nivel de bit (`result |= b1 ^ b2`).
- No existe ningún salto condicional ni interrupción prematura en función del contenido.
- El tiempo de ejecución depende exclusivamente de la longitud de las entradas y no de la posición del primer byte erróneo ni de cuántos bytes coinciden. Al neutralizar cualquier correlación entre el tiempo de respuesta y los datos secretos, la fuga de información por canal lateral queda completamente erradicada.

---

## 4. Bitácora

Comandos ejecutados en el entorno de trabajo y salidas verificadas:

```bash
# 1. Generación de los datos del reto
python data/generar_datos.py
# Salida:
# Creado data/muestra/reto_xor.hex — rompelo con: python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)

# 2. Contenido del reto cifrado (hexadecimal)
cat data/muestra/reto_xor.hex
# Salida:
# 7a525a58175e59435245595817675f565943585a745845470d175b5617545b5641521753525b17405e515e175352175e59415e435653584417524417675f565943585a1a70425244431a05070501191779581754585a475645435e45175142524556175352175b5617525a474552445619

# 3. Criptoanálisis de frecuencia sobre el reto XOR de 1 byte
python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
# Salida:
# clave=0x37
# Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

# 4. Prueba del subcomando XOR de referencia
python src/cripto.py xor --texto hola --clave K
# Salida:
# 2324272a

# 5. Cálculo de MAC ingenuo vs. HMAC-SHA256
python src/cripto.py mac --clave secreta --msg "pago 100" --modo ingenuo
# Salida:
# a8cc54c07b3acb7470c25ab9eea5234bfa2562e37298eee275e39a457004b725

python src/cripto.py mac --clave secreta --msg "pago 100" --modo hmac
# Salida:
# 5ec4a52407221836a66e8d654d914aaa4b18bd31cf31907348bcd292677b902e

# 6. Ejecución de la suite de autoevaluación oficial
python src/verificar.py
# Salida:
# == Lab 02 · Criptografía ==
#   ✓ romper_xor_1byte recupera clave y texto
#   ✓ mac_ingenuo = sha256(clave||msg)
#   ✓ mac_hmac = HMAC-SHA256
#   ✓ verificar_mac compara bien
# 
# 4 OK · 0 a revisar · 0 sin implementar
```

