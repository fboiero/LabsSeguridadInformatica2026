# Informe — Laboratorio 02 · Criptografía

**Grupo:** 10 · **Fecha de entrega:** 06/11/2026

**Integrantes:**
| Nombre y apellido      | Legajo | Usuario de GitHub |
| ---------------------- | ------ | ----------------- |
| Belén Rocío Ramello    | 15226  | @belramello       |
| Carolina Paula Corazza | 15239  | @carocor1         |
| Chiara Agustina Kordek | 14719  | @chiarakordek     |
| Juan Pablo Saby        | 15026  | @JuanSaby         |

## 0. Declaración de uso de IA
Se utilizó IA generativa (Claude) como herramienta de apoyo en este laboratorio: para planificar y repartir las tareas, supervisar redacción de borradores del código de src/cripto.py y de los textos del informe y del mini-research. El código se ejecutó y verificó contra el reto provisto por la cátedra.

Auditoría final, brinando un informe completo a los integrantes de la salida y los puntos modificados comparandolo con los requerimiento exigidos por la catedra.

## 1. Parte A — Análisis de la falla
**Caso:** WEP (Wired Equivalent Privacy, redes WiFi). Corresponde porque 10 mod 5 = 0.

### A.1 — Qué prometía

WEP buscaba proteger las comunicaciones inalámbricas frente a la escucha casual, controlar el acceso a la red y detectar cambios en los mensajes. Para eso cifraba cada trama con RC4 y adjuntaba un valor de integridad (ICV) calculado con CRC-32 [1][3].

### A.2 — El mal uso

El problema no fue simplemente “usar RC4”, sino cómo se lo empleó. Para cada paquete, WEP combinaba la clave compartida y estática con un IV público: un número que debía variar entre paquetes. Ese IV tenía solo 24 bits, así que había 2²⁴ —unos 16,7 millones— de valores posibles. Si se eligen al azar, alrededor de 5.000 paquetes ya dan cerca de un 50 % de probabilidad de que se repita alguno, por la paradoja del cumpleaños [1][3]. El IV viajaba visible en el encabezado y algunos equipos lo reiniciaban en cero o lo incrementaban de forma predecible [1].

La comprobación de integridad tampoco era criptográfica: CRC-32 está diseñado para detectar errores accidentales, no para autenticar mensajes frente a un atacante. Su linealidad permite calcular el cambio correspondiente en el CRC al modificar bits del contenido [1].

### A.3 — Propiedad rota y explotación

Cuando dos paquetes usan el mismo IV y la misma clave WEP, RC4 produce la misma secuencia de bytes para cifrarlos, llamada *keystream*. El cifrado combina esa secuencia con el mensaje mediante XOR. Si luego se aplica XOR entre los dos paquetes cifrados, la secuencia repetida se cancela y queda `C1 ⊕ C2 = P1 ⊕ P2`: el resultado combina los dos mensajes originales. No revela automáticamente los mensajes enteros, pero si el atacante conoce o adivina parte de uno, puede recuperar la parte correspondiente del otro [1].

El ataque de Fluhrer, Mantin y Shamir (FMS) aprovechó una debilidad en el arranque de RC4: algunos valores de IV hacen que los primeros bytes de la secuencia filtren pistas sobre bytes de la clave. Una pista aislada no alcanza; al reunir muchos paquetes con esos IV y combinar las pistas, se puede reconstruir la clave compartida [2]. Las técnicas posteriores mejoraron el proceso. En sus pruebas, Tews, Weinmann y Pyshkin recuperaron una clave WEP de 104 bits con menos de 40.000 tramas en el 50 % de los casos y con 85.000 en el 95 %; en una red 802.11g, la reinyección podía reunir las tramas en menos de un minuto [3]. Esos resultados dependen del escenario, no significan que toda red se rompa siempre en ese tiempo.

CRC-32 se parece a un control de errores: sirve para notar si los datos se dañaron por accidente, pero no prueba quién los envió. Como no usa una clave secreta y su cálculo es lineal, un atacante puede cambiar ciertos bits y calcular el CRC que corresponde a ese cambio; el receptor acepta así el paquete alterado [1]. En conjunto, las fallas rompieron la confidencialidad y la integridad y, al poder recuperarse la clave compartida, también el control de acceso a la red.

### A.4 — Cómo debió hacerse

El diseño debe evitar repetir un nonce/IV bajo la misma clave, derivar claves de sesión y usar cifrado autenticado: además de cifrar, el receptor verifica una etiqueta que depende de la clave secreta [1][4]. En WPA2, CCMP usa AES-CCM para cifrar y verificar la integridad; WPA3-Personal usa SAE para autenticar y AES-CCMP o AES-GCMP para proteger los datos [4][5]. TKIP fue una medida transitoria para equipos antiguos, no la solución de largo plazo [4].

### Fuentes

1. Borisov, N., Goldberg, I., & Wagner, D. (2001). *Intercepting Mobile Communications: The Insecurity of 802.11*. Proceedings of the 7th Annual International Conference on Mobile Computing and Networking (MobiCom ’01). https://www.cs.umd.edu/~waa/414-F11/Borisov2001_Insecure802_11.pdf
2. Fluhrer, S., Mantin, I., & Shamir, A. (2001). *Weaknesses in the Key Scheduling Algorithm of RC4*. Selected Areas in Cryptography (SAC 2001), Lecture Notes in Computer Science, 2259, 1–24. https://doi.org/10.1007/3-540-45537-X_1
3. Tews, E., Weinmann, R.-P., & Pyshkin, A. (2007). *Breaking 104 Bit WEP in Less Than 60 Seconds*. Cryptology ePrint Archive, Report 2007/120. https://eprint.iacr.org/2007/120.pdf
4. Frankel, S., Eydt, B., Owens, L., & Scarfone, K. (2007). *Establishing Wireless Robust Security Networks: A Guide to IEEE 802.11i* (NIST SP 800-97). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-97
5. National Security Agency. (2018). *WPA3 Will Enhance Wi-Fi Security*. Cybersecurity Report. https://www.nsa.gov/portals/75/documents/what-we-do/cybersecurity/professional-resources/ctr-cybersecurity-technical-report-wpa3.pdf

## 2. Parte B.1 — Romper el XOR
**Clave hallada:** `0x37` (55 en decimal).

**Mensaje en claro recuperado:**
> Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

**Cómo se rompió.** El cifrado usa XOR con una clave de un solo byte, es decir que existen apenas 256 claves posibles. La función `romper_xor_1byte` las prueba todas (de 0x00 a 0xFF), descifra el texto con cada una y le asigna un puntaje según qué tan parecido a lenguaje natural resulta: suma puntos por espacios y vocales (muy frecuentes en español e inglés), suma menos por otras letras, es neutral con la puntuación y resta fuerte por bytes de control o fuera de ASCII. La clave con mejor puntaje es la correcta.

**Por qué falla el cifrado clásico.** Una clave de 1 byte tiene un espacio de claves trivial (2^8 = 256) que se recorre por fuerza bruta en milisegundos. Además, XOR conserva la estructura estadística del texto plano (los espacios y las vocales siguen siendo reconocibles), así que se puede decidir automáticamente cuál clave es la buena. Un cifrado necesita un espacio de claves enorme y no filtrar estructura del mensaje, y su seguridad no puede depender de que el atacante desconozca el algoritmo (principio de Kerckhoffs).

## 3. Parte B.2 — Autenticación
### B.2.1 — Ataque de length-extension

SHA-256 sigue la construcción Merkle–Damgård [2]: el mensaje se rellena (*padding*) y se procesa en bloques de 512 bits, es decir, 64 bytes. El relleno agrega un bit en 1, luego ceros y, al final, la longitud del mensaje original como un entero de 64 bits [1]. Cada bloque actualiza un estado interno, y el resumen final es simplemente ese estado después de procesar el último bloque [1]. En otras palabras, el hash publicado *es* el estado interno de la función en ese punto.

Por eso, si un servidor usa `h = sha256(K || m)` como MAC, un atacante que conoce `h`, el mensaje `m` y la longitud de la clave `K` (pero no la clave) puede falsificar un MAC válido [2]:

1. Calcula el *padding* que la función agregó a `K || m`, para lo cual solo necesita la longitud total, no el contenido de `K`.
2. Usa `h` como estado inicial y continúa el cálculo del hash sobre un sufijo `s` elegido por él.
3. Obtiene un MAC válido para el mensaje `m || padding || s`, sin haber conocido nunca `K`.

**Ejemplo:** el servidor recibe `monto=100&destino=ana` junto con su MAC. El atacante construye `monto=100&destino=ana<padding>&destino=atacante` y calcula el MAC correspondiente a partir del original. Al recibirlo, el servidor recalcula `sha256(K || mensaje_extendido)`, obtiene exactamente ese valor y acepta el mensaje como auténtico. Si al procesar los parámetros toma el último valor de `destino`, la transferencia termina en la cuenta del atacante.

Hay dos detalles a tener en cuenta. Primero, el atacante necesita la longitud de `K` para calcular el *padding*; si no la conoce, puede probar con las longitudes posibles, que suelen ser pocas. Segundo, el mensaje falsificado contiene en el medio los bytes del *padding*, que el atacante no puede evitar [2].

El ataque no requiere romper SHA-256 ni encontrar colisiones: aprovecha la forma en que se construyó el MAC. El problema es un mal uso de la función, porque `sha256(clave || mensaje)` no es una construcción de MAC.

### B.2.2 — Cómo lo resuelve HMAC

HMAC, definido en el RFC 2104, aplica la función de hash dos veces con dos claves derivadas de `K` [3]:

```
HMAC(K, m) = H( (K ⊕ opad) || H( (K ⊕ ipad) || m ) )
```

`ipad` es el byte `0x36` repetido y `opad` el byte `0x5C` repetido, ambos con la longitud del bloque de la función (`B = 64` bytes para SHA-256). Si la clave es más corta que el bloque se completa con ceros, y si es más larga primero se hashea [3].

La estructura anidada es la que impide la extensión. El hash interno, `H((K ⊕ ipad) || m)`, produce un valor intermedio que nunca se publica. Lo único que ve el atacante es la salida del hash externo, que procesa ese valor intermedio después de un bloque que depende de otra clave derivada, `K ⊕ opad`. Para extender el mensaje, el atacante tendría que continuar el hash *interno*, cuyo estado no conoce; y continuar el hash externo a partir del resultado público no le sirve, porque eso no corresponde al MAC de ningún mensaje extendido. Por eso HMAC no es vulnerable a este ataque [2], aunque use internamente una función Merkle–Damgård como SHA-256.

Según el propio RFC 2104, la construcción fue presentada y analizada criptográficamente por Bellare, Canetti y Krawczyk en Crypto '96 [3].

### B.2.3 — Comparación en tiempo constante (timing attacks)

Un ataque de temporización aprovecha que un sistema tarda distinto tiempo según los datos que procesa, por ejemplo por optimizaciones que evitan operaciones innecesarias o por ramificaciones condicionales [5]. Comparar dos cadenas con `==` es un caso típico: la comparación se corta en el primer carácter distinto, así que el tiempo de respuesta crece con la cantidad de caracteres iniciales correctos.

**Ejemplo:** el servidor verifica un MAC HMAC-SHA256 de 64 caracteres hexadecimales (256 bits) comparándolo con `==`. El atacante envía un mensaje con un MAC inventado y prueba los 16 valores posibles del primer carácter (`0`–`9`, `a`–`f`). Mide cuánto tarda cada respuesta, repitiendo cada prueba muchas veces para promediar el ruido. El valor cuya respuesta tarda un poco más es el correcto, porque la comparación avanzó un carácter más. Fija ese carácter y repite el procedimiento con el segundo, y así sucesivamente. Cada posición cuesta como máximo 16 pruebas, así que en total son del orden de 64 × 16 = 1.024 pruebas (multiplicadas por las repeticiones necesarias), frente a las 16⁶⁴ combinaciones de la fuerza bruta. Al final obtiene un MAC válido sin conocer la clave.

`hmac.compare_digest` evita esta fuga porque no corta la comparación según el contenido: devuelve el mismo resultado que `a == b`, pero usa un método diseñado para impedir el análisis de tiempos [4]. Así, el tiempo no revela cuántos caracteres coinciden. Según la documentación, si las entradas tienen longitudes distintas el tiempo podría revelar sus tipos y longitudes, pero no sus valores [4]. Esto no es un problema para un MAC, porque su longitud es fija y pública.

En la práctica, el ruido de la red dificulta el ataque, pero no lo vuelve imposible. Crosby, Wallach y Riedi mostraron que, filtrando adecuadamente las mediciones, se pueden distinguir diferencias de 15 a 100 µs a través de Internet y de hasta 100 ns en una red local [6]. Kocher ya había advertido que los sistemas criptográficos en red están en riesgo cuando el atacante puede medir tiempos con precisión razonable [5]. Por eso, además de comparar en tiempo constante, conviene limitar la cantidad de intentos de verificación por cliente.

### Fuentes

1. Eastlake 3rd, D., & Hansen, T. (2011). *US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)* (RFC 6234). IETF. https://www.rfc-editor.org/rfc/rfc6234
2. Wikipedia. (s. f.). *Length extension attack*. Consultado el 5 de noviembre de 2026. https://en.wikipedia.org/wiki/Length_extension_attack
3. Krawczyk, H., Bellare, M., & Canetti, R. (1997). *HMAC: Keyed-Hashing for Message Authentication* (RFC 2104). IETF. https://www.rfc-editor.org/rfc/rfc2104
4. Python Software Foundation. (s. f.). *hmac — Keyed-Hashing for Message Authentication*. Documentación de Python 3. https://docs.python.org/3/library/hmac.html
5. Kocher, P. C. (1996). *Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems*. Advances in Cryptology — CRYPTO '96, LNCS 1109, 104–113. https://paulkocher.com/doc/TimingAttacks.pdf
6. Crosby, S. A., Wallach, D. S., & Riedi, R. H. (2009). *Opportunities and Limits of Remote Timing Attacks*. ACM Transactions on Information and System Security, 12(3), artículo 17. https://doi.org/10.1145/1455526.1455530

## 4. Bitácora

```bash
# 1. Generación de datos de prueba
python3 entregas/lab02/grupo10/data/generar_datos.py
# salida: Creado data/muestra/reto_xor.hex — rompelo con: python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)

# 2. Resolución del reto XOR (compatible con Bash / POSIX)
python3 entregas/lab02/grupo10/src/cripto.py romper --hex $(cat entregas/lab02/grupo10/data/muestra/reto_xor.hex)
# Nota: En entorno Windows PowerShell se ejecutó con:
# python entregas/lab02/grupo10/src/cripto.py romper --hex (Get-Content entregas/lab02/grupo10/data/muestra/reto_xor.hex -Raw).Trim()
# salida: clave=0x37
# salida: Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

# 3. Cálculo de MAC ingenuo
python3 entregas/lab02/grupo10/src/cripto.py mac --clave k --msg hola --modo ingenuo
# salida: bda2866001749f4665752d576d83d329f9f6c901b39b99976e2dd7fcbe271683

# 4. Cálculo de MAC con HMAC
python3 entregas/lab02/grupo10/src/cripto.py mac --clave k --msg hola --modo hmac
# salida: e3b409496f147c6a4ddb76add1750d9d63a8bbf752e745b81a0e23d5e0ede322
```
