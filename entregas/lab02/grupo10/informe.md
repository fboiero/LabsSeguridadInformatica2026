# Informe — Laboratorio 02 · Criptografía

**Grupo:** 10 · **Integrantes:** *(CORAZZA, CAROLINA - KORDEK, CHIARA - RAMELLO, BELÉN - SABY, JUAN PABLO)* · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA
Se utilizó IA generativa (Claude) como herramienta de apoyo en este laboratorio: para planificar y repartir las tareas, supervisar redacción de borradores del código de `src/cripto.py` y de los textos del informe y del mini-research. El código se ejecutó y verificó contra el reto provisto por la cátedra.

## 1. Parte A — Análisis de la falla <!-- INICIO SECCION 1 -->
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

<!-- FIN SECCION 1 -->
## 2. Parte B.1 — Romper el XOR
<!-- INICIO SECCION 2 -->
**Clave hallada:** `0x37` (55 en decimal).

**Mensaje en claro recuperado:**
> Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

**Cómo se rompió.** El cifrado usa XOR con una clave de un solo byte, es decir que existen apenas 256 claves posibles. La función `romper_xor_1byte` las prueba todas (de 0x00 a 0xFF), descifra el texto con cada una y le asigna un puntaje según qué tan parecido a lenguaje natural resulta: suma puntos por espacios y vocales (muy frecuentes en español e inglés), suma menos por otras letras, es neutral con la puntuación y resta fuerte por bytes de control o fuera de ASCII. La clave con mejor puntaje es la correcta.

**Por qué falla el cifrado clásico.** Una clave de 1 byte tiene un espacio de claves trivial (2^8 = 256) que se recorre por fuerza bruta en milisegundos. Además, XOR conserva la estructura estadística del texto plano (los espacios y las vocales siguen siendo reconocibles), así que se puede decidir automáticamente cuál clave es la buena. Un cifrado necesita un espacio de claves enorme y no filtrar estructura del mensaje, y su seguridad no puede depender de que el atacante desconozca el algoritmo (principio de Kerckhoffs).

<!-- FIN SECCION 2 -->
## 3. Parte B.2 — Autenticación
<!-- INICIO SECCION 3 -->
**B.2.1 length-extension · B.2.2 cómo lo resuelve HMAC · B.2.3 tiempo constante**

<!-- FIN SECCION 3 -->
## 4. Bitácora
<!-- INICIO SECCION 4 -->
```bash
python entregas/lab02/grupo10/data/generar_datos.py
# salida: Creado data/muestra/reto_xor.hex — rompelo con: python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)

python entregas/lab02/grupo10/src/cripto.py romper --hex (Get-Content entregas/lab02/grupo10/data/muestra/reto_xor.hex -Raw).Trim()
# salida: clave=0x37
# salida: Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

python entregas/lab02/grupo10/src/cripto.py mac --clave k --msg hola --modo ingenuo
# salida: bda2866001749f4665752d576d83d329f9f6c901b39b99976e2dd7fcbe271683

python entregas/lab02/grupo10/src/cripto.py mac --clave k --msg hola --modo hmac
# salida: e3b409496f147c6a4ddb76add1750d9d63a8bbf752e745b81a0e23d5e0ede322
```
<!-- FIN SECCION 4 -->
