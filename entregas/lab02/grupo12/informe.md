# Informe — Laboratorio 02 · Criptografía

**Grupo:** 12 · **Integrantes:** Gerbaudo, Mateo (14157 — @gerbaudo19), Mariatti, Matias (13293 — @matiasmariatticasc), Colque Condo, Luis Alvaro (14994 — @ColqueAlvaro), Rodriguez, Gonzalo (15310 — @Gonza149) · **Fecha:** 2026-05-11

**Caso Parte A:** Sony PS3 (ECDSA) — reutilización del nonce `k` (#2)

## 0. Declaración de uso de IA
 
 *Herramienta:* Muse Spark (OpenCode) y Gemini (Antigravity).
 *Uso:* Redacción de Parte A (§1) a partir de fuentes primarias (Mateo), generación de código en `cripto.py` para fuerza bruta sobre XOR (Matías), y redacción técnica de B.2.1 junto con la implementación de `mac_ingenuo()` (Álvaro).
 *Partes afectadas:* Informe (Sección 1 por @gerbaudo19, Sección 2 y código XOR por @matiasmariatticasc, Sección 3.1 y `mac_ingenuo` por @ColqueAlvaro).
 *Verificación:* Se verificaron las fórmulas contra RFC 6979. Para la Parte B.1, se ejecutó localmente el script verificando que la clave `0x37` y el mensaje del Memo fueran correctos. Para la Parte B.2.1, se verificó el cálculo de `mac_ingenuo()` contra la salida de `hashlib.sha256` y se validó el modelo teórico del ataque de extensión de longitud sobre la construcción Merkle-Damgård.

## 1. Parte A — Análisis de la falla: Sony PS3 y ECDSA

### A.1 — Qué prometía el sistema

La PS3 implementaba una cadena de confianza basada en ECDSA (curva P-256): solo Sony, poseedor de la clave privada `d`, podía firmar ejecutables (`EBOOT.BIN`), firmwares y loaders. La consola verificaba cada binario con la clave pública correspondiente y rechazaba todo lo no firmado. La propiedad garantizada era **autenticidad e integridad del código**: el usuario tenía la garantía de que el código ejecutado provenía de Sony y no había sido modificado [1][3].

### A.2 — Cuál fue el mal uso concreto

La falla no estaba en ECDSA como algoritmo, sino en su uso. En ECDSA cada firma `(r,s)` de un mensaje `m` requiere un nonce `k` único, secreto y nunca reutilizado:

```
k aleatorio en [1, n-1]
r = (k·G)_x mod n
s = k⁻¹(H(m) + d·r) mod n
```

Sony generó `k` de forma estática/constante para todas las firmas, en lugar de aleatorio por firma o determinístico por mensaje [1]. El equipo fail0verflow lo detectó en el CCC 27C3 (2010) al observar que `r` se repetía idéntico en firmas de binarios distintos: si `k` se repite, `r` se repite [1]. Un sistema seguro debe generar `k` con un CSPRNG (`secrets` en Python) o mejor determinísticamente con `RFC 6979 HMAC(k,d,H(m))` [2]; Sony no hizo ninguno.

Este es el error clásico que distingue "algoritmo roto" de "uso roto": ECDSA seguía siendo seguro, pero su condición de seguridad más básica fue violada.

### A.3 — Qué propiedad se rompió y cómo se explotó

Se rompió la **autenticidad** (y con ella la integridad autorizada): al conocer `k` reutilizado, un atacante recupera la clave privada `d` de Sony y puede firmar cualquier código como si fuera Sony.

Explotación concreta con dos firmas distintas `(r,s1)` y `(r,s2)` sobre mensajes `m1,m2` con el mismo `k` y mismo `r`:

```
k = (H(m1) - H(m2)) · (s1 - s2)⁻¹ mod n
d = (s·k - H(m)) · r⁻¹ mod n
```

Con `d` obtenida, el atacante firma su propio `EBOOT.BIN` o custom firmware y la PS3 lo acepta como legítimo. De ahí el "PS3 Epic Fail": jailbreak permanente, carga de Linux y homebrew sin necesidad de exploit de hardware, demostrado por fail0verflow y popularizado por Geohot en enero de 2011 [1][3]. La confidencialidad del sistema también colapsa indirectamente, porque el control de acceso entero dependía de esa firma.

### A.4 — La forma correcta de haberlo hecho

Sony debió generar `k` único e impredecible por cada firma, ya sea con un generador criptográficamente seguro (CSPRNG) con suficiente entropía, o preferentemente de forma determinística según **RFC 6979** (`k = HMAC-DRBG(d, H(m))`), que deriva `k` de la clave privada y el hash del mensaje sin estado aleatorio [2]. Con `k` distinto por mensaje, `r` nunca se repite y la deducción de `d` es computacionalmente inviable. Una línea de defensa adicional es validar en tests que `r` no se repita entre firmas.

### 1.5 Fuentes

[1] fail0verflow — "Console Hacking 2010 — PS3 Epic Fail", 27th Chaos Communication Congress (27C3), Berlín, 29-dic-2010. Slides y video en media.ccc.de. Demostración de `r` constante y recuperación de clave privada de Sony.
[2] NIST FIPS PUB 186-4 §4.2 / IETF RFC 6979 (Pornin, 2013) — Deterministic Usage of DSA and ECDSA. Especifica generación de `k` y requisito de unicidad; explica construcción `k = HMAC(d, H(m))`.
[3] N. Piotrowski et al. / Geohot — análisis público enero 2011 de la cadena de confianza PS3 (bootldr → lv0 → lv2) y publicación de clave privada ECDSA de Sony tras el fallo, citado en cobertura técnica de la época.

## 2. Parte B.1 — Romper el XOR

**Comando de ejecución:**
```bash
python src/cripto.py romper --hex (cat data/muestra/reto_xor.hex)
```

**Salida obtenida:**
```text
clave=0x37
Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.
```

**Análisis:**
El cifrado XOR con una clave de un solo byte (8 bits) es completamente inseguro porque el espacio de claves es minúsculo (solo 256 combinaciones posibles). Esto permite realizar un ataque de fuerza bruta exhaustivo en fracciones de segundo. Al iterar sobre las 256 claves, descifrar el texto y pasarle una función de "scoring" que cuenta los caracteres más frecuentes en el lenguaje natural (espacios, vocales, letras comunes como n, s, r, l), el algoritmo puede deducir instantáneamente cuál es el texto plano correcto y, por ende, la clave utilizada.

## 3. Parte B.2 — Autenticación

### B.2.1 — Ataque de Length-Extension sobre `sha256(clave || mensaje)`

#### ¿Por qué permite un ataque de length-extension?
La vulnerabilidad se debe directamente a la arquitectura de las funciones de hash basadas en la **construcción Merkle-Damgård**, como SHA-256:

1. **Estructura iterativa y estado interno:**
   SHA-256 divide el mensaje de entrada en bloques fijos de 512 bits (64 bytes). Mantiene un estado interno de 256 bits compuesto por 8 registros de 32 bits ($H_0, H_1, \dots, H_7$), los cuales se inicializan con constantes fijas estandarizadas (el vector de inicialización o IV).
2. **Función de compresión:**
   Cada bloque $M_i$ es procesado junto con el estado acumulado mediante una función de compresión $f$, de modo que el estado subsiguiente es $S_i = f(S_{i-1}, M_i)$.
3. **Esquema de relleno (padding):**
   Al final de la entrada se agrega un byte `0x80` (bit `1`), una secuencia de ceros (`0x00`) y finalmente un entero de 64 bits que codifica la longitud total del mensaje original en bits, redondeando la longitud a un múltiplo exacto de 512 bits.
4. **Digest final como reflejo del estado interno:**
   El resultado final del hash devuelto por SHA-256 **es exactamente el estado interno de los registros tras procesar el último bloque acolchado**. No existe ninguna transformación secreta posterior ni truncamiento protector.

Por ende, si se define una MAC de forma ingenua como:
$$\text{MAC} = \text{SHA-256}(clave \parallel mensaje)$$
el atacante que intercepta el mensaje y el hash resultante está recibiendo en bandeja el estado interno completo de la función de compresión tras haber procesado $(clave \parallel mensaje \parallel pad_1)$.

#### ¿Cómo opera el ataque sin conocer la clave?
Un atacante que intercepta el mensaje legítimo $M$ y su supuesto MAC $H = \text{SHA-256}(K \parallel M)$:

1. **No necesita la clave $K$, solo su longitud:** Aunque desconozca los bytes de la clave secreta $K$, basta con que conozca o estime su longitud $|K|$ (fácilmente determinable si es fija por especificación, ej. 16 o 32 bytes, o deducible mediante unas pocas pruebas).
2. **Reconstruye el relleno original ($pad_1$):** Conociendo $|K|$ y la longitud del mensaje interceptado $|M|$, el atacante calcula matemáticamente el relleno exacto $pad_1$ que aplicó la víctima en su cálculo original.
3. **Reanuda la compresión desde el estado interceptado:** Descompone el hash interceptado $H$ en los 8 registros de 32 bits e inicializa con ellos los registros internos de SHA-256 (reemplazando el IV estándar).
4. **Calcula la extensión:** A partir de ese estado intermedio, el atacante alimenta a la función de compresión los bytes arbitrarios adicionales que desea añadir ($M_{\text{extra}}$) junto con el nuevo padding final $pad_2$.
5. **Resultado:** El nuevo hash obtenido es matemáticamente idéntico a:
   $$H' = \text{SHA-256}(K \parallel M \parallel pad_1 \parallel M_{\text{extra}})$$
   El atacante genera así una firma perfectamente válida para el mensaje extendido $(M \parallel pad_1 \parallel M_{\text{extra}})$ sin haber sabido jamás la clave $K$.

#### ¿Qué podría falsificar un atacante sin conocer la clave? (Ejemplo concreto)
Supongamos un servicio que recibe peticiones estructuradas (por ejemplo, parámetros URL, query strings o transacciones) autenticadas con esta construcción ingenua:

- **Mensaje original:** `accion=transferir&monto=100&para=juan`
- **MAC legítimo generado por el cliente:** `sha256(clave_secreta || "accion=transferir&monto=100&para=juan")`

Un atacante en la red intercepta este paquete. Sin conocer `clave_secreta`:
1. Calcula el relleno $pad_1$ correspondiente a la longitud de `clave_secreta || msg`.
2. Define los datos a inyectar al final: `&para=atacante&monto=100000`.
3. Inicia SHA-256 con el estado obtenido del MAC interceptado y calcula el hash de la extensión.
4. Envía al servidor la carga maliciosa:
   `accion=transferir&monto=100&para=juan<pad1>&para=atacante&monto=100000`
   junto con el nuevo hash falsificado.

**Impacto:** Cuando el servidor recibe la solicitud, computa `sha256(clave_secreta || mensaje_recibido)`. Como la concatenación coincide byte a byte con lo procesado por el atacante, la validación de la MAC es **exitosa**. La gran mayoría de los analizadores de parámetros (parsers HTTP/query strings) toman el **último** valor recibido para claves duplicadas, por lo que el servidor ejecuta la transferencia a favor del atacante por un monto de $100.000, vulnerando por completo la autenticidad y la integridad de los datos.

---

*(A cargo de P4: Gonzalo)*
**B.2.2 cómo lo resuelve HMAC · B.2.3 tiempo constante**

## 4. Bitácora

```bash
# Parte A no requiere ejecución - análisis documental con fuentes [1][2][3]
# Verificación de Parte B:
# cd entregas/lab02/grupo12
# python data/generar_datos.py
# python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
# B.2.1 - Ejecución mac_ingenuo (Álvaro):
# python src/cripto.py mac --clave secreta --msg "pago 100" --modo ingenuo
# Salida esperada: a8cc54c07b3acb7470c25ab9eea5234bfa2562e37298eee275e39a457004b725
# (Pendiente para P4: modo hmac y verificación)
# python src/cripto.py mac --clave secreta --msg "pago 100" --modo hmac
```
