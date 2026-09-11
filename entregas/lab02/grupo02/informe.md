# Informe — Laboratorio 02 · Criptografía

**Grupo:** 02 · **Integrantes:** *(vos — usuario GitHub), (tu compañera — usuario GitHub)* · **Fecha:** 2026-09-04

## 0. Declaración de uso de IA

Se utilizó un asistente de IA (Claude) como apoyo para: comprender los
conceptos criptográficos del lab (length-extension, HMAC, ataques de
temporización), orientar la implementación de las funciones en `cripto.py`,
y revisar la redacción del informe. El código y las respuestas fueron
verificados y ejecutados por el grupo antes de la entrega. La comprensión
final de los contenidos es responsabilidad de los integrantes.

## 1. Parte A — Análisis de la falla
**Caso:** Sony PS3 (ECDSA) — reutilización del nonce k al firmar

**A.1 — Qué prometía**

La PS3 implementaba una cadena de confianza (chain of trust) con ejecutables firmados y un hipervisor, cuyo objetivo era que la consola sólo ejecutara código autorizado por Sony. El esquema de firma usado era ECDSA (Elliptic Curve Digital Signature Algorithm): la promesa criptográfica era autenticidad e integridad, que sólo Sony pudiera producir código que la consola aceptara como legítimo, y que nadie pudiera falsificar una firma válida sin conocer la clave privada de Sony.

**A.2 — El mal uso**

El algoritmo ECDSA no estaba roto sino que presentaba un fallo en la implementación. Cada firma ECDSA requiere un número aleatorio k (el "nonce") que debe ser distinto en cada firma. Sony reutilizó siempre el mismo valor de k para firmar, en vez de generarlo aleatoriamente cada vez. La falla crítica fue que un parámetro que debía ser aleatorizado en cada generación de clave no se aleatorizó en absoluto, algo que la propia documentación de ECDSA advierte explícitamente.
Es crucial elegir un k distinto para cada firma, de lo contrario la ecuación puede resolverse para obtener la clave privada. La reutilización de nonce en ECDSA revela la clave privada directamente porque dos firmas que comparten el mismo valor r exponen k algebraicamente; no se necesita ninguna suposición de dificultad computacional, es álgebra pura que se completa en microsegundos. Esto le permitió a GeoHot (George Hotz) publicar la clave raíz de la PS3, que puede usarse para firmar cualquier código y hacerlo aparecer como firmado por Sony, lo que rompió por completo el control de Sony sobre qué software podía ejecutarse en la consola.

**A.3 — Propiedad comprometida y cómo se explotó**

La propiedad que se rompió fue la **autenticidad** del firmware (y, como consecuencia, su integridad). ECDSA le permite a Sony firmar cada firmware/software oficial con su clave privada, de modo que la consola pueda verificar —usando la clave pública de Sony— que ese código efectivamente proviene de Sony y no fue modificado. Si la firma se compromete, deja de haber forma de distinguir código oficial de código falsificado: cualquiera que consiga la clave privada puede firmar su propio software y la PS3 lo va a aceptar como legítimo.

El mecanismo de la explotación fue el siguiente:

1. ECDSA exige que en cada firma se use un número aleatorio distinto llamado *nonce* (k), generado de forma impredecible.
2. Sony implementó mal el algoritmo y usaba **siempre el mismo valor de k** para firmar todos los mensajes, en lugar de generar uno nuevo cada vez.
3. El grupo fail0verflow, en 2010, analizó varias firmas oficiales de Sony y detectó que provenían del mismo k.
4. Con dos firmas distintas (de dos mensajes distintos) generadas con el mismo k, es posible plantear un sistema de ecuaciones y despejar algebraicamente la clave privada de Sony.
5. Con la clave privada obtenida, fail0verflow pudo firmar cualquier código propio (homebrew, jailbreaks, firmwares modificados) y la PS3 lo aceptaba como si fuera software oficial de Sony.

La idea central es que reutilizar el nonce en ECDSA dos veces equivale, matemáticamente, a exponer la clave privada. El algoritmo ECDSA en sí no fue roto ni tiene una debilidad matemática: lo que falló fue la implementación de Sony, que violó un requisito no negociable del esquema de firma.

**Fuente:** fail0verflow, "Console Hacking 2010: PS3 Epic Fail" (27C3, 2010).

**A.4 — Forma correcta**

El nonce k debe generarse de manera aleatoria y criptográficamente segura (usando un CSPRNG) en cada operación de firma, sin reutilizarlo nunca ni derivarlo de forma predecible. Como alternativa más robusta, se puede usar ECDSA determinístico (RFC 6979), que deriva k de manera segura y reproducible a partir del mensaje y la clave privada, eliminando la dependencia de un generador aleatorio externo y evitando así este tipo de fallo por implementación.

## 2. Parte B.1 — Romper el XOR

Para esta parte se implementó y ejecutó la función `romper_xor_1byte()`, cuyo objetivo es recuperar el texto original de un mensaje cifrado mediante XOR con una clave de un solo byte.

El procedimiento consiste en probar las **256 claves posibles** que puede representar un byte, desde `0x00` hasta `0xff`. Para cada una de ellas se aplica nuevamente XOR sobre el texto cifrado, aprovechando que XOR es una operación involutiva: si se aplica la misma clave utilizada para cifrar, se recupera el texto original.

Luego, cada texto candidato se evalúa mediante un criterio simple de frecuencia de caracteres. Se asigna un puntaje según la cantidad de bytes que corresponden a caracteres frecuentes en lenguaje natural, principalmente espacios, letras comunes, vocales y letras mayúsculas. Finalmente, se selecciona como resultado la clave cuyo texto candidato obtiene el mayor puntaje.

La ejecución se realizó mediante:

```bash
python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
```

En Windows PowerShell, el equivalente utilizado fue:

```powershell
python entregas\lab02\grupo02\src\cripto.py romper --hex "$(Get-Content data\muestra\reto_xor.hex)"
```

El programa recuperó la siguiente clave:

```text
clave=0x37
```

Y el texto claro obtenido fue:

```text
Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.
```

### Resultado y conclusión

El ataque permitió recuperar correctamente el contenido del mensaje probando únicamente **256 posibilidades**, lo que demuestra que una clave XOR de un solo byte ofrece un espacio de búsqueda extremadamente pequeño.

Aunque XOR puede ser seguro cuando se utiliza correctamente, por ejemplo con una clave aleatoria del mismo tamaño que el mensaje y sin reutilizarla, utilizar una clave de un solo byte repetida hace que el cifrado sea trivialmente vulnerable a fuerza bruta. Además, el análisis de frecuencia permite identificar rápidamente cuál de los 256 resultados tiene mayor probabilidad de corresponder a lenguaje natural.

Por lo tanto, la principal lección de este ejercicio es que **la longitud y la aleatoriedad de la clave son fundamentales para la seguridad de un cifrado**. Un espacio de claves demasiado pequeño permite recorrer todas las posibilidades en un tiempo prácticamente inmediato.


## 3. Parte B.2 — Autenticación

Se implementaron tres funciones en `cripto.py`: `mac_ingenuo()` (la forma
insegura), `mac_hmac()` (la forma correcta) y `verificar_mac()` (comparación en
tiempo constante).

**B.2.1 — Por qué `sha256(clave || mensaje)` permite length-extension**

SHA-256 usa la construcción Merkle-Damgård: procesa el mensaje en bloques y el
digest final *es* su estado interno al terminar. Esto tiene una consecuencia
grave para una MAC construida como `sha256(clave || mensaje)`: quien conoce ese
digest conoce el estado interno de la función en ese punto, y puede **seguir
hasheando desde ahí** como si el cómputo no hubiera terminado.

Un atacante que observa un mensaje y su MAC, **sin conocer la clave**, puede
calcular un MAC válido para `clave || mensaje || padding || datos_extra`. Es
decir, puede **anexar datos y producir un tag válido** para la versión extendida.
Ejemplo: si el mensaje era `usuario=juan&monto=100` con su MAC, el atacante puede
generar un MAC válido para `usuario=juan&monto=100&admin=true` sin saber la clave.
La falla no está en SHA-256, sino en usarlo directamente como MAC.

**B.2.2 — Cómo lo resuelve HMAC**

HMAC (RFC 2104) no concatena la clave y hashea una vez, sino que aplica dos
hashes anidados con dos paddings distintos:

    HMAC(K, m) = H( (K ⊕ opad) || H( (K ⊕ ipad) || m ) )

El hash interno queda **envuelto** por el externo. El valor que se expone es la
salida del hash externo, no el estado interno "crudo" que el ataque de
length-extension necesitaría. Para extenderlo haría falta la clave, que está
incorporada en el hash externo. Por eso HMAC es seguro estructuralmente, con
independencia de la función de hash que use por debajo.

**B.2.3 — Qué ataque evita comparar en tiempo constante**

Comparar tags con `==` es vulnerable a un **ataque de temporización (timing)**.
El operador `==` compara byte a byte y **corta apenas encuentra una diferencia**,
así que tarda un poco más cuanto más bytes coinciden desde el inicio. Un atacante
que mide el tiempo de respuesta explota esto: prueba tags variando el primer byte
hasta detectar el que tarda un poco más (acertó ese byte), luego el segundo, y
así reconstruye el tag válido **byte a byte** — convirtiendo un problema inviable
(adivinar 32 bytes de golpe) en uno lineal.

`hmac.compare_digest()` compara **siempre todos los bytes**, sin cortar antes, de
modo que el tiempo no depende de cuántos coincidieron. Lo verificamos
empíricamente: con una comparación ingenua, un tag que difiere en el primer byte
tardó ~4 ms y uno que coincidía en 500 bytes tardó ~170 ms; con
`hmac.compare_digest()` ambos casos rondaron los 14 ms, sin diferencia
apreciable. Ejemplo concreto del riesgo: una API que valida firmas de webhooks
con `==` podría permitir que un atacante, midiendo latencias, forje una firma
válida; con `compare_digest()` esa fuga desaparece.

## 4. Bitácora

```bash
# Preparación del entorno
python3 data/generar_datos.py
python3 src/cripto.py xor --texto hola --clave K

# B.1 — Romper el cifrado XOR de 1 byte
python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
# → clave=0x37
# → "Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026..."

# B.2 — Calcular MAC de un mensaje
python3 src/cripto.py mac --clave secreta --msg "pago 100" --modo hmac
# → 5ec4a52407221836a66e8d654d914aaa4b18bd31cf31907348bcd292677b902e

python3 src/cripto.py mac --clave secreta --msg "pago 100" --modo ingenuo
# → a8cc54c07b3acb7470c25ab9eea5234bfa2562e37298eee275e39a457004b725
```

