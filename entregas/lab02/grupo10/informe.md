# Informe — Laboratorio 02 · Criptografía

**Grupo:** 10 · **Integrantes:** *(CORAZZA, CAROLINA - KORDEK, CHIARA - RAMELLO, BELÉN - SABY, JUAN PABLO)* · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA
Se utilizó IA generativa (Claude) como herramienta de apoyo en este laboratorio: para planificar y repartir las tareas, supervisar redacción de borradores del código de `src/cripto.py` y de los textos del informe y del mini-research. El código se ejecutó y verificó contra el reto provisto por la cátedra. Los integrantes revisaron el contenido entregado.
## 1. Parte A — Análisis de la falla
<!-- INICIO SECCION 1 -->
**Caso:** *(el asignado)*
**A.1 — Qué prometía · A.2 — El mal uso · A.3 — Propiedad rota y explotación · A.4 — Lo correcto**

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
