# Entregable — Lab Extra 4: Cracking de contraseñas

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero
(@Ferca19), Guadalupe Gómez (@guadagomezgg8) y Lautaro Mariño
(@lautaromarino0) · **Fecha:** 19/11/2026 (America/Buenos_Aires)

## Declaración de uso de IA

Fernando Cagliero (@Ferca19) usó OpenAI Codex para preparar y revisar los
scripts de medición/cálculo, interpretar sus resultados y redactar P1/P4. Las
mediciones locales y el cálculo GPU están adjuntos; la cifra GPU es una
extrapolación declarada, no una corrida de cracking ni una medición con 1.000
GPU. No se usó IA para afirmar resultados de cracking que no se capturaron.

## 1. Tabla de resultados

Los resultados de operador, analista y admin, el contenido descifrado de los
`.enc` y el estado de las flags quedan pendientes de integración con quienes
ejecutaron el cracker. Para root, la consigna define una contraseña fuera del
diccionario de 49 candidatos: que no haya match en ese diccionario no demuestra
que la contraseña sea imposible de recuperar con otros candidatos o recursos.

| Usuario | Algoritmo | ¿Cayó? | Técnica | Contraseña | Tiempo aprox. |
|---|---|---|---|---|---|
| operador | MD5 | Pendiente de evidencia del cracker. | Pendiente. | No consignada. | Pendiente. |
| analista | SHA-256 | Pendiente de evidencia del cracker. | Pendiente. | No consignada. | Pendiente. |
| admin | SHA-256 | Pendiente de evidencia del cracker. | Pendiente. | No consignada. | Pendiente. |
| root | PBKDF2 | No aparece en el diccionario de 49 palabras indicado por el caso. | Búsqueda de diccionario, sin match esperado. | — | — |

## 2. Medición de velocidad (P1)

Medición de las primitivas con `hashlib` en AMD Ryzen 7 3700X, Python 3.12.2 y
Windows 11. Son tres repeticiones y se informa la mediana; la prueba no incluye
E/S, comparación de hashes ni overhead del cracker completo. Diccionario real:
49 entradas no vacías. Detalle reproducible:
[`medir_p1.py`](evidencia/medir_p1.py) y
[`medicion-p1-local.txt`](evidencia/salidas/medicion-p1-local.txt).

| Algoritmo | Intentos/s (CPU local) | Proyección para 49 candidatos |
|---|---:|---:|
| MD5(salt‖password) | 1.157.273 | 0,000042 s |
| SHA-256(salt‖password) | 873.897 | 0,000056 s |
| PBKDF2-HMAC-SHA256, 200.000 iteraciones | 8,89 | 5,510604 s |

En esta CPU, PBKDF2 reduce la tasa frente a MD5 aproximadamente 5,11 órdenes
de magnitud y frente a SHA-256 4,99. Eso aumenta el costo de cada candidato;
no vuelve imposible un ataque de diccionario. El ejemplo del enunciado de
10⁹ MD5/s es una tasa hipotética para GPU, no una medición de esta máquina. La
estimación GPU de P4 abajo muestra por separado una referencia RTX 4090 para
PBKDF2 y sus supuestos; las cifras no son una comparación controlada en la
misma GPU.

## 3. El loot

Pendiente de integrar las salidas del descifrado y el impacto por cuenta; no se
reconstruye contenido de `.enc` sin una salida observada.

## 4. Las flags

No se adjunta `ctf status extra4` ni se declaran flags del grupo en este bloque.
Pendiente de la corrida y captura de integración.

## 5. Preguntas P1–P5

**P1 — diferencia de costo.** La tabla anterior mide cerca de 5 órdenes de
magnitud entre los hashes rápidos y PBKDF2-200k en la misma CPU local. Con
10⁹ MD5/s del ejemplo del enunciado, un atacante puede probar candidatos
rápidamente; la derivación GPU de P4 sitúa una RTX 4090 alrededor de 44.284
intentos/s a 200.000 iteraciones, bajo una escala inversa ideal desde el dato
de 999 iteraciones. La comparación ilustrativa entre esas referencias ronda
4,35 órdenes, pero combina tasas de fuentes distintas y no reemplaza una
medición en la misma GPU.

**P2:** pendiente del bloque asignado.

**P3:** pendiente del bloque asignado.

**P4 — trabajo por intento y 1.000 GPUs.** Root no aparece porque su clave está
fuera del diccionario entregado; PBKDF2 aumenta el costo de cada candidato,
pero el motivo observado de que no haya match aquí es el espacio de candidatos.
El [benchmark publicado para Hashcat y RTX 4090](https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd)
reporta 8.865,7 kH/s en PBKDF2-HMAC-SHA256 con 999 iteraciones (modo 10900).
Escalando idealmente en proporción inversa a las iteraciones, da
8.865.700 × 999 / 200.000 = **44.284 intentos/s por GPU**. El
[módulo oficial de Hashcat para el modo 10900](https://github.com/hashcat/hashcat/blob/master/src/modules/module_10900.c)
identifica la función medida. La escala inversa es una aproximación y no una
medición directa a 200.000 iteraciones.

Con 49 candidatos y 1.000 GPU, como máximo 49 GPU trabajan en paralelo en ese
lote. El tiempo ideal de un lote es aproximadamente 1 / 44.284 s =
**22,58 μs**, antes de planificación, transferencia e inicialización; las
951 GPU restantes no reducen el tiempo por debajo de la latencia por intento.
En una sola GPU, los 49 candidatos serían aproximadamente 0,001106 s. No se
ejecutó el lote en GPU: es una proyección teórica reproducible en
[`calcular_p4_gpu.py`](evidencia/calcular_p4_gpu.py) y
[`calculo-p4-1000-gpus.txt`](evidencia/salidas/calculo-p4-1000-gpus.txt).

**P5:** pendiente del bloque asignado.

## 6. Conclusión

Pendiente de integración grupal.
