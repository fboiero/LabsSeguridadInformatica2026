# Lab Extra 4 — resultados del benchmark P1

## Condiciones

- Python 3.12.14, Windows 11 (`Windows-11-10.0.26200-SP0`), CPU informada por Python: AMD64 Family 23 Model 104 Stepping 1, AuthenticAMD.
- El benchmark llama a `hash_de()` de `src/cracker.py` sin modificar ese archivo.
- Salt sintético fijo de 16 bytes (`a4` repetido 16 veces), igual para ambos conjuntos y los tres algoritmos.
- Cada conjunto tiene exactamente 20 candidatos únicos sintéticos: una lista pura y 20 variantes generadas con una regla de sufijo de año.
- MD5 y SHA-256 repiten la muestra 1.000 veces (20.000 evaluaciones) para reducir el error del cronómetro; PBKDF2 procesa cada candidato una sola vez: exactamente 20 evaluaciones por conjunto, con 200.000 iteraciones.
- Medición con `time.perf_counter()`, sin warm-up. No se usaron datos del caso ni se realizó una búsqueda exhaustiva.
- Salida completa: `evidencia/salidas/benchmark_p1.txt`.

## Resultados observados

| Algoritmo | Diccionario puro | Con regla de año |
|---|---:|---:|
| MD5 | 480.951,900 evaluaciones/s; 20.000 evaluaciones en 0,041584 s | 432.146,515 evaluaciones/s; 20.000 en 0,046281 s |
| SHA-256 | 403.887,824 evaluaciones/s; 20.000 evaluaciones en 0,049519 s | 427.196,162 evaluaciones/s; 20.000 en 0,046817 s |
| PBKDF2-HMAC-SHA-256 (200.000 iteraciones) | 8,931 evaluaciones/s; 20 candidatos en 2,239444 s | 7,127 evaluaciones/s; 20 candidatos en 2,806122 s |

El diccionario de práctica del laboratorio contiene 49 entradas. Si se usa la tasa sintética rápida como una estimación aritmética para ese listado, MD5 tardaría aproximadamente 0,000102 s y SHA-256 0,000121 s. Son estimaciones, no mediciones del cracker sobre el diccionario real. **No se estima el tiempo de PBKDF2 para el diccionario completo**: la consigna limita esta prueba a una muestra controlada de 20 candidatos y prohíbe extrapolarla a una búsqueda exhaustiva o a una contraseña real.

## Interpretación y límites

En esta ejecución, la tasa de MD5 y SHA-256 fue del orden de 10^5 evaluaciones por segundo en esta implementación y equipo; PBKDF2 quedó entre 7 y 9 evaluaciones por segundo con 200.000 iteraciones. La comparación representa solo esta máquina, versión de Python, función de la biblioteca y pequeña muestra. No describe el rendimiento de una GPU.

La variación de tiempo entre los dos conjuntos PBKDF2 no demuestra que las reglas hagan más lento cada hash: son listas diferentes y se midieron una sola vez; ambas realizaron 20 derivaciones con los mismos parámetros. El resultado es una muestra controlada, no una búsqueda exhaustiva.

Para reproducir desde la raíz del repositorio: `python entregas/labextra4/grupo10/tests/benchmark_p1.py`.
