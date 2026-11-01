# Entregable — Lab Extra 4: Cracking de contraseñas

**Grupo:** 10 · **Integrantes:**
- Saby, Juan Pablo
- Belén
- Chiara
- Carolina

**Declaración de uso de IA:**
- **Herramienta utilizada:** Antigravity / Asistente de IA (Gemini).
- **Alcance y propósito del uso:** Asistencia en la planificación técnica, auditoría de requerimientos y desarrollo del núcleo algorítmico en Python estándar (`src/cracker.py`: implementación de `hash_de`, `cargar_sombra`, `aplicar_reglas`, `crackear` y captura de `KeyboardInterrupt`).
- **Partes originadas o modificadas con asistencia de IA:** El código fuente inicial de las funciones en `entregas/labextra4/grupo10/src/cracker.py` y la estructura base del presente informe.
- **Método de verificación humana y técnica:**
  1. Compilación estricta de sintaxis con `python -m py_compile`.
  2. Verificación de resolución de importación modular del paquete (`from src.cracker import ...`).
  3. Ejecución de un banco de pruebas unitarias sintéticas independientes comprobando:
     - Exactitud de los digests de `hash_de()` contra `hashlib` para MD5, SHA-256 y PBKDF2 (200.000 iteraciones).
     - Validación de excepciones `ValueError` ante registros malformados en `cargar_sombra()`.
     - Deduplicación determinista y generación ordenada de variantes en `aplicar_reglas()`.
     - Involutividad del descifrado XOR en `descifrar_loot()`.
     - Comportamiento de búsqueda exhaustiva y captura limpia de interrupción manual en `crackear()`.

---

## 1. Tabla de resultados

*(A completar por Carolina tras la ejecución de las pruebas)*

| Usuario | Algoritmo | ¿Cayó? | Técnica (diccionario / regla: cuál) | Contraseña | Tiempo aprox. |
|---|---|---|---|---|---|
| operador | md5 | | | | |
| analista | sha256 | | | | |
| admin | sha256 | | | | |
| root | pbkdf2 | | — | — | — |

## 2. Medición de velocidad (P1)

*(A completar por Chiara a partir de los datos empíricos del benchmark independiente `tests/benchmark_p1.py`)*

| Algoritmo | Intentos/segundo (tu máquina) | Diccionario completo tardaría… |
|---|---|---|
| md5 | | |
| sha256 | | |
| pbkdf2-200k | | |

## 3. El loot

*(A completar por Carolina con la salida del descifrado de cada archivo `.enc` y el análisis de impacto corporativo)*

## 4. Las flags

*(A completar por Carolina con la captura y verificación de `./ctf status extra4`)*

## 5. Preguntas P1–P5

*(A completar por Carolina)*

- **P1 (Órdenes de magnitud y GPU):**
- **P2 (Propósito y límites del Salt):**
- **P3 (Políticas de contraseñas y NIST SP 800-63B):**
- **P4 (Trabajo por intento y resistencia de PBKDF2):**
- **P5 (Respuesta a incidentes y almacenamiento defensivo en PhantomCorp):**

## 6. Conclusión

*(A redactar por el grupo según lineamientos defensivos)*
