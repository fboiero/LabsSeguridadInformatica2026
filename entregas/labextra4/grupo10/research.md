# Research — Laboratorio Extra 4: Cracking de contraseñas

| Campo | Información |
|---|---|
| **Grupo** | 10 |
| **Opción elegida** | **Opción B — La herramienta profesional (Hashcat y defensa moderna)** |
| **Integrantes** | Saby, Juan Pablo; Ramello, Belén; Kordek, Chiara; Corazza, Carolina |
| **Fecha de cierre** | 7 de noviembre de 2026 |

**Declaración de uso de IA (obligatoria):**
- **Herramientas utilizadas:** Antigravity / Gemini como asistente de investigación y redacción técnica.
- **Alcance y propósito:** Cotejo de literatura criptográfica; estructuración de la comparación entre modos de ataque de Hashcat y la implementación local.
- **Partes asistidas por IA:** Verificación de la redacción y corrección de la estructura segun lo solicitado por la cátedra.
- **Verificación humana y técnica:** Las autoras y autores revisaron manualmente cada definición, contrastaron los conceptos de *mask* y *combinator* con el código de `aplicar_reglas()` en `src/cracker.py`, y verificaron la exactitud de las cifras públicas de benchmark y parámetros de NIST SP 800-63B y RFC 8018.

---

## Resumen

Esta investigación analiza el funcionamiento interno de herramientas de auditoría de contraseñas profesionales como **Hashcat**, contrastando su capacidad de procesamiento masivo en GPU con el cracker desarrollado en CPU para este laboratorio. Se examina la diferencia operativa entre los ataques de máscara (*mask*), combinador (*combinator*) y mutación por reglas (*mangling*), se fundamenta por qué el *salt* destruye la viabilidad de las tablas precalculadas (*rainbow tables*), y se expone el funcionamiento del modelo de *k-anonymity* empleado por Have I Been Pwned y recomendado por NIST SP 800-63B para validar credenciales de forma segura.

---

## 1. Hashcat: paralelismo masivo y velocidades en GPU

**Hashcat** está diseñado para explotar arquitecturas masivamente paralelas como procesadores gráficos (GPUs), FPGAs y aceleradores computacionales mediante OpenCL y CUDA. A diferencia de una CPU tradicional de propósito general (diseñada para ejecutar pocos hilos con baja latencia y lógica de control compleja), una GPU contiene miles de núcleos aritméticos simples (ALUs) organizados en multiprocesadores de transmisión (SM). Esto le permite ejecutar millones de instancias del mismo algoritmo en paralelo (*Single Instruction, Multiple Threads* - SIMT).

La velocidad de cracking alcanzable no depende únicamente del hardware, sino fundamentalmente del **diseño criptográfico del algoritmo** y sus requerimientos de memoria (*memory-hardness*):

### Datos de benchmark de referencia pública (NVIDIA GeForce RTX 4090, 24 GB VRAM)

Las siguientes cifras provienen de pruebas públicas consolidadas de la comunidad de seguridad y el repositorio oficial de Hashcat (v6.2.6+) sobre hardware de última generación:

| Algoritmo y modo Hashcat | Entorno de hardware | Parámetros de prueba | Velocidad observada | Fuente y referencia |
|---|---|---|---:|---|
| **MD5** (`-m 0`) | NVIDIA RTX 4090 | Hash puro, sin salt (operaciones bit a bit básicas) | $\approx 164.100\text{ MH/s}$ ($164,1\text{ GH/s}$) | Chick3nman / Hashcat Benchmark Reference (2024) [4] |
| **MD5 + Salt** (`-m 10` / `-m 20`) | NVIDIA RTX 4090 | `salt` de 16 bytes prepended/appended | $\approx 55.400\text{ MH/s}$ ($55,4\text{ GH/s}$) | Chick3nman / Hashcat Benchmark Reference (2024) [4] |
| **PBKDF2-HMAC-SHA256** (`-m 10900`) | NVIDIA RTX 4090 | 1.000 iteraciones (modo estándar de benchmark) | $\approx 2.510\text{ kH/s}$ ($2,51\text{ MH/s}$) | Hashcat Official Forums Benchmark [4] |
| **PBKDF2-HMAC-SHA256** (`-m 10900`) | NVIDIA RTX 4090 | 200.000 iteraciones (caso PhantomCorp) | $\approx 12,5\text{ kH/s}$ ($12.550\text{ H/s}$) | Cálculo proporcional derivado de iteraciones [4] |
| **bcrypt** (`-m 3200`) | NVIDIA RTX 4090 | Coste $2^5 = 32$ iteraciones (benchmark default) | $\approx 128.500\text{ H/s}$ ($128,5\text{ kH/s}$) | Hashcat Official Forums Benchmark [4] |
| **bcrypt** (`-m 3200`) | NVIDIA RTX 4090 | Coste $2^{12} = 4.096$ iteraciones (producción recomendada) | $\approx 1.004\text{ H/s}$ | Chick3nman / Hashcat Benchmark Reference [4] |
| **Argon2id** (`-m 34000`) | NVIDIA RTX 4090 | $m=64\text{ MB}$, $t=3$, $p=4$ (OWASP Cheat Sheet) | $\approx 55\text{ H/s}$ | OWASP Password Storage Guidelines / Hashcat [4] |

### Análisis comparativo

1. **Hashes rápidos vs. Funciones lentas:** MD5 es más de **13 millones de veces más rápido** en la misma GPU que PBKDF2 con 200.000 iteraciones. Esto se debe a que MD5 se resuelve en 64 pasos elementales de suma, rotación y operaciones booleanas que se mapean directamente en las instrucciones nativas de la GPU sin transferencias de memoria.
2. **Resistencia a GPU (*Memory-hardness*):** Mientras que PBKDF2 es intensivo únicamente en cómputo (CPU/ALU bound) y puede ser acelerado por hardware especializado como ASICs o clústeres de GPUs, algoritmos modernos como **Argon2id** y **scrypt** son *memory-hard*. Al exigir que cada intento acceda de forma seudoaleatoria a un bloque de memoria de 64 MB, saturan el bus de memoria y la memoria compartida de la GPU, provocando que los miles de hilos queden ociosos esperando datos (*memory stall*), reduciendo el rendimiento a escasas decenas de intentos por segundo.

---

## 2. Ataques mask y combinator frente a reglas de mangling

Hashcat soporta distintos modos de ataque (`-a`), cada uno diseñado para un modelo de amenaza específico:

### 1. Ataque de Máscara / *Mask Attack* (Modo `-a 3`)
- **Principio:** Modela la estructura sintáctica fija o semi-fija de la contraseña mediante comodines por posición. Por ejemplo, la máscara `?u?l?l?l?l?d?d?s` indica: 1 mayúscula (`?u`), 4 minúsculas (`?l`), 2 dígitos (`?d`) y 1 símbolo (`?s`).
- **Comportamiento:** Genera exhaustivamente el espacio cartesiano de los conjuntos elegidos únicamente para esas posiciones.
- **Ventaja/Desventaja:** Es óptimo cuando se conoce la política corporativa que forzó al usuario (ej. "debe empezar con mayúscula y terminar en número"), reduciendo un espacio de $95^8 \approx 6,6 \times 10^{15}$ a $26 \times 26^4 \times 10^2 \times 33 \approx 3,9 \times 10^{10}$ combinaciones (una reducción de 5 órdenes de magnitud). Sin embargo, excluye cualquier contraseña que no respete estrictamente ese molde posicional.

### 2. Ataque Combinador / *Combinator Attack* (Modo `-a 1`)
- **Principio:** Toma dos diccionarios independientes ($D_1$ y $D_2$) y genera el producto cartesiano concatenando cada palabra de $D_1$ con cada palabra de $D_2$ ($P = w_1 \mathbin{\Vert} w_2$).
- **Aplicación:** Modela el comportamiento de contraseñas compuestas por dos términos comunes (ej. `mate` + `cocido` = `matecocido`, o `river` + `plate` = `riverplate`).
- **Complejidad:** El espacio resultante es de tamaño $|D_1| \times |D_2|$. No aplica transformaciones morfológicas internas.

### 3. Ataque con Reglas de Mutación / *Rule-based Mangling*
- **Principio:** Toma una palabra base (*lemma*) de un diccionario y le aplica una secuencia predefinida de funciones de transformación morfológica.
- **Implementación en el laboratorio (`src/cracker.py`):**
  - Identidad: `palabra`
  - Capitalización: `Palabra`
  - Sufijos temporales: `palabra2024`, `palabra2025`, `palabra2026`, `Palabra2024`, etc.
  - Sufijos incrementales: `palabra1`, `palabra12`, `palabra123`, `Palabra1`, etc.
- **Comparación con Hashcat:** En Hashcat, las reglas se definen mediante un lenguaje de directivas en archivos `.rule` (ej. `c` para capitalizar, `$2 $0 $2 $6` para concatenar `2026`). Mientras que *mask* define posiciones rígidas y *combinator* fusiona listas enteras, el *mangling* replica de forma quirúrgica los sesgos cognitivos humanos de adaptación de contraseñas, permitiendo que `phantom2026` caiga a partir de `phantom` sin tener que recorrer todo el espacio alfanumérico.

---

## 3. Tablas Rainbow (*Rainbow Tables*) y el rol del Salt

Una **Rainbow Table** es una estructura de datos precalculada que permite invertir funciones hash unidireccionales sin almacenar todos los pares `(candidato, hash)`. Utiliza secuencias encadenadas de funciones de reducción $R(h)$ y funciones de hash $H(p)$ que colapsan trayectorias en puntos de inicio y puntos finales, intercambiando tiempo de cálculo por almacenamiento en disco.

### ¿Por qué el salt las inutiliza de forma definitiva?
1. **Pérdida de reusabilidad:** Para que una tabla precalculada funcione, el algoritmo de reducción y hash debe ser universal e idéntico para todos los objetivos.
2. **Entrada modificada:** Cuando se incorpora un salt único de 16 bytes por usuario, el cálculo pasa a ser $H(\text{salt}_i \mathbin{\Vert} \text{password})$. Cada salt define un espacio matemático completamente disjunto.
3. **Inviabilidad económica del cómputo previo:** Una tabla generada para el salt `s4l7-01` no sirve para `s4l7-02`. Para poder quebrar un sistema con salts de 16 bytes mediante tablas precalculadas, el atacante debería precalcular $2^{128}$ tablas distintas, lo cual supera los recursos de almacenamiento físico del planeta.
4. **Distinción fundamental:** El salt neutraliza las tablas precalculadas y el ataque masivo multi-objetivo simultáneo, pero **no mitiga el ataque de diccionario offline directo contra un objetivo individual**. Si la contraseña es predecible, caerá tan rápido como el algoritmo permita evaluarla.

---

## 4. Pregunta de cierre: Have I Been Pwned y el modelo de *k-anonymity*

La norma **NIST SP 800-63B (Sección 5.1.1.2)** establece que los sistemas de autenticación deben verificar las contraseñas elegidas por los usuarios contra listas de credenciales comprometidas en filtraciones previas conocidas. El servicio **Have I Been Pwned (HIBP)**, creado por Troy Hunt, provee esta capacidad mediante una API de consulta basada en el principio de **k-anonimato** (*k-anonymity*), permitiendo al verificador consultar si una contraseña ha sido expuesta **sin revelarla ni transmitirla en ningún momento al servicio**.

### Mecanismo de consulta por rango (*Range API*)

```text
Usuario escribe: "riverplate"
    │
    ▼
1. Cliente calcula localmente:
   SHA-1("riverplate") = 8C5C8145CFDEE40B798BEF8FF19B917E36EB32B8
    │
    ├─ Prefijo (5 caracteres hex):   "8C5C8"
    └─ Sufijo (35 caracteres hex):   "145CFDEE40B798BEF8FF19B917E36EB32B8"
    │
    ▼
2. Cliente envía petición HTTP GET a HIBP:
   GET https://api.pwnedpasswords.com/range/8C5C8
    │
    ▼
3. Servidor HIBP busca en su base todos los hashes que empiezan con "8C5C8"
   y devuelve una lista de cientos de sufijos con sus frecuencias:
   0023B2A...:3
   ...
   145CFDEE40B798BEF8FF19B917E36EB32B8:1248   <-- Coincidencia encontrada localmente
   FF9821A...:1
    │
    ▼
4. Cliente verifica localmente si su sufijo está en la respuesta recibida.
   Si está presente, rechaza la contraseña informando cuántas veces fue filtrada.
```

### Propiedades de seguridad y privacidad

1. **Confidencialidad absoluta de la contraseña:** El servidor de HIBP solo observa un prefijo de 5 caracteres hexadecimales ($16^5 = 1.048.576$ cubos posibles). Cada prefijo colisiona con un conjunto de aproximadamente $500$ a $1.000$ contraseñas filtradas distintas. HIBP no tiene forma de saber cuál de todas ellas estaba consultando el usuario, logrando un grado de anonimato $k \ge 500$.
2. **Inmunidad ante espionaje de red:** Un intermediario en la red (o atacante Man-in-the-Middle) que intercepte la consulta HTTPS únicamente ve el prefijo `8C5C8`, a partir del cual es matemáticamente imposible deducir la contraseña original.
3. **Superioridad frente a políticas de complejidad obsoletas:** Las políticas que exigen "mayúscula, número y símbolo" generan un falso sentido de seguridad que desemboca en contraseñas predecibles como `Password123!`. El modelo de *k-anonymity* contrasta contra más de 850 millones de contraseñas reales obtenidas en brechas, permitiendo a los usuarios elegir frases de paso largas, fáciles de recordar y matemáticamente seguras (ej. `caballo-teclado-verde-mate`), garantizando que no hayan sido comprometidas previamente.

---

## Fuentes consultadas

1. **NIST**, *Digital Identity Guidelines: Authentication and Authenticator Management*, Special Publication 800-63B, National Institute of Standards and Technology, Gaithersburg, MD, 2020. URL: https://pages.nist.gov/800-63-4/sp800-63b.html — Consultado el 6 de noviembre de 2026.
2. **Have I Been Pwned**, *Pwned Passwords — API v3, Range Search Model*, Troy Hunt, 2018–2024. URL: https://haveibeenpwned.com/API/v3#PwnedPasswords — Consultado el 6 de noviembre de 2026.
3. **Hashcat Wiki**, *Hashcat Attack Modes and Rule-based Attack Specifications*, Hashcat Project, 2023. URL: https://hashcat.net/wiki/doku.php?id=attack_modes — Consultado el 6 de noviembre de 2026.
4. **Hashcat Benchmark Reference**, *Hashcat Public GPU Benchmarks: NVIDIA RTX 4090 Hashrates (Chick3nman / Hashcat Forum)*. URL: https://hashcat.net/forum/thread-10900.html — Consultado el 6 de noviembre de 2026.
5. **RFC 8018**, *PKCS #5: Password-Based Cryptography Specification Version 2.1*, Internet Engineering Task Force (IETF), 2017. URL: https://www.rfc-editor.org/rfc/rfc8018.html — Consultado el 6 de noviembre de 2026.
6. **OWASP Foundation**, *Password Storage Cheat Sheet*, Open Worldwide Application Security Project, 2024. URL: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — Consultado el 6 de noviembre de 2026.
