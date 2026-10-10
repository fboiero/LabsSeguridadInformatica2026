# Mini-research — Laboratorio 03

**Tema elegido:**
- [x] **A.** PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".
- [ ] **B.** TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.
- [ ] **C.** Autenticación vs autorización; modelos RBAC y ABAC.
- [ ] **D.** Ataques de timing reales y cómo se mitigan.

---

## Desarrollo

### 1. El problema fundamental: Las funciones de hash criptográficas rápidas vs la verificación de contraseñas

Las funciones criptográficas tradicionales (MD5, SHA-1, SHA-256, BLAKE3) fueron diseñadas para verificar integridad de datos y calcular firmas digitales con el menor costo computacional y la mayor tasa de transferencia posible. Esta virtud ingenieril se convierte en una vulnerabilidad crítica cuando se aplican al almacenamiento de contraseñas:

1. **Entropía humana vs entropía matemática:** A diferencia de una clave criptográfica de 256 bits generada uniformemente al azar ($2^{256}$ posibilidades), las contraseñas humanas tienen un espacio de búsqueda drásticamente restringido debido a patrones gramaticales, longitudes típicas y distribuciones sesgadas de caracteres.
2. **Asimetría de hardware y paralelismo masivo:** Un servidor legítimo solo necesita calcular un hash al momento del inicio de sesión de un usuario. En cambio, un atacante que obtiene un volcado de la base de datos realiza ataques *offline* sin límites de tasa (*rate-limiting*). En una GPU comercial moderna o una granja de ASICs/FPGAs, se pueden computar decenas de miles de millones de hashes SHA-256 por segundo de forma paralela.

Por este motivo surgieron las **Funciones de Derivación de Claves (KDF)** y los denominados **"hashes lentos"**, diseñados explícitamente para imponer una penalización de costo artificial y configurable que amortiza el login legítimo en milisegundos pero vuelve prohibitivo el cálculo de miles de millones de intentos en ataques offline.

---

### 2. Evolución cronológica y técnica de los algoritmos

```
+------------------------------------------------------------------------------------+
| 1999: PBKDF2 (RFC 2898)  --> CPU-bound (iteraciones lineales)                      |
| 1999: bcrypt (Niels Provos) --> Introducción de memoria interna estática (4 KB)    |
| 2009: scrypt (Colin Percival) --> Memory-Hard Functions (gran consumo de RAM)      |
| 2015: Argon2 (PHC Winner, RFC 9106) --> Estado del arte: tiempo, memoria y canales |
+------------------------------------------------------------------------------------+
```

#### A. PBKDF2 (Password-Based Key Derivation Function 2 — RFC 2898 / RFC 8018)
- **Mecanismo:** Aplica una función pseudoaleatoria subyacente (típicamente HMAC-SHA256) en un bucle repetitivo de $N$ iteraciones combinadas mediante XOR.
- **Limitación crítica:** Es estrictamente **CPU-bound** (limitado por procesamiento). No requiere prácticamente memoria RAM adicional para computar el bucle (solo unos pocos bytes para el estado interno del HMAC).
- **Vulnerabilidad ante hardware especializado:** Debido a su nulo requerimiento de memoria, un atacante puede implementar pipelines de PBKDF2 en ASICs o núcleos de GPU de manera compacta y masivamente paralela, logrando tasas de cracking muy altas a pesar del número de iteraciones.

#### B. bcrypt (Provos & Mazières, 1999)
- **Mecanismo:** Basado en el cifrador de bloque Blowfish modificado (`Eksblowfish` — *Expensive Key Schedule*). Realiza una expansión de clave intensiva que inicializa matrices internas de sustitución (S-boxes) mediante múltiples rondas de cifrado.
- **Aporte técnico:** Introdujo la necesidad de memoria activa de trabajo (aproximadamente **4 KB**). En 1999, esto dificultaba enormemente la construcción de circuitos dedicados (FPGAs) porque cada núcleo de cracking requería memoria embebida costosa.
- **Límites modernos:** El espacio de memoria de 4 KB cabe hoy con holgura en las memorias caché L1/L2 de GPUs modernas. Además, bcrypt trunca las contraseñas a un máximo estricto de **72 bytes**, lo que genera complicaciones en aplicaciones con claves largas o esquemas multilenguaje en UTF-8.

#### C. scrypt (Colin Percival, 2009 — RFC 7914)
- **Mecanismo:** Diseñado formalmente como la primera función estrictamente **secuencialmente dura en memoria** (*Sequential Memory-Hard Function*).
- **Aporte técnico:** Obliga a utilizar un arreglo de memoria configurable (frecuentemente decenas o cientos de megabytes) en dos etapas: primero llena un búfer con pseudorandomness y luego realiza accesos de lectura en saltos dependientes de los datos previos.
- **Impacto contra atacantes:** En ASICs o FPGAs, la memoria dedicada es extraordinariamente costosa en términos de área de silicio y disipación térmica. Un atacante no puede colocar miles de unidades scrypt en un chip sin agotar la memoria disponible o enfrentar cuellos de botella de ancho de banda.
- **Limitación:** Sus accesos a memoria dependen del valor de la clave, lo que lo hace potencialmente susceptible a ataques de canal lateral basados en caché (*cache-timing attacks*).

#### D. Argon2 (Ganador del Password Hashing Competition 2015 — RFC 9106)
- **Mecanismo:** Representa el estándar contemporáneo más avanzado y recomendado unánimemente por OWASP. Permite configurar de forma independiente tres parámetros de costo:
  1. **Tiempo ($t$):** Número de pasadas sobre la memoria.
  2. **Memoria ($m$):** Cantidad de kibibytes de memoria asignada (típicamente de 19 MB a 64 MB por hash).
  3. **Paralelismo ($p$):** Cantidad de hilos de ejecución concurrentes.
- **Variantes criptográficas:**
  - **Argon2d:** Accesos a memoria dependientes de los datos. Máxima resistencia contra ataques por fuerza bruta en GPU/ASIC. Riesgo teórico de ataques de canal lateral si el atacante comparte el hardware físico del servidor.
  - **Argon2i:** Accesos a memoria independientes de los datos. Inmune a ataques de temporización por canal lateral; óptimo para derivación de claves en discos cifrados.
  - **Argon2id (Recomendado):** Enfoque híbrido. La primera mitad de la primera pasada sigue el esquema de Argon2i para mitigar ataques de canal lateral, y el resto sigue Argon2d para maximizar la resistencia al paralelismo masivo de GPUs.

---

### 3. Matriz comparativa de propiedades técnicas

| Algoritmo | Año | Dependencia principal | Uso de memoria | Resistencia a GPU/ASIC | Parámetros configurables | Recomendación actual (OWASP) |
|---|:---:|:---:|:---:|:---:|---|:---:|
| **PBKDF2** | 2000 | CPU | Despreciable (< 1 KB) | 🔴 Baja (fácilmente paralelizable) | Iteraciones, PRF | Aceptable como *fallback* si no hay librerías de terceros (mín. 600.000 iters con SHA-256) |
| **bcrypt** | 1999 | CPU / Caché | ~4 KB | 🟡 Moderada (cabe en cachés de GPU modernas) | Factor de costo (work factor) | Aceptable para sistemas heredados (cost $\ge 10$) |
| **scrypt** | 2009 | Memoria (RAM) | Alta (configurable, ej. 16–64 MB) | 🟢 Alta (costo prohibitivo de silicio) | $N$ (costo), $r$ (bloque), $p$ (paralelismo) | Fuerte alternativa si Argon2 no está disponible |
| **Argon2id** | 2015 | CPU + RAM + Hilos | Alta (configurable, ej. 19–64 MB) | 🟢🟢 Máxima (estándar de oro actual) | Tiempo ($t$), Memoria ($m$), Paralelismo ($p$) | **Primera opción preferida** |

---

## Fuentes (mín. 3)

1. **OWASP Foundation (2024).** *Password Storage Cheat Sheet*. OWASP Cheat Sheet Series.  
   Disponible en: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
2. **Biryukov, A., Dinu, D., & Khovratovich, D. (2015 / RFC 9106, 2021).** *Argon2 Password-Hash Function*. Internet Engineering Task Force (IETF).  
   Disponible en: https://www.rfc-editor.org/rfc/rfc9106.html
3. **Percival, C. (2009).** *Stronger Key Derivation via Sequential Memory-Hard Functions*. BSDCan 2009 Conference Proceedings (Presentación formal de scrypt / IETF RFC 7914).  
   Disponible en: https://www.tarsnap.com/scrypt/scrypt.pdf
4. **Provos, N., & Mazières, D. (1999).** *A Future-Adaptable Password Scheme*. USENIX Security Symposium. (Diseño original de bcrypt y Eksblowfish).  
   Disponible en: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf

---

## Reflexión

El estudio de los hashes lentos revela una lección fundamental en seguridad defensiva: **el equilibrio entre la disponibilidad del servicio y la asimetría contra el atacante**.

Cuando diseñamos arquitecturas de autenticación en backend, el administrador suele verse tentado a priorizar la velocidad de respuesta (latencias en el orden de los microsegundos) o el ahorro de recursos de hardware en servidores de alta concurrencia. Sin embargo, utilizar hashes ultrarrápidos no protege al usuario legítimo; simplemente le regala a un atacante la capacidad de quebrar millones de registros por segundo en cuanto ocurre una fuga física o lógica de la base de datos (tal como se evidenció en la brecha de LinkedIn con SHA-1).

La introducción de funciones duras en memoria como **scrypt** y **Argon2id** cambió las reglas del juego: al ligar la dificultad de cómputo al consumo de memoria física en lugar de simples ciclos de procesador, los defensores lograron encarecer de manera drástica el costo económico y la viabilidad técnica de construir hardware especializado para cracking. No obstante, esto impone una nueva responsabilidad defensiva: dimensionar cuidadosamente los parámetros de tiempo y memoria en los servidores productivos para evitar vectores de Denegación de Servicio (DoS) basados en saturar la memoria del backend con múltiples peticiones de login simultáneas. La seguridad moderna no se basa en el secretismo del algoritmo, sino en forzar un costo matemático y financiero inasumible para el adversario.
