# Mini-research — Laboratorio 03 · Autenticación

**Grupo:** Grupo 04  
**Tema elegido:**
- [x] **A. PBKDF2 vs bcrypt vs scrypt vs Argon2: por qué existen "hashes lentos".**
- [ ] **B. TOTP vs FIDO2/WebAuthn: por qué las passkeys superan al TOTP.**
- [ ] **C. Autenticación vs autorización; modelos RBAC y ABAC.**
- [ ] **D. Ataques de timing reales y cómo se mitigan.**

---

## 1. Desarrollo

### 1.1 El problema de fondo: por qué los hashes rápidos no sirven para contraseñas

Cuando vemos funciones de hash tradicionales como MD5, SHA-1 o SHA-256 en materias de sistemas o redes, aprendemos que están diseñadas para ser lo más rápidas y eficientes posible: tienen que verificar la integridad de archivos de varios gigabytes en milisegundos con un consumo casi nulo de memoria RAM y CPU.

El problema aparece cuando usamos esos mismos algoritmos para almacenar contraseñas en una base de datos. En ese escenario, la velocidad juega completamente a favor del atacante y en contra del defensor:
- **Asimetría de uso:** Nuestro backend solo calcula el hash una única vez cuando el usuario se loguea. Al usuario no le cambia nada que el servidor tarde 5 microsegundos o 70 milisegundos en responder. En cambio, si un atacante se roba la base de datos, va a intentar calcular miles de millones de hashes por segundo para descifrar la mayor cantidad de cuentas posible.
- **La ventaja del hardware paralelo (GPUs y ASICs):** Un procesador de servidor tradicional (CPU) tiene pocos núcleos pensados para tareas complejas y secuenciales. Una placa de video moderna (GPU) o un circuito ASIC tiene miles de núcleos simples trabajando en paralelo. Con una placa de video estándar hoy se pueden probar decenas de miles de millones de hashes SHA-256 por segundo. Si la contraseña se guardó con una sola pasada de hash, cualquier clave típica cae en minutos.

Por esta razón nacieron las funciones de derivación de claves (**KDF - Key Derivation Functions**) o **"hashes lentos"**. Su objetivo es penalizar el cálculo computacional de forma controlada mediante parámetros configurables (*work factors*), volviendo inviable el ataque masivo por fuerza bruta.

---

### 1.2 Comparación de los algoritmos

#### A. PBKDF2 (Password-Based Key Derivation Function 2 — RFC 2898)
- **Cómo trabaja:** Toma la contraseña, le suma un salt aleatorio y aplica una función pseudoaleatoria (casi siempre HMAC-SHA256) en un bucle repetido durante una cantidad $c$ de iteraciones.
- **Tipo de costo:** Es puramente de procesamiento (**CPU-bound**). Consume una cantidad mínima de memoria RAM (unos pocos bytes para el estado).
- **El límite actual:** Como no exige memoria, los atacantes pueden programar núcleos de HMAC en GPUs o granjas de ASICs de forma masiva y muy barata. Aunque el estándar NIST SP 800-63B recomienda usar al menos 200.000 iteraciones (que es lo que implementamos en este laboratorio), el aumento del factor de trabajo sobrecarga los CPUs del servidor pero no frena del todo a las placas de video modernas, lo que motivó el desarrollo de algoritmos basados en memoria.

#### B. bcrypt (Niels Provos y David Mazières, 1999)
- **Cómo trabaja:** Está basado en el cifrador por bloques Blowfish, utilizando una rutina inicial de expansión de claves llamada **Eksblowfish** (*Expensive Key Schedule Blowfish*) donde el costo de repetición crece de forma exponencial ($2^k$).
- **Tipo de costo:** Requiere CPU y un buffer de memoria de **4 KiB** que se lee y escribe constantemente de manera no lineal.
- **Ventajas y limitaciones:** Al exigir 4 KiB de memoria por cada hilo de cálculo, bcrypt aprovechaba la memoria caché L1 de los procesadores y complicaba enormemente la paralelización en las GPUs de la época. Sin embargo, tiene dos desventajas conocidas en desarrollo:
  1. Esos 4 KiB hoy en día entran con facilidad en los chips ASIC modernos.
  2. Posee una limitación histórica de diseño: trunca automáticamente cualquier contraseña que supere los **72 bytes**.

#### C. scrypt (Colin Percival, 2009 — RFC 7914)
- **Cómo trabaja:** Fue el primer algoritmo diseñado formalmente como una función dura en memoria (**memory-hard function**). Genera un vector pseudoaleatorio muy grande en memoria RAM y después lo recorre en un orden pseudoaleatorio que depende de los datos anteriores.
- **Tipo de costo:** Permite configurar costo de CPU/memoria ($N$), tamaño de bloque ($r$) y paralelismo ($p$).
- **Impacto:** Obliga al atacante a disponer de cientos de megabytes de memoria RAM de alta velocidad por cada intento simultáneo, lo cual encarece drásticamente el costo de diseñar hardware dedicado (ASICs). Su principal punto débil teórico es que puede ser susceptible a ataques de canal lateral si el atacante puede medir el tiempo de acceso a las líneas de caché de memoria.

#### D. Argon2 (Alex Biryukov, Daniel Dinu y Dmitry Khovratovich, 2015 — RFC 9106)
- **Cómo trabaja:** Fue el ganador unánime de la *Password Hashing Competition* (PHC) en 2015 y representa el estándar moderno más avanzado para almacenamiento de contraseñas.
- **Las tres variantes:**
  - **Argon2d:** El orden de acceso a la memoria depende del valor de la contraseña (*data-dependent*). Es el más resistente contra ataques con GPUs y ASICs, pero puede filtrar información por tiempos de acceso a caché (se usa principalmente en criptomonedas y pruebas de trabajo).
  - **Argon2i:** El acceso a la memoria es independiente del valor de la contraseña (*data-independent*). Es inmune a canales laterales por tiempo, pero pierde un poco de resistencia contra optimizaciones de hardware.
  - **Argon2id (Recomendado):** Es la variante híbrida. Durante la primera mitad del cómputo se comporta como Argon2i para blindarse contra ataques de canal lateral, y en la segunda mitad opera como Argon2d para maximizar la resistencia contra GPUs y ASICs. Es el estándar de oro recomendado formalmente por OWASP y el RFC 9106.

---

### 1.3 Matriz comparativa

| Algoritmo | Año | Cuello de botella principal | Parámetro de ajuste | Resistencia a GPU | Resistencia a ASIC | Recomendación actual |
|---|---|---|---|---|---|---|
| **PBKDF2** | 2000 | CPU | Número de iteraciones ($c$) | Baja | Muy Baja | Aceptado como estándar legado (mín. 200k iteraciones) |
| **bcrypt** | 1999 | CPU + Caché L1 (4 KiB) | Factor de costo logarítmico ($2^k$) | Media | Media | Muy utilizado en producción; límite de 72 bytes |
| **scrypt** | 2009 | Memoria RAM (Memory-hard) | Costo ($N$), Bloque ($r$), Hilos ($p$) | Alta | Alta | Muy sólido; superado por Argon2id |
| **Argon2id** | 2015 | Memoria RAM + CPU | Memoria ($m$), Iteraciones ($t$), Hilos ($p$) | Excelente | Excelente | **Recomendación actual por defecto (OWASP)** |

---

## 2. Fuentes consultadas (formato APA)

1. Biryukov, A., Dinu, D., & Khovratovich, D. (2021). *Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications*. RFC 9106, Internet Engineering Task Force (IETF). https://www.rfc-editor.org/rfc/rfc9106.html
2. Kaliski, B. (2000). *PKCS #5: Password-Based Cryptography Specification Version 2.0*. RFC 2898, Internet Engineering Task Force (IETF). https://www.rfc-editor.org/rfc/rfc2898.html
3. National Institute of Standards and Technology (NIST). (2020). *Digital Identity Guidelines: Authentication and Lifecycle Management*. NIST Special Publication 800-63B. U.S. Department of Commerce. https://doi.org/10.6028/NIST.SP.800-63b
4. OWASP Foundation. (2023). *Password Storage Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
5. Percival, C. (2016). *The scrypt Password-Based Key Derivation Function*. RFC 7914, Internet Engineering Task Force (IETF). https://www.rfc-editor.org/rfc/rfc7914.html
6. Provos, N., & Mazières, D. (1999). *A Future-Adaptable Password Scheme*. Proceedings of the FREENIX Track: 1999 USENIX Annual Technical Conference, Monterey, CA.

---

## 3. Reflexión

Analizar la evolución de estos algoritmos nos muestra con claridad un concepto central de la ingeniería de software y la seguridad: **la seguridad nunca es fija, es una constante carrera con el avance en el hardware**. Un algoritmo que era adecuado hace diez años hoy puede ser simple de quebrar porque las nuevas GPUs tienen órdenes de magnitud más potencia de cálculo.

Desde la perspectiva del diseño de sistemas en producción, la elección y configuración de un hash lento plantea un compromiso entre **seguridad criptográfica y disponibilidad del servicio**:

Si elegimos parámetros demasiado exigentes, dejamos al servidor vulnerable a un ataque de **Denegación de Servicio (DoS)**, ya que a un atacante le bastaría con disparar 50 o 100 peticiones de login falsas en paralelo para colapsar el servidor web.

Por eso, en arquitecturas reales la protección de contraseñas no se resuelve con una sola herramienta. Se busca un equilibrio calibrando el hash lento para que tome entre 50 y 100 ms en el servidor legítimo (como las 200.000 iteraciones de PBKDF2 que usamos en el lab o 19 MiB en Argon2id), complementándolo siempre con controles perimetrales: **rate limiting** en la API de autenticación, bloqueo temporal ante intentos fallidos y autenticación multifactor (MFA/TOTP).
