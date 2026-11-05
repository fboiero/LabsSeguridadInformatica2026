# Informe — Laboratorio 03 · Autenticación

**Grupo:** Grupo 04  
**Integrantes:**
- Integrante 1 — `@uRIELoLIVERO`
- Integrante 2 — `@JereAntunez`
- Integrante 3 — `@FacundoAnil4`
- Integrante 4 — `@LelliMatias`

---

## 0. Declaración de uso de asistentes de IA

* **¿El grupo utilizó asistentes de IA en este trabajo?** Sí.
* **Herramienta utilizada:** Gemini 3.8 Flash.
* **Finalidad y alcance:**
  - Asistencia en la revisión del desarrollo de las funciones del esqueleto de código.
  - Búsqueda y estructuración de la información sobre la brecha de RockYou (Parte A) y soporte en la redacción técnica de las preguntas sobre contraseñas y TOTP (Parte B).
* **Partes del entregable afectadas:** Código en [`src/auth.py`](src/auth.py), informe en [`informe.md`](informe.md) y mini-research en [`research.md`](research.md).
* **Metodología de validación:**
  - Pruebas directas con Python 3.11 en contenedor Docker.
  - Validación del vector de prueba oficial de la RFC 6238 (`totp` con clave `12345678901234567890` y $t=59$, verificando que dé exactamente `287082`).
  - Verificación del comportamiento de `hmac.compare_digest` frente a comparaciones tradicionales.
  - Lectura y cotejo de estándares técnicos (RFC 2898, RFC 4226, RFC 6238 y NIST SP 800-63B).

---

## 1. Parte A — Análisis de la brecha (Caso 1: RockYou, 2009)

### 1.1 Contexto del incidente
En diciembre de 2009, la empresa estadounidense **RockYou**, que desarrollaba aplicaciones y widgets para redes sociales populares de esa época (principalmente MySpace y Facebook), sufrió un incidente de seguridad crítico que expuso las credenciales de más de 32 millones de usuarios.

### 1.2 La falla concreta
El problema no estuvo en una debilidad de algún algoritmo criptográfico moderno, sino en dos fallas graves de desarrollo y arquitectura:
1. **Contraseñas en texto plano:** La base de datos de producción (MySQL) guardaba las contraseñas de los usuarios tal cual las escribían, sin aplicar ninguna función de hash, sin sal (*salt*) y sin ningún factor de costo computacional.
2. **Inyección SQL no autenticada:** Tenían una aplicación web de gestión interna accesible desde Internet con una vulnerabilidad clásica de SQL Injection (SQLi), donde los parámetros de entrada se concatenaban directamente en la consulta a la base de datos sin sanear.

### 1.3 Explotación
Un atacante bajo el seudónimo "Tomas" descubrió la inyección SQL en la web. Al no haber validación de entrada, pudo ejecutar consultas arbitrarias y realizar un volcado (*dump*) completo de la tabla de usuarios. Como las contraseñas estaban almacenadas en texto plano, no tuvo que crackear nada ni gastar tiempo de cómputo: las más de 32 millones de contraseñas quedaron legibles y utilizables al instante.

### 1.4 Impacto y consecuencia histórica
La lista de contraseñas filtradas terminó publicándose en foros de la comunidad. Con el tiempo se limpió, se ordenó por frecuencia de uso y dio origen al célebre diccionario **`rockyou.txt`** (con más de 14 millones de contraseñas únicas). Hoy en día, cualquiera que haga pentesting o trabaje en ciberseguridad conoce este archivo: es la wordlist estándar por defecto que se usa en herramientas como John the Ripper o Hashcat para ataques de fuerza bruta y *credential stuffing*.

### 1.5 Cómo se debió haber resuelto
1. **Almacenamiento seguro con funciones KDF:** Las contraseñas jamás deben persistirse en texto plano. Se debió implementar un algoritmo de hash lento con factor de trabajo ajustable como **PBKDF2-HMAC-SHA256** (con al menos 200.000 iteraciones, siguiendo las recomendaciones del NIST SP 800-63B), o alternativas orientadas a memoria como bcrypt o Argon2id, acompañadas siempre de un salt aleatorio de al menos 16 bytes único por usuario.
2. **Consultas parametrizadas:** En la capa de aplicación web, utilizar sentencias preparadas (*Prepared Statements*) para separar la lógica SQL de los datos del usuario, eliminando de raíz la posibilidad de una inyección SQL.

### 1.6 Fuentes consultadas
- Federal Trade Commission (FTC). (2012). *In the Matter of RockYou, Inc.* FTC Docket No. C-4357.
- Goodin, D. (2009). *32 million passwords exposed in RockYou breach*. The Register.
- NIST Special Publication 800-63B (2020). *Digital Identity Guidelines: Authentication and Lifecycle Management*.

---

## 2. Parte B.1 — Contraseñas

### ¿Por qué salt por usuario?
1. **Evita correlacionar contraseñas idénticas:** Si dos o más usuarios eligen la misma clave (por ejemplo, `Santiago123!`), en un sistema sin salt sus hashes guardados serían idénticos. Un atacante que mire la base de datos sabría al instante que esos usuarios comparten credencial sin necesidad de romperla. Con un salt pseudoaleatorio único por usuario (generado con `secrets.token_bytes(16)`), la misma contraseña produce cadenas de hash totalmente distintas para cada persona.
2. **Inutiliza tablas precalculadas (Rainbow Tables):** Sin salt, un atacante puede calcular los hashes de las 100.000 contraseñas más comunes una sola vez y buscar coincidencias contra toda la base de datos de un solo barrido. Al haber un salt aleatorio de 16 bytes ($2^{128}$ combinaciones), las tablas precalculadas no sirven de nada.
3. **Multiplica el costo de cracking:** Obliga al atacante a crackear cada cuenta de forma individual. Si la base tiene 1.000 usuarios, el atacante tiene que hacer el trabajo 1.000 veces por separado en vez de probar un diccionario una sola vez contra todos.

### ¿Por qué muchas iteraciones (200.000) y no una sola?
1. **Asimetría entre atacante y defensor:** Los algoritmos de hash comunes (como SHA-256 a secas) se diseñaron para ser muy rápidos y eficientes. Pero en contraseñas esa velocidad juega en contra: con placas de video (GPUs) modernas o ASICs, un atacante puede probar miles de millones de hashes por segundo. Si usáramos una sola iteración, cualquier clave típica se quiebra en cuestión de segundos.
2. **Penalización temporal controlada:** Al encadenar 200.000 iteraciones de HMAC-SHA256 (el estándar PBKDF2), el cómputo en nuestro servidor toma alrededor de 50 a 100 milisegundos cuando un usuario inicia sesión. Para una persona real ese tiempo es imperceptible, pero para un atacante que necesita probar un diccionario de 10 millones de palabras, esos milisegundos por intento convierten un ataque de pocos minutos en meses o años de procesamiento ininterrumpido.

### ¿Por qué la verificación debe ser en tiempo constante (`hmac.compare_digest`)?
La comparación de cadenas común (`string1 == string2`) trabaja carácter por carácter y corta en cuanto encuentra la primera diferencia (*early exit* o cortocircuito). Si el primer carácter no coincide, la operación termina unos nanosegundos antes que si coinciden los primeros diez.  
Aunque esa diferencia sea mínima, un atacante que mida con precisión los tiempos de respuesta de la red puede deducir la contraseña o el hash carácter por carácter (lo que se conoce como *timing attack* o ataque por canal lateral).  
La función `hmac.compare_digest` recorre siempre la totalidad de los bytes sin importar en qué posición esté el error, asegurando que la comparación tarde exactamente lo mismo y cerrando esa fuga de información.

---

## 3. Parte B.2 — TOTP (RFC 6238)

### ¿Por qué el segundo factor (TOTP) frena el robo de contraseñas?
Porque introduce autenticación multifactor real combinando dos dimensiones:
- **Algo que sé:** La contraseña estática del usuario.
- **Algo que tengo:** El dispositivo (como el teléfono) que almacena la semilla secreta compartida.

Si un atacante consigue nuestra contraseña (por una filtración masiva, reutilización en otro sitio o un keylogger viejo), esa credencial por sí sola no le sirve para entrar. El código numérico de 6 dígitos que calcula el TOTP es dinámico y cambia cada 30 segundos según la fórmula $C = \lfloor t / 30 \rfloor$. Cuando el atacante intente usar la contraseña robada, el código efímero ya habrá expirado y el acceso quedará bloqueado salvo que también tenga posesión física o lógica del dispositivo con la semilla.

### ¿Qué NO protege el TOTP?
Aunque es una mejora de seguridad indispensable, el TOTP tiene límites técnicos claros:
1. **Phishing en tiempo real (Adversary-in-the-Middle / AitM):** Si el usuario cae en una página falsa montada con herramientas como *Evilginx* que funcionan como un proxy inverso transparente, el usuario ingresa su usuario, clave y código TOTP vigente. El servidor del atacante reenvía esos datos al servicio legítimo en ese mismo segundo, completa el inicio de sesión y secuestra la cookie de sesión (*session token*) resultante.
2. **Malware en el equipo del usuario (Session Hijacking):** Si la máquina de la víctima tiene un troyano infostealer (como RedLine o Lumma), el malware espera a que el usuario se loguee legítimamente con su contraseña y TOTP, y luego copia directamente las cookies de sesión del navegador. El atacante entra clonando la sesión sin tener que pasar por el login ni por el 2FA.
3. **Compromiso de la semilla secreta en el servidor:** La semilla base del TOTP se comparte entre el cliente y el servidor en texto claro para poder calcular el HMAC. Si la base de datos del backend se ve comprometida y las semillas no estaban protegidas, el atacante puede generar en su propia máquina los mismos códigos que el usuario.
4. **Reutilización dentro de la ventana de tiempo:** Si el servidor no invalida de inmediato el código de 6 dígitos una vez que fue utilizado dentro de los 30 segundos, un tercero que lo intercepte podría intentar reutilizarlo antes de que cambie la ventana temporal.

---

## 4. Bitácora de comandos y evidencia de ejecución

A continuación se registran las pruebas realizadas sobre [`src/auth.py`](src/auth.py):

### 4.1 Generación de hash seguro (PBKDF2 con Salt aleatorio y 200.000 iteraciones)
```bash
$ python auth.py hash --password 'Santiago123!'
pbkdf2_sha256$200000$3fea62ce4d6d83ed3bd30e14098ad7de$c2d1431bcf9449f04e411fa0846b912d8bb7fbf8636d5ed1cd5fa5143e5896a5
```

### 4.2 Verificación de contraseña correcta
```bash
$ python auth.py verify --password 'Santiago123!' --registro 'pbkdf2_sha256$200000$3fea62ce4d6d83ed3bd30e14098ad7de$c2d1431bcf9449f04e411fa0846b912d8bb7fbf8636d5ed1cd5fa5143e5896a5'
OK
```

### 4.3 Verificación con contraseña incorrecta
```bash
$ python auth.py verify --password 'ContraseñaInvalida' --registro 'pbkdf2_sha256$200000$3fea62ce4d6d83ed3bd30e14098ad7de$c2d1431bcf9449f04e411fa0846b912d8bb7fbf8636d5ed1cd5fa5143e5896a5'
FALLO
```

### 4.4 Verificación del vector oficial RFC 6238 (Secreto ASCII `12345678901234567890`, $t=59$)
```bash
$ python auth.py totp --secret 12345678901234567890 --t 59
287082
```
*El resultado obtenido coincide con el vector de prueba de 6 dígitos especificado formalmente en el RFC 6238.*
