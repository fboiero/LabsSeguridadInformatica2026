# Informe — Laboratorio 03 · Autenticación

*Grupo:* 06 · *Integrantes:* 
- Beccereca, Martín - martinbeccereca
- Benito, María Belén
- De Miguel, Alejo - AlejoDM
- Giudici, Tomás - TomasGiudici
- Suppo, Carolina 

*Fecha:* 

---

## 0. Declaración de uso de IA
- *Herramientas utilizadas:* Claude Code.
- *Finalidad del uso:* Estructuración del informe Markdown.
- *Partes generadas o asistidas:* Estructuración del esquema del informe.
- *Verificación:* Todos los datos históricos, volúmenes de registros expuestos, detalles criptográficos y fuentes bibliográficas fueron contrastados y verificados manualmente contra publicaciones de seguridad primarias.

---

## 1. Parte A — Análisis de la brecha: Credential stuffing

**Caso asignado:** Credential stuffing — grupo 06, `número de grupo mod 4 = 2`
sobre la tabla del enunciado.

### Qué se explota (la falla)

El *credential stuffing* no rompe ningún algoritmo criptográfico ni explota una
vulnerabilidad de software: explota una práctica humana, el reuso de
contraseñas entre sitios distintos. El atacante no adivina contraseñas al
azar (eso sería fuerza bruta clásica) ni prueba una única contraseña contra
muchas cuentas (eso sería *password spraying*); en cambio, automatiza el
ingreso de pares usuario/contraseña reales, filtrados previamente en la
brecha de otro servicio no relacionado, contra el sistema objetivo. La
apuesta del atacante es estadística: si una fracción de esos usuarios reusó su
contraseña en el sitio objetivo, cada intento fallido no cuesta nada y cada
acierto entrega una cuenta válida.

La falla, entonces, no está en un componente técnico roto sino en la ausencia
de controles que asuman que esto va a pasar: falta de un segundo factor de
autenticación, falta de verificación de la contraseña contra listas de
credenciales ya filtradas, y falta de límites al ritmo de intentos de login
(OWASP Foundation, s.f.).

### Cómo se explotó: el caso Zoom (abril de 2020)

Un caso documentado de esta técnica es el de Zoom en abril de 2020. La
firma de inteligencia de amenazas Cyble detectó, alrededor del 1 de abril
de 2020, la venta de más de 500.000 credenciales de cuentas de Zoom en foros
de la dark web, a un precio de apenas USD 0,002 por cuenta (en varios casos,
directamente regaladas para ganar reputación en esos foros). Cada credencial
incluía el correo electrónico, la contraseña, la URL de la reunión personal y
la "Host Key" de la cuenta.

Según la cobertura técnica del incidente, las credenciales no salieron de
un hackeo a los servidores de Zoom: fueron recopiladas de brechas
anteriores y no relacionadas, sufridas por otros servicios. Los atacantes
automatizaron el intento de esos pares usuario/contraseña contra Zoom,
aprovechando el pico de uso de la plataforma durante los primeros meses de la
pandemia. El éxito del ataque dependió pura y exclusivamente de cuántos
usuarios habían reutilizado, en Zoom, una contraseña ya filtrada en otro
lado (BleepingComputer, 2020).

Esto muestra el patrón típico de un credential stuffing: no hace falta
vulnerar el sistema objetivo en absoluto si el eslabón débil es la conducta
del usuario en otros sistemas.

### La forma correcta: qué lo frena

**Autenticación multifactor (MFA/2FA).** Es la mitigación más efectiva contra
este ataque, porque incluso si el par usuario/contraseña es válido, al
atacante le falta el segundo factor. Según cita la OWASP Foundation, un
análisis de Microsoft estima que el MFA habría prevenido el 99,9% de los
compromisos de cuentas por este tipo de ataque (OWASP Cheat Sheet Series,
s.f.). Esta es exactamente la mitigación que implementa la Parte B.2 de este
mismo laboratorio (TOTP): un atacante que solo tiene la contraseña filtrada
queda frenado porque no tiene el secreto compartido necesario para generar el
código de un solo uso.

**Verificación contra contraseñas comprometidas.** El estándar NIST SP
800-63B-4 (parte de las *Digital Identity Guidelines* Rev. 4, publicadas en
su versión final en julio de 2025) exige explícitamente que el verificador
rechace contraseñas conocidas por haber sido filtradas: "Verifiers SHALL
compare the prospective secret against a blocklist that contains known
commonly used, expected, or compromised passwords", blocklist que debe
incluir "passwords obtained from previous breach corpuses" (NIST, 2025,
§3.1.1.2). Es la mitigación que ataca la causa raíz: si la contraseña que un
usuario intenta registrar ya apareció en una brecha pública, el sistema la
rechaza antes de que pueda ser reutilizada.

**Límite de intentos (rate limiting).** El mismo estándar exige que el
verificador limite los intentos fallidos consecutivos de autenticación a no
más de 100 antes de bloquear ese autenticador (NIST, 2025, §3.2.2), lo que
vuelve inviable probar millones de credenciales filtradas en tiempo
razonable. OWASP agrega, como defensas complementarias en capas, CAPTCHA,
huella digital de dispositivo/conexión y bloqueo de tráfico proveniente de
proveedores de hosting o redes de proxy conocidas por alojar bots (OWASP
Cheat Sheet Series, s.f.).

Ninguna de estas tres mitigaciones es suficiente por sí sola, de ahí que las
tres guías coincidan en un enfoque de defensa en capas. Pero el MFA es,
de las tres, la que corta el ataque incluso cuando la contraseña filtrada es
válida.


## 2. Parte B.1 — Contraseñas

### Por qué el salt tiene que ser único por usuario

El *salt* es un valor pseudoaleatorio criptográficamente seguro (generado mediante `secrets.token_bytes`) que se combina con la contraseña antes de aplicar la función de derivación de clave. Debe ser único para cada usuario y registro por dos razones fundamentales:

1. **Evitar la deducción de contraseñas idénticas entre usuarios:**
   Si dos usuarios eligen la misma contraseña en un esquema sin salt o con un salt global fijo, sus hashes resultantes en la base de datos serían idénticos.
   Esto permite a cualquier atacante que acceda a la base de datos deducir de inmediato qué usuarios comparten clave sin necesidad de haberla crackeado previamente. Al emplear un salt aleatorio independiente por usuario, la salida criptográfica es completamente distinta:
   El atacante no puede correlacionar registros ni inferir igualdad de contraseñas.

2. **Mitigación de ataques masivos y tablas precomputadas:**
   Sin un salt por usuario, un atacante puede precomputar una tabla de contraseñas comunes y sus hashes una única vez, y utilizarla para atacar a todos los usuarios de la base de datos en simultáneo. Con un salt único por usuario, las tablas precalculadas quedan completamente inutilizadas: el atacante está forzado a recalcular el espacio de búsqueda completo de forma individual para cada salt específico, multiplicando el esfuerzo por la cantidad $N$ de usuarios comprometidos.

---

### Por qué conviene un número alto de iteraciones

Las funciones criptográficas de hash generales (como SHA-256 o MD5) fueron diseñadas para procesar grandes volúmenes de datos a máxima velocidad y con mínimo consumo de recursos. Esta característica, ideal para verificar integridad de archivos, es una debilidad crítica cuando se almacenan contraseñas:

1. **Asimetría frente a hardware acelerador:**
   Un atacante con hardware masivamente paralelo puede calcular miles de millones de hashes SHA-256 directos por segundo en un ataque de fuerza bruta offline contra una base de datos filtrada.
   
2. **Estiramiento de clave y factor de trabajo:**
   PBKDF2 (*Password-Based Key Derivation Function 2*) introduce un costo computacional parametrizable mediante un número de iteraciones. La función encadena repetidamente HMAC-SHA256, forzando a calcular 200.000 derivaciones consecutivas para un solo intento de contraseña.

3. **Impacto asimétrico (Defensa vs. Ataque):**
   - **Para el servidor legítimo:** Calcular 200.000 iteraciones toma aproximadamente entre 30ms y 80ms en un hilo de CPU estándar. Este tiempo es completamente imperceptible para un usuario humano que inicia sesión una sola vez.
   - **Para el atacante:** Un ataque de diccionario de 10^8 palabras candidatas, que con SHA-256 simple tomaría fracciones de segundo en GPU, con 200.000 iteraciones de PBKDF2 pasa a requerir días o semanas de cómputo continuo y un costo energético masivo, volviendo la fuerza bruta económicamente inviable.

---

### Comparación en tiempo constante

En `verify_password()`, la comparación entre el hash calculado y el almacenado se realiza estrictamente con `hmac.compare_digest()` en lugar del operador de igualdad estándar `==`. El operador `==` compara byte a byte y retorna `False` al encontrar el primer byte discordante (*early exit*), produciendo variaciones medibles en el tiempo de respuesta. Un atacante podría explotar esta fuga mediante un canal lateral de temporización (*timing attack*) para reconstruir el hash derivado byte a byte. `hmac.compare_digest()` garantiza que la comparación tome exactamente el mismo tiempo independientemente de cuántos bytes coincidan.

---



## 5. Fuentes consultadas
1. OWASP Cheat Sheet Series. (s.f.). *Credential Stuffing Prevention Cheat Sheet*. OWASP Foundation. https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html
2. OWASP Foundation. (s.f.). *Credential stuffing*. https://owasp.org/www-community/attacks/Credential_stuffing
3. OWASP Cheat Sheet Series. (s.f.). *Password Storage Cheat Sheet*. OWASP Foundation. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
4. National Institute of Standards and Technology. (2025). *NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Authenticator Management, Revision 4*. https://pages.nist.gov/800-63-4/sp800-63b.html
5. BleepingComputer. (2020, 13 de abril). *Over 500,000 Zoom accounts sold on hacker forums, the dark web*. https://www.bleepingcomputer.com/news/security/over-500-000-zoom-accounts-sold-on-hacker-forums-the-dark-web/