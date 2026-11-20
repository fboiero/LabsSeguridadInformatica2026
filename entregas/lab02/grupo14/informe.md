# Informe — Laboratorio 02 · Criptografía

**Grupo:** 14 · **Integrantes:** Laureano Gomez Redondo — Laureano-GR, Martin Gaido — martinagaidoo, Valentina Chiapero — valechiapero, Martin Cesano — MartinCesano, Fede Perón — fedeeperon · **Fecha:** 16 de octubre de 2026

## 0. Declaración de uso de IA

Se utilizó ayuda de IA (ChatGPT) únicamente para comprender los enunciados y revisar la sintaxis de Python, no para generar el código de implementación.

## 1. Parte A — Análisis de la falla

**Caso:** Zoom E2E

### A.1 — Qué prometía
Zoom E2E prometía cifrado de extremo a extremo en sus reunencias, asegurando que solo los participantes autorizados podían acceder al contenido de las llamadas. La encriptación se realizaría en el dispositivo del remitente y se descifraría únicamente en el dispositivo del destinatario, con claves gestionadas por los propios usuarios.

### A.2 — El mal uso
Se descubrió que la implementación de E2E en Zoom tenía vulnerabilidades en el manejo de claves de sesión. En ciertos escenarios, las claves podían ser derivadas predeciblemente o intercambiadas de manera insegura, violando el principio de clave secreta. Además, había reportes de que metadatos de las llamadas (quién habló cuándo, duración) no estaban protegidos.

### A.3 — Propiedad rota y explotación
La vulnerabilidad permitía a un atacante intermediario (MITM) secuestrar la sesión de una llamada Zoom y forzar el descifrado del tráfico. Al explotar la falla en el intercambio de claves, el atacante podría injectar comandos o visualizar el contenido de la reunión sin que los participantes lo sospechen. Esto afecta la confidencialidad de todas las comunicaciones en la plataforma.

### A.4 — Lo correcto
La implementación adecuada de E2E debe usar intercambio de claves segur (como Diffie-Hellman), firmas digitales para autenticar los extremos, y cifrado simétrico con claves rotadas por sesión. Cada extremo debe verificar la identidad del otro antes de establecer la canalización de datos cifrada.

## 2. Parte B.1 — Romper el XOR

### Romper XOR de clave de 1 byte
Se implementó la función `romper_xor_1byte()` que usa análisis de frecuencia para adivinar la clave de 1 byte. La función prueba las 256 claves posibles y puntúa cada candidato basándose en cuántos bytes del texto resultante caen en un conjunto de caracteres frecuentes en español (espacios, vocales, consonantes comunes, dígitos, puntuación). La clave con mayor puntuación se selecciona como la más probable.

**Resultado:** Dado el mensaje "Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa." cifrado con clave 0x37, la función `romper_xor_1byte` recupera correctamente la clave 0x37 y el texto en claro.

### Clave hallada
- Clave: 0x37
- Mensaje en claro: Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

**Por qué el cifrado clásico falla:** El cifrado XOR de clave corta es vulnerable porque, al tener solo 1 byte de clave, puede romperse fácilmente por análisis de frecuencia. El español (y cualquier idioma con distribución de caracteres no uniforme) tiene patrones estadísticos claros que permiten adivinar la clave sin conocela previamente. Esto demuestra que el cifrado de clave simétrica corta NO protege los datos y debe evitarse en cualquier escenario de seguridad.

## 3. Parte B.2 — Autenticación

### B.2.1 length-extension
El MAC ingenuo `sha256(clave || msg)` es vulnerable a ataques de extensión de longitud. Dado que SHA-256 procesa bloques, un atacante que conozca `sha256(clave || msg)` puede calcular `sha256(clave || msg || padding || nuevo_msg)` sin conocer la clave, simplemente adicionando padding y el nuevo mensaje al final. Esto rompe la integridad porque el atacante puede extender el mensaje y el MAC simultáneamente sin saber la clave secreta.

### B.2.2 cómo lo resuelve HMAC
HMAC (Hash-based Message Authentication Code) previene el length-extension usando la estructura interna `H(key || H(key || msg))`. Esta doble hashing con la clave dentro de ambas capas asegura que cualquier cambio en la longitud o contenido del mensaje cambie el resultado de manera impredecible. Incluso si el atacante conoce el MAC actual, no puede extender el mensaje porque la operación interna de HMAC lo impide matemáticamente.

### B.2.3 tiempo constante
La comparación `verificar_mac()` debe usar `hmac.compare_digest()` para comparar los MACs en tiempo constante. Esto evita ataques de canal lateral por tiempo donde un atacante mide cuánto tiempo toma la comparación para inferir información sobre el MAC correcto. La comparación en tiempo constante asegura que el tiempo de ejecución sea el mismo independientemente de cuántos bytes coincidan, haciendo imposibles los ataques de timing.

## 4. Bitácora

Comandos ejecutados durante el laboratorio:
- `python3 data/generar_datos.py` — generó data/muestra/reto_xor.hex
- `python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)` — rompió el cifrado XOR
- `python3 src/cripto.py mac --clave "k" --msg "m"` — probó el MAC ingenuo
- `python3 src/cripto.py mac --clave "k" --msg "m" --modo hmac` — probó el HMAC
- `python3 verificar.py` — autoevaluación del laboratorio

## 5. Declaración de uso de IA

Se utilizó ayuda de IA (ChatGPT) únicamente para comprender los enunciados y revisar la sintaxis de Python, no para generar el código de implementación. Todas las funciones fueron implementadas desde cero por los integrantes del grupo.

## 6. INTEGRANTES

**Laureano Gomez Redondo** — laureanogore004@gmail.com — Implementó `romper_xor_1byte` y revisión de frecuencia de caracteres.

**Martin Gaido** — martinagaido00@gmail.com — Implementó `mac_ingenuo` y documentación de la vulnerabilidad length-extension.

**Valentina Chiapero** — v08.03.00@gmail.com — Completó el informe, bitácora y declaración de uso de IA.

**Martin Cesano** — cesano305@gmail.com — Implementó `verificar_mac` con `hmac.compare_digest`.

**Fede Perón** — peronfedee@gmail.com — Implementó `mac_hmac` usando el módulo hmac.