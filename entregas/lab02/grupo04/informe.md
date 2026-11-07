# Laboratorio 02 — Criptografía

**Grupo:** 04

**Integrantes:**
- Uriel Olivero — @uRIELoLIVERO
- Jeremias Antunez — @JereAntunez
- Facundo Anil — @FacundoAnil4
- Matias Lelli — @LelliMatias

**Fecha:** 2026-11-06

---

## Parte A — Análisis de falla criptográfica: Zoom "E2E" (caso 4)

### A.1 — Qué prometía el sistema

En abril de 2020, Zoom Video Communications afirmó públicamente que sus videollamadas usaban **cifrado end-to-end (E2E)**, tanto en comunicados de prensa como en su white paper técnico [1]. El cifrado E2E implica que únicamente los participantes de la comunicación pueden descifrar su contenido. Ni Zoom ni ningún intermediario debería tener acceso a las claves necesarias para recuperar la información, garantizando así la confidencialidad frente a terceros, incluida la propia empresa.

### A.2 — Cuál fue el mal uso concreto

La investigación de Citizen Lab (abril de 2020) reveló que lo que Zoom llamaba "E2E" era en realidad **cifrado en tránsito con gestión centralizada de claves** [2]:

1. **Las claves de sesión (AES-128) eran generadas y distribuidas por los servidores de Zoom**, no derivadas localmente por los clientes.
2. El cliente cifra el audio y video con esa clave, pero como la clave está disponible para Zoom, la empresa —o quien comprometiera sus servidores— podía descifrar las comunicaciones.
3. Adicionalmente, se detectó que algunos paquetes de llamadas dentro de EE. UU. eran enrutados a través de servidores en China, con claves generadas allí [2].
4. El cifrado AES-128 en modo ECB utilizado para proteger el audio y video de las reuniones también fue señalado como una debilidad [2]. ECB es determinístico: bloques de texto plano idénticos producen bloques cifrados idénticos, lo que permite revelar patrones de la información original. Por este motivo, no es adecuado para cifrar datos multimedia.

Aunque AES es un algoritmo criptográfico seguro, el modo ECB no proporciona las propiedades de seguridad necesarias para este escenario. Sin embargo, el problema central identificado por Citizen Lab fue la arquitectura de gestión y distribución de claves: Zoom tenía acceso a las claves de sesión, por lo que no podía garantizar un cifrado verdaderamente end-to-end.

### A.3 — Qué propiedad se rompió y cómo se explotó

La propiedad principal comprometida fue la **confidencialidad**, ya que Zoom tenía acceso a las claves criptográficas necesarias para descifrar las comunicaciones. Esto contradice directamente la garantía de cifrado end-to-end que la plataforma afirmaba ofrecer.

La autenticidad de las afirmaciones de seguridad también quedó cuestionada, aunque no debe confundirse con la autenticidad criptográfica de los mensajes.

**Mecanismo de explotación potencial:**

- Zoom, al controlar la infraestructura que generaba y distribuía las claves de sesión, tenía la capacidad técnica de descifrar las comunicaciones.
- Un atacante externo que consiguiera comprometer los servidores o acceder a las claves de sesión podría utilizarlas para descifrar el tráfico correspondiente, sin necesidad de romper AES ni ningún otro algoritmo criptográfico.

Es importante distinguir entre la capacidad de acceso de Zoom y un ataque externo efectivo: la investigación identificó una debilidad arquitectónica, no demostró que un atacante externo hubiera descifrado masivamente las llamadas.

La FTC (Comisión Federal de Comercio de EE. UU.) inició acciones contra Zoom y en 2020 llegó a un acuerdo por afirmaciones engañosas sobre sus prácticas de seguridad [3].

### A.4 — La forma correcta de haberlo hecho

Implementar un sistema de cifrado end-to-end real, en el que las claves de sesión se establezcan y gestionen exclusivamente entre los dispositivos participantes mediante protocolos criptográficos auditados. Los servidores de Zoom deberían limitarse a retransmitir información cifrada, sin tener acceso a las claves necesarias para descifrar las comunicaciones. Para las reuniones grupales, también deberían utilizarse mecanismos seguros de distribución y actualización de claves.

**Fuentes:**

[1] Zoom Video Communications, *Zoom Security White Paper* (versión de marzo de 2020, archivada).  
https://web.archive.org/web/20200401000000*/zoom.us/docs/doc/Zoom%20Security%20White%20Paper.pdf

[2] B. Marczak, J. Scott-Railton, "Move Fast and Roll Your Own Crypto", Citizen Lab, University of Toronto, 3 de abril de 2020.  
https://citizenlab.ca/2020/04/move-fast-roll-your-own-crypto-a-quick-look-at-the-confidentiality-of-zoom-meetings/

[3] Federal Trade Commission, "FTC Requires Zoom to Enhance its Security Practices as Part of Settlement", 9 de noviembre de 2020.  
https://www.ftc.gov/news-events/news/press-releases/2020/11/ftc-requires-zoom-enhance-its-security-practices-part-settlement

[4] Zoom Blog, "Zoom's E2E Encryption Rolls Out", 26 de octubre de 2020.  
https://blog.zoom.us/zoom-rolling-out-end-to-end-encryption-offering/

---

## Parte B — Implementación

### B.1 — Reto XOR resuelto

El archivo `data/muestra/reto_xor.hex` se genera con `python3 data/generar_datos.py`.

Comando ejecutado:

```bash
python3 src/cripto.py romper --hex "$(cat data/muestra/reto_xor.hex)"
```

**Resultado de la ejecución original registrada:**

| Campo | Valor |
|---|---|
| Clave hallada | `0x7f` (127 decimal) |
| Texto en claro | `PhantomCorp confidential: operacion AURORA autorizada para el 2024-03-15. Coordinar con agentes en nodos 7, 12 y 19. Clave de sesion: DELTA-BRAVO-9.` |

**Lección:** con una clave de 1 byte solo hay 256 posibilidades. El análisis de frecuencia de caracteres permite elegir el texto más probable sin conocer previamente el mensaje. La longitud y aleatoriedad de la clave son fundamentales.

**Nota:** el generador crea una clave aleatoria nueva cada vez. Si se vuelve a generar el reto, hay que actualizar la clave y comprobar que el texto en claro del informe corresponde al archivo que se entrega.

### B.2 — Autenticación de mensajes: ingenuo vs. HMAC

#### B.2.1 — ¿Por qué `sha256(clave || mensaje)` permite length-extension?

SHA-256 pertenece a la familia Merkle–Damgård: procesa el input en bloques y al terminar expone su estado interno como digest. Eso lo hace vulnerable al **ataque de extensión de longitud** (*length-extension attack*):

1. El atacante observa `MAC = SHA256(clave || mensaje)` y la longitud aproximada de `clave || mensaje`.
2. Para realizar el ataque, necesita conocer o estimar la longitud de la clave secreta, ya que esta información es necesaria para reconstruir correctamente el padding original de SHA-256. Si desconoce la longitud exacta, puede probar diferentes valores posibles.
3. Sin conocer la clave, inicializa SHA-256 con el estado interno reconstruido a partir de `MAC`, y continúa el hash añadiendo bytes arbitrarios tras el padding original.
4. Obtiene `SHA256(clave || mensaje || padding_interno || texto_extra)`, una MAC válida para un mensaje extendido, sin conocer la clave secreta.

**Ejemplo concreto:** si un servidor acepta `SHA256("s3cr3t" || "monto=100")` como MAC válida, un atacante que conoce la etiqueta puede intentar generar una firma válida para un mensaje extendido que agregue parámetros como `&admin=true`. El mensaje resultante contiene el padding interno de SHA-256, por lo que el servidor debe procesarlo correctamente y aceptar la interpretación del nuevo parámetro para que la falsificación tenga efecto. Todo esto puede realizarse sin conocer la clave secreta.

#### B.2.2 — ¿Cómo lo resuelve HMAC estructuralmente?

HMAC rompe la vulnerabilidad de la construcción ingenua mediante **dos hashes anidados** con rellenos de clave distintos (definidos en RFC 2104):

```text
HMAC(k, m) = SHA256((k xor opad) || SHA256((k xor ipad) || m))
```

- El hash **interno** procesa `(k xor ipad) || m` y produce un digest intermedio.
- El hash **externo** procesa `(k xor opad) || digest_interno`.

Aunque un atacante pudiera realizar una extensión sobre el hash interno, el resultado no permitiría generar una MAC HMAC válida. Esto se debe a que la etiqueta final depende de un segundo hash que procesa la clave combinada con `opad` y el resultado del hash interno. Sin conocer la clave, el atacante no puede construir correctamente esta capa externa. Por lo tanto, la extensión del hash interno no se traduce en una falsificación válida de HMAC.

**Referencia:** H. Krawczyk, M. Bellare, R. Canetti, RFC 2104, 1997.  
https://datatracker.ietf.org/doc/html/rfc2104

#### B.2.3 — ¿Qué ataque evita `hmac.compare_digest`? Ejemplo concreto.

Evita los ataques de temporización (*timing attacks*), una variante de los ataques de canal lateral (*side-channel attacks*).

**Mecanismo:**

Una comparación convencional de cadenas puede finalizar anticipadamente cuando encuentra el primer carácter diferente. Esto puede generar diferencias en el tiempo de ejecución dependiendo de cuántos caracteres coincidan.

Un atacante que pueda medir repetidamente el tiempo de respuesta de un endpoint que verifica MAC podría aprovechar esas diferencias para intentar deducir progresivamente los bytes correctos de una etiqueta.

Por ejemplo:

1. Envía una MAC cuyo primer byte considera correcto y el resto incorrecto.
2. Si la comparación tarda ligeramente más que con una MAC cuyo primer byte también es incorrecto, podría inferir que acertó esa posición.
3. Repite el procedimiento para las posiciones siguientes, intentando reconstruir la etiqueta válida.

**Ejemplo concreto:** un endpoint `/api/pagar?mac=XXXX` verifica la MAC recibida. Si utiliza una comparación convencional que retorna al encontrar el primer byte diferente, un atacante podría medir los tiempos de respuesta para intentar recuperar progresivamente la MAC correcta sin conocer la clave secreta.

**`hmac.compare_digest`** evita este comportamiento al realizar una comparación que no presenta cortocircuitos dependientes del contenido de los valores comparados. De esta manera, se reduce la posibilidad de que el tiempo de ejecución revele cuántos bytes coinciden.

Es importante aclarar que no garantiza un tiempo absolutamente constante en todas las circunstancias: las diferencias de longitud o tipo pueden seguir proporcionando información temporal. Por eso también es conveniente validar previamente el formato y la longitud de las MAC recibidas.

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA?** Sí.

| Herramienta | Uso y alcance | Verificación |
|---|---|---|
| Claude (Anthropic) | redacción del informe (Parte A — caso Zoom E2E y Parte B ), y elaboración del mini-research sobre ataques de extensión de longitud. | Las fuentes citadas fueron verificadas por los integrantes del grupo: se comprobó que las URLs son accesibles y que las afirmaciones del informe corresponden al contenido referenciado. |

**Verificación de fuentes:** las referencias del informe fueron consultadas y contrastadas con el contenido generado. La revisión técnica del código y la validación de los resultados (reto XOR, MACs) corresponden a los
integrantes del grupo.