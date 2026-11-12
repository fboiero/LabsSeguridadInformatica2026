# Research — Lab Extra SSRF · El metadata service de la nube (Opción B)

**Grupo:** 08 · **Fecha:** 08/11/2026

**Declaración de uso de IA:** se usó Claude (Anthropic) vía Claude Code para
estructurar el texto y resumir las fuentes. El grupo leyó y verificó cada
afirmación contra la documentación oficial citada; las fuentes están al pie.

---

Elegimos investigar el **Instance Metadata Service (IMDS)**, el servicio que
mejor explica por qué un SSRF en la nube es catastrófico — y que conecta
directamente con el R1 de este lab.

## 1. ¿Qué información expone y a quién?

Toda instancia de cómputo en la nube (EC2 en AWS, VM en GCP/Azure) puede
consultar un servicio de metadatos en la dirección **link-local**
`169.254.169.254` (en GCP el nombre es `metadata.google.internal`, misma IP).
Es alcanzable **solo desde la propia instancia** — no tiene ruta desde afuera —
por lo que históricamente se asumió "de confianza". Expone:

- Datos de la instancia: ID, tipo, región, zona, IPs, user-data (scripts de
  arranque, que a veces contienen secretos).
- Lo crítico en AWS: bajo
  `http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol>`
  entrega **credenciales temporales** del rol IAM asociado a la instancia:
  `AccessKeyId`, `SecretAccessKey` y `Token` de sesión, con permisos de ese rol.

## 2. ¿Por qué un SSRF lo convierte en robo de credenciales?

El IMDS no pide autenticación: confía en que *cualquiera que pueda hablarle ya
está dentro de la instancia*. Un SSRF rompe ese supuesto: el atacante le pide a
la aplicación vulnerable que fetchee la URL del IMDS, y el pedido sale **desde la
instancia** (posición de red "de confianza"). En IMDSv1 bastaba un `GET`:

```
GET /preview?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/webapp-role
→ { "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." }
```

Con esas credenciales el atacante se autentica contra la API de AWS como si
fuera la instancia y pivota a todo lo que el rol permita (S3, RDS, etc.). Es
**robo de identidad de la máquina**, no de un dato puntual.

## 3. ¿Qué es IMDSv2 y qué ataque bloquea?

**IMDSv2** (AWS, 2019) agrega un handshake orientado a sesión: antes de leer
metadatos hay que pedir un token con un **`PUT`** a `/latest/api/token` enviando
la cabecera `X-aws-ec2-metadata-token-ttl-seconds`, y luego usar ese token en la
cabecera `X-aws-ec2-metadata-token` de cada `GET`. Esto bloquea el SSRF típico
porque la mayoría de las funciones vulnerables **solo hacen `GET` de una URL**:
no pueden emitir un `PUT` con cabeceras arbitrarias, así que nunca obtienen el
token. Además, las respuestas del IMDSv2 traen un TTL de red (hop limit) que
impide reenviarlas fuera de la instancia. IMDSv2 no "arregla" el SSRF, pero
corta el camino más jugoso (robo de credenciales IAM). Hoy AWS recomienda
forzar IMDSv2 (`HttpTokens: required`).

## 4. ¿Cómo se relaciona con lo que hicimos en R1?

En R1 le pedimos al `/preview` que fetcheara `http://127.0.0.1:9000/` y leímos un
panel que "solo escuchaba en localhost". El IMDS es el mismo patrón, llevado a la
nube: `169.254.169.254` es el "localhost de confianza" de una instancia cloud. La
diferencia es el **premio**: en el lab, un panel interno; en cloud, las llaves de
toda la cuenta. Idéntico mecanismo (un servicio que confía en la *ubicación de
red* del que pregunta), impacto incomparablemente mayor. El caso **Capital One
(2019)** es exactamente esto: un SSRF vía una WAF mal configurada leyó el IMDS,
obtuvo credenciales y exfiltró ~100 millones de registros de un bucket S3.

## Pregunta de cierre — SSRF vs. inyección de comandos (Lab 07)

- **Similitud:** en ambos el atacante **actúa a través del servidor**, usando su
  identidad y sus privilegios. "El server pide por vos" (SSRF) y "el server
  ejecuta por vos" (inyección de comandos) comparten la raíz: *input del usuario
  que termina controlando una acción del lado servidor que no debería controlar*.
  Los dos anulan el perímetro desde adentro.

- **Diferencia:** la inyección de comandos da **ejecución de código** en el host
  (RCE): leés archivos, corrés binarios, escalás, conseguís shell — control total
  de esa máquina. El SSRF "solo" te deja **hacer pedidos de red** desde el
  servidor: no ejecutás código en él, pero alcanzás todo lo que él alcanza
  (localhost, red interna, metadata cloud).

- **¿Cuál es más peligrosa?** En una sola máquina, la **inyección de comandos** es
  peor: RCE es el techo del impacto. Pero en una arquitectura **cloud/distribuida**
  el SSRF suele ser más grave de lo que parece: con un `GET` roba las credenciales
  IAM de la instancia y compromete **toda la cuenta** (decenas de servicios, datos
  de millones) sin ejecutar una sola línea en el servidor. Nuestra conclusión:
  la command injection tiene el peor impacto *local*; el SSRF tiene el peor
  impacto *de alcance* cuando hay una nube detrás. Capital One lo demuestra.

---

## Fuentes

- OWASP Top 10 (2021) — A10:2021 Server-Side Request Forgery (SSRF).
  https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- OWASP — Server Side Request Forgery Prevention Cheat Sheet.
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- AWS — Use IMDSv2 (Instance Metadata Service Version 2).
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- AWS — Retrieve instance metadata / `iam/security-credentials`.
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html
- GCP — VM metadata (`metadata.google.internal`, 169.254.169.254).
  https://cloud.google.com/compute/docs/metadata/overview
- Capital One / análisis del incidente SSRF→IMDS (2019). Krebs on Security:
  https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/
