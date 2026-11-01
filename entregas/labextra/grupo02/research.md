# Research — Lab Extra: SSRF

**Grupo:** 02 · **Autor de esta parte:** Torres Damaris — @damaris412

**Declaración de uso de IA:** usamos Claude (Anthropic) para ayudar a organizar
y redactar este research; los hechos y cifras se tomaron de las fuentes citadas
abajo y se contrastaron con la descripción técnica del caso. La conexión con lo
que hicimos en el lab es propia.

**Opción elegida:** A — Un caso real (Capital One, 2019), que además nos deja
explicar el metadata service de la Opción B.

---

## El caso: Capital One (2019)

En julio de 2019 Capital One —uno de los bancos más grandes de EE.UU.— reveló
una brecha que expuso datos de aproximadamente **100 millones de personas en
EE.UU. y 6 millones en Canadá**: solicitudes de tarjetas de crédito, nombres,
direcciones, scores crediticios y, en subconjuntos menores, números de seguridad
social y de cuentas bancarias. La infraestructura afectada estaba alojada en
AWS. La atacante fue identificada y el caso terminó con condena penal y una
multa de **USD 80 millones** de la OCC al banco.

### 1. ¿Qué funcionalidad era vulnerable?
Un **WAF (Web Application Firewall) mal configurado** que Capital One operaba
sobre sus aplicaciones en AWS. El WAF podía ser inducido a realizar peticiones
hacia donde el atacante indicara: es decir, era explotable como **SSRF**. El
problema no fue una "rotura" del sistema, sino que un componente de borde podía
hacer pedidos server-side sin restringir el destino.

### 2. ¿Qué pidió el atacante a través del servidor?
A través del SSRF, la atacante alcanzó el **Instance Metadata Service** de AWS en
`http://169.254.169.254/`. Esa dirección link-local devuelve metadatos de la
instancia EC2, incluidas las **credenciales temporales del rol IAM** que la
instancia (y el WAF) tenían asignado:

```
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<rol-del-WAF>
```

El servidor, que sí podía hablar con el metadata service, devolvió esas claves.

### 3. ¿Qué obtuvo y cuál fue el impacto?
Con esas credenciales temporales —válidas y con los permisos del rol del WAF— la
atacante ejecutó un `List Buckets` de S3 y luego un `Sync` que descargó el
contenido de los buckets a los que el rol tenía acceso. Ahí estaban los datos de
los ~106 millones de clientes. El SSRF no robó los datos directamente: robó las
**llaves**, y las llaves abrieron el almacenamiento. Impacto: la mayor brecha
bancaria de datos personales de EE.UU. de ese año, con costo reputacional,
regulatorio (multa de USD 80M) y legal.

### 4. ¿Qué mitigación lo habría impedido?
- **IMDSv2.** La defensa más directa y específica: AWS introdujo la versión 2 del
  metadata service, que exige obtener primero un token con una request `PUT`
  (con un header especial y TTL de salto limitado) y usarlo en las requests
  siguientes. Un SSRF simple de solo-`GET` —como el de este ataque— no puede
  completar ese handshake, de modo que no llega a las credenciales. Hoy conviene
  forzar `imds v2 only` en las instancias.
- **Principio de mínimo privilegio en el rol IAM:** si el rol del WAF no hubiera
  tenido permiso de lectura sobre esos buckets, las credenciales robadas habrían
  servido para mucho menos.
- **Corregir el SSRF en origen:** validar/allowlist del destino y bloqueo de la
  IP de metadata (`169.254.169.254`) a nivel de red. Es la misma mitigación que
  proponemos para el `/preview` de nuestro lab (P4).

## Relación con lo que hicimos en el lab (R1)
En nuestro R1 le pedimos al server que fetcheara `http://127.0.0.1:9000/` y nos
devolvió un panel que "solo escuchaba en localhost". Capital One es la versión
cloud del mismo movimiento: en lugar de `127.0.0.1` pidieron
`169.254.169.254`, otra dirección que **solo es alcanzable desde la propia
máquina**. La diferencia de impacto es brutal: nuestro localhost tenía una
"deploy key" de juguete; el localhost de la nube tiene las credenciales de toda
la cuenta. La lección es la misma que vimos en P1: confiar en "esto solo se
alcanza desde adentro" deja de valer cuando un servicio fetchea URLs arbitrarias.

## Pregunta de cierre: SSRF vs. inyección de comandos
**Similitud:** en ambos el servidor hace algo *por vos* abusando de su posición y
sus privilegios. En SSRF el server **pide** por vos (usás su ubicación de red);
en inyección de comandos (Lab 07) el server **ejecuta** por vos (usás su
identidad en el sistema operativo). En los dos casos el atacante no toca
directamente el recurso final: lo toca el servidor en su nombre.

**Diferencia y cuál es más peligrosa:** la inyección de comandos suele ser *más*
peligrosa en una sola máquina, porque da ejecución de código arbitrario —control
total del host, incluido leer/escribir archivos y, muchas veces, pivotar. El
SSRF está más "acotado" a hacer requests. **Pero** en arquitecturas cloud/red
interna el SSRF puede ser igual de catastrófico con un solo `GET`: como mostró
Capital One, alcanza el metadata service y se lleva las credenciales de la cuenta
entera sin ejecutar un solo comando. Nuestra conclusión: la inyección de comandos
es más potente por request, pero el SSRF es más *subestimado* —parece "solo leer
una URL" y termina siendo robo de credenciales cloud. El contexto decide: en un
server aislado, RCE; en la nube, SSRF al metadata es tan grave como un RCE.

## Fuentes

- Krebs on Security — *What We Can Learn from the Capital One Hack* (2019).
  https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/
- AWS — *Use IMDSv2* (documentación de EC2 Instance Metadata Service).
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
- OWASP — *Server-Side Request Forgery (SSRF)* / A10:2021.
  https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- U.S. OCC — *OCC Assesses $80 Million Civil Money Penalty Against Capital One* (2020).
  https://www.occ.gov/news-issuances/news-releases/2020/nr-occ-2020-101.html
- MITRE — *CWE-918: Server-Side Request Forgery (SSRF)*.
  https://cwe.mitre.org/data/definitions/918.html
