# Mini-research — Laboratorio 05

**Grupo:** 06
**Tema elegido:** _(marcá uno)_

- [ ] **A.** El CVE-2015-3306 de ProFTPD 1.3.5: qué es el `mod_copy`, cómo se
      explota el comando `SITE CPFR/CPTO`, y por qué un banner de versión alcanza
      para saber que un servidor es vulnerable.
- [ ] **B.** Tipos de escaneo de `nmap` (`-sS` vs `-sT` vs `-sU` vs `-sV`):
      cómo funciona cada uno a nivel de paquetes TCP/IP y qué huella deja en el
      objetivo.
- [x] **C.** OSINT y recon pasivo: qué información de una organización se puede
      reunir **sin tocar** sus sistemas (certificados, DNS, buscadores, filtraciones)
      y por qué es tan valiosa para un atacante.
- [ ] **D.** El estándar CVSS: cómo se arma un score (vector base), qué
      significan sus métricas, y por qué "criticidad" no es lo mismo que "score".

---

## Desarrollo

### OSINT y reconocimiento pasivo

OSINT (_Open Source Intelligence_) consiste en recopilar y analizar información de fuentes abiertas para producir conocimiento útil. En seguridad informática permite conocer la exposición pública de una organización y orientar evaluaciones posteriores.

OSINT y reconocimiento pasivo no son equivalentes. Para este trabajo, se considera pasiva la consulta de información ya recopilada por terceros, sin enviar solicitudes a la infraestructura del objetivo. Que un dato sea público no significa que obtenerlo sea pasivo: visitar el sitio de la organización implica contactar su servidor.

Entre las fuentes que pueden consultarse se encuentran:

- **WHOIS y RDAP:** ofrecen datos del registro de dominios, como registrador, fechas y servidores de nombres, según el dominio y la información disponible. Algunos datos del titular pueden estar ocultos o sujetos a restricciones de acceso [2].
- **DNS pasivo e histórico:** las bases de terceros pueden mostrar asociaciones entre nombres, direcciones IP y proveedores. Los registros A, MX, NS y TXT ayudan a interpretar la infraestructura y los servicios utilizados [1][4]. Una consulta con `dig` no es necesariamente pasiva: si se dirige al servidor autoritativo del objetivo, interactúa con él. Incluso un resolvedor externo puede consultar al autoritativo si no tiene la respuesta en caché.
- **Certificate Transparency:** sus registros públicos permiten encontrar nombres incluidos en certificados. Estos datos son indicios: no demuestran que el servicio siga activo ni que el nombre conserve el mismo propietario [3].
- **Buscadores y repositorios de terceros:** pueden mostrar documentos, correos y referencias a tecnologías. Abrir contenido alojado directamente por el objetivo deja de cumplir la definición estricta de reconocimiento pasivo adoptada aquí.
- **Servicios de consulta de incidentes:** herramientas como Have I Been Pwned permiten identificar exposición histórica de datos asociados a cuentas. La aparición de un correo no demuestra que su contraseña actual esté comprometida, y la ausencia de resultados tampoco garantiza que nunca haya sido afectado [5].

Para un atacante, relacionar estos datos permite identificar posibles objetivos y preparar acciones posteriores. MITRE describe cómo la información DNS puede revelar proveedores, servidores de correo y oportunidades de reconocimiento adicional [1]. Desde la defensa, las mismas fuentes ayudan a revisar la exposición pública y detectar información desactualizada o innecesaria. Consultar terceros evita el contacto directo con el objetivo, pero no garantiza anonimato: cada servicio puede aplicar sus propias políticas de registro.

En el Laboratorio 05 se utilizaron `nmap` y `curl` para identificar servicios y consultar directamente servidores de PhantomCorp, lo que corresponde a reconocimiento activo. También se realizaron consultas con `whois` y `dig` sobre un dominio de prueba. Su clasificación depende de los servidores consultados y del tráfico generado, no solo del nombre de la herramienta.

## Reflexión

La distinción principal es que información pública no significa obtención pasiva. Para clasificar una actividad hay que observar con quién interactúa la herramienta y de dónde provienen los datos. En PhantomCorp, `nmap` y `curl` fueron activos porque se comunicaron con el target, mientras que las consultas sobre dominios de prueba sirvieron para analizar el alcance y las huellas de WHOIS y DNS. Además, los resultados históricos deben tratarse como indicios que requieren contexto, no como pruebas de que un servicio sigue activo o una cuenta continúa comprometida.

## Fuentes

1. MITRE ATT&CK. _Gather Victim Network Information: DNS — T1590.002_. https://attack.mitre.org/techniques/T1590/002/
2. ICANN. _Registration Data Access Protocol (RDAP)_. https://www.icann.org/rdap/
3. Google. _What is Certificate Transparency (CT)?_ https://developers.google.com/public-key-infrastructure/faq/what-is-certificate-transparency
4. Cloudflare. _DNS record types_. https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/
5. Have I Been Pwned. _Frequently Asked Questions_. https://haveibeenpwned.com/FAQs
