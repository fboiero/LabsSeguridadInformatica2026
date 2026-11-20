# Informe de Penetration Test — PhantomCorp «Clientes»

**Grupo:** 06
**Fecha:** 30/10/2026
**Cliente:** PhantomCorp S.A. · **Tipo:** Caja negra · **Alcance:** host `phantomcorp` del laboratorio

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

Usamos asistentes de IA como apoyo para el reconocimiento, el ordenamiento de las evidencias y la redacción. En todos los casos ejecutamos las pruebas nosotros contra el entorno autorizado y contrastamos cada afirmación del informe con las salidas crudas antes de incorporarla. Ningún resultado, flag ni estado de validación proviene de la IA: provienen de las respuestas reales del objetivo.

| Integrante       | Herramienta                         | En qué se usó                                                                            | Cómo se verificó                                                                                                                                                                 |
| ---------------- | ----------------------------------- | ---------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Martín Beccereca | Codex                               | Reconocimiento, pruebas controladas de autenticación y registro de evidencias de R1–R2.  | Contrastamos cada respuesta HTTP y el cambio de comportamiento ante las solicitudes contra las salidas guardadas.                                                                |
| Belén Benito     | Chatgpt                             | Integración del informe y verificación independiente del recorrido completo.             | Reprodujo R1–R4 en el entorno autorizado y registró el estado oficial del CTF (4/4).                                                                                             |
| Alejo De Miguel  | Claude (Anthropic), vía Claude Code | Post-explotación de R3 y estructura del hallazgo H-03 (CVSS, remediación, limitaciones). | Ejecutó la solicitud a `/backup/rrhh.conf`, el control negativo (404) y la validación de R3; revisó el texto contra la evidencia cruda.                                          |
| Tomás Giudici    | Codex                               | Reconocimiento inicial y captura de evidencias de R1.                                    | Comprobó las respuestas del portal y de `robots.txt` contra las salidas guardadas.                                                                                               |
| Carolina Suppo   | Opencode                            | Análisis de impacto de R4 y revisión de la priorización de remediaciones.                | Contrastó las respuestas de `/api/reporte`, el conteo y el contenido limitado del recurso de clientes con las salidas crudas; no se afirma extracción de registros individuales. |

## 1. Resumen ejecutivo

Contratados por PhantomCorp, evaluamos en modalidad de caja negra el sistema «Clientes», sin credenciales ni documentación previa y únicamente dentro del entorno autorizado. En pocas horas logramos tomar el control del servicio y llegar hasta el archivo que concentra los datos de clientes.

El sistema quedó comprometido por completo. Partiendo de internet y sin ninguna clave, un atacante puede encadenar cuatro fallas hasta ejecutar órdenes en el servidor con el máximo nivel de privilegio y alcanzar la base de clientes, que según el propio sistema reúne **48.210 personas con nombre, DNI y número de tarjeta**. No hubo ninguna barrera que detuviera la secuencia completa.

El riesgo para el negocio es alto. La exposición de nombre, DNI y tarjeta de decenas de miles de clientes implica incumplimiento de la Ley 25.326 de Protección de Datos Personales, obligaciones frente a las marcas de tarjetas (PCI-DSS) y un daño de reputación difícil de revertir. El control total del servidor permitiría, además, alterar o destruir información; en esta auditoría nos limitamos a demostrarlo sin tocar los datos.

**Recomendación prioritaria:** eliminar de inmediato la funcionalidad que permite ejecutar comandos del sistema a través de la API de reportes y quitar del servicio web el archivo de configuración que publica las claves. Son las dos medidas que cortan la cadena de ataque demostrada.

| Severidad   | Cantidad de hallazgos |
| ----------- | --------------------- |
| Crítica     | 1                     |
| Alta        | 2                     |
| Media       | 0                     |
| Baja        | 0                     |
| Informativa | 1                     |

## 2. Alcance y metodología

Evaluamos el servicio HTTP de `phantomcorp` desde la consola atacante `cyberlab-attacker`, ambos en la red `cyberlab_labnet`. Levantamos el entorno oficial con Docker Compose (equivalente a `make lab N=final`) y no modificamos el objetivo ni consultamos su código fuente, sus soluciones ni el manifiesto de retos para descubrir rutas o flags. No escaneamos otros hosts, no ejecutamos acciones destructivas y no realizamos extracción masiva de datos ni denegación de servicio. La ventana autorizada es la fijada por la cátedra.

Seguimos el marco habitual de una auditoría encadenada:

- **Reconocimiento y enumeración.** Página inicial, `robots.txt`, la ruta anunciada y una ruta inexistente como control. Estas solicitudes se realizaron el 28/10/2026 entre las 17:10:20 y las 17:10:31 UTC, según las cabeceras del servidor.
- **Explotación.** Dos solicitudes POST controladas al formulario de acceso: una con credenciales inválidas, como línea base, y otra con una condición booleana para comprobar la hipótesis de inyección SQL.
- **Post-explotación.** Consulta al archivo de configuración señalado por el acceso anterior, con un control negativo para confirmar que el recurso existe realmente.
- **Impacto.** Uso del token obtenido para enumerar y leer, en modo solo lectura, el recurso que contiene los datos de clientes.

Todas las solicitudes usaron un tiempo máximo de diez segundos.

| Recurso observado         | Resultado                                | Evidencia                            |
| ------------------------- | ---------------------------------------- | ------------------------------------ |
| `http://phantomcorp/`     | 200, portal público sin enlaces visibles | `evidencia/salidas/p1-inicio.txt`    |
| `/robots.txt`             | 200; anuncia `/portal-rrhh`              | `evidencia/salidas/p1-robots.txt`    |
| `/portal-rrhh`            | 200; portal interno y formulario         | `evidencia/salidas/p1-r1-portal.txt` |
| `/p1-control-inexistente` | 404, Not Found                           | `evidencia/salidas/p1-control.txt`   |

Las cabeceras declaran `PhantomClientes/2.0`; es un banner observado, no una identificación independiente del software. La comparación con el 404 de control muestra que el portal no es una respuesta genérica para cualquier ruta.

## 3. Narrativa del ataque

```
recon/enum  ->  foothold (SQLi)  ->  loot (token)  ->  impacto (RCE root -> datos)
```

**Reconocimiento y enumeración.** La página inicial respondió con un portal público, sin enlaces al portal interno. Consultamos `robots.txt`, un recurso habitual de enumeración, y su línea `Disallow: /portal-rrhh` nos dio una ruta concreta. Al solicitarla, el servidor devolvió el título «Portal RRHH PhantomCorp», un formulario `POST` hacia `/portal/login` con los campos `user` y `pass`, y la flag `FLAG{final_recon_portal}` en un comentario HTML.

**Acceso sin credenciales válidas.** Establecimos una línea base enviando credenciales inválidas a `POST /portal/login`: el servidor respondió `401 Unauthorized`. Luego una solicitud con `user=' OR '1'='1' -- ` y `pass=x` devolvió `200 OK`, el mensaje «Bienvenido admin. Dashboard RRHH.» y la flag `FLAG{final_sqli_foothold}`. El cambio de 401 a 200 con una contraseña sin valor confirma el bypass de autenticación. La misma respuesta señaló el recurso `/backup/rrhh.conf`.

**Loot del secreto.** Solicitamos `/backup/rrhh.conf` sin credenciales ni cookie de sesión y recibimos `200 OK`. El archivo exponía, en texto plano, credenciales de base de datos y un token de API, junto con la flag `FLAG{final_token_looted}`. Un control negativo contra una ruta inexistente bajo `/backup/` devolvió `404`, lo que descarta que ese prefijo responda igual para cualquier ruta. Este archivo se obtuvo sin pasar por el portal, por lo que la exposición no depende del bypass de SQL.

**Impacto sobre los datos de clientes.** Con el token accedimos a `/api/reporte`. La solicitud sin `cmd` devolvió el resultado de `id` con `uid=0(root)`: el servicio ejecuta comandos como root. Con órdenes de solo lectura enumeramos el directorio `priv` y consultamos la primera línea de `clientes.db.txt`, que informó 48.210 registros con los campos nombre, DNI y tarjeta, junto con la flag `FLAG{final_crown_jewels}`. No extrajimos registros individuales ni modificamos datos.

## 4. Hallazgos (detalle técnico)

Ordenados de mayor a menor severidad.

### H-01 — Ejecución de comandos del sistema como root mediante la API de reportes

- **Severidad:** Crítica · **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (9.8)
- **Ubicación:** `GET /api/reporte`, parámetros `token` y `cmd`.
- **Descripción:** el endpoint ejecuta en el servidor los comandos recibidos en `cmd` y devuelve su salida. El proceso corre como `root`. El único control previo es un token estático, que se obtiene sin autenticación desde el archivo del hallazgo H-02 (ver más abajo); por eso, en la práctica, llegar a esta ejecución no requiere privilegios.
- **Evidencia reproducible:**
  ```bash
  TOKEN=$(curl -fsS --max-time 10 http://phantomcorp/backup/rrhh.conf | sed -n 's/^API_TOKEN=//p')
  curl -sS -i --max-time 10 --get --data-urlencode "token=$TOKEN" http://phantomcorp/api/reporte
  curl -sS -i --max-time 10 --get --data-urlencode "token=$TOKEN" --url "http://phantomcorp/api/reporte?cmd=ls+priv"
  curl -sS -i --max-time 10 --get --data-urlencode "token=$TOKEN" --url "http://phantomcorp/api/reporte?cmd=head+-n+1+priv/clientes.db.txt"
  ```
  Respuestas (`evidencia/salidas/p4-r4-identidad.txt`, `p4-r4-recurso.txt`, `p4-r4-impacto.txt`):
  ```
  $ id
  uid=0(root) gid=0(root) groups=0(root)
  $ ls priv
  clientes.db.txt
  $ head -n 1 priv/clientes.db.txt
  clientes: 48210 registros (nombre, DNI, tarjeta). FLAG{final_crown_jewels}
  ```
- **Impacto:** ejecución remota de comandos con privilegios de root sobre el host del servicio. Demostramos lectura del recurso que, según su propia primera línea, representa 48.210 registros con nombre, DNI y tarjeta. La ejecución como root habilita además leer, modificar o destruir cualquier archivo del contenedor; no ejecutamos esas acciones por las reglas del engagement.
- **CVSS — justificación:** el vector es remoto (`AV:N`), de baja complejidad (`AC:L`), sin interacción (`UI:N`). Asignamos `PR:N` porque el token que nominalmente protege el endpoint se sirve sin autenticación en H-02; quien alcanza el servidor puede obtenerlo sin credenciales. La ejecución como root justifica impacto alto en confidencialidad, integridad y disponibilidad. Si se valorara el token como un privilegio real (`PR:L`), el score sería 8.8; aun en ese caso, el riesgo de la cadena completa es crítico.
- **Remediación:** eliminar la ejecución de comandos del sistema desde la API. Si se necesita una función de reporte, implementarla como una operación fija que consulte solo los datos autorizados mediante consultas parametrizadas, sin invocar un shell. Ejecutar el servicio con una cuenta sin privilegios (`USER` no-root en el Dockerfile) y restringir el endpoint por autenticación y autorización. Verificar que `cmd` deje de interpretarse como comando del sistema.
- **Limitación:** las pruebas fueron de solo lectura. No modificamos datos, no realizamos acciones destructivas ni recuperamos registros individuales.

### H-02 — Exposición pública de un archivo de configuración con credenciales y token de API

- **Severidad:** Alta · **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5)
- **Ubicación:** `GET /backup/rrhh.conf`.
- **Descripción:** el servidor entrega por HTTP, sin autenticación ni sesión, un archivo de configuración en texto plano con credenciales de base de datos y un token de API. La única barrera es conocer la ruta, que la respuesta del acceso al portal reveló. Confirmamos que el archivo es alcanzable sin pasar por el bypass de SQL, porque la solicitud se realizó sin credenciales ni cookie.
- **Evidencia reproducible:**
  ```bash
  curl -sS -i --max-time 10 http://phantomcorp/backup/rrhh.conf
  curl -sS -i --max-time 10 http://phantomcorp/backup/p3-control-inexistente.conf
  ```
  La primera devolvió `200 OK` con `DB_USER`, `DB_PASS`, `API_TOKEN` (valor omitido en este informe) y `FLAG{final_token_looted}` (`evidencia/salidas/p3-r3-evidencia.txt`). La segunda devolvió `404 Not Found` (`evidencia/salidas/p3-control.txt`), lo que respalda que el archivo existe y no es una respuesta genérica.
- **Impacto:** divulgación de credenciales de base de datos y del token de API a cualquiera que conozca o adivine la ruta, sin autenticarse. Ese token es el que habilita la ejecución de comandos de H-01.
- **CVSS — justificación:** acceso remoto, sin privilegios ni interacción, con alto impacto en confidencialidad (secretos) y sin impacto demostrado en integridad ni disponibilidad.
- **Remediación:** retirar los archivos de configuración y backups del directorio servido por la aplicación; si deben existir, ubicarlos fuera del árbol web y con control de acceso autenticado. Rotar de inmediato las credenciales y el token expuestos. No almacenar secretos en archivos de texto accesibles por HTTP: usar variables de entorno o un gestor de secretos. El token, además, debe ser largo y aleatorio (no un valor corto y predecible), viajar en un header en vez de en la URL —donde queda registrado en logs— y tener expiración y rotación.
- **Limitación:** no exploramos otras rutas de backup ni comprobamos la validez de las credenciales de base de datos.

### H-03 — Inyección SQL que permite eludir la autenticación del portal

- **Severidad:** Alta · **CVSS v3.1:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (7.5)
- **Ubicación:** `POST /portal/login`, parámetro `user`.
- **Descripción:** el formulario de acceso construye la consulta de autenticación concatenando la entrada del usuario. Una condición booleana en `user`, con una contraseña sin valor, hace que el servidor conceda el acceso como `admin`. El servidor no emite cookie ni crea una sesión persistente: devuelve directamente el contenido del dashboard; aun así, el control de acceso queda eludido.
- **Evidencia reproducible:**
  ```bash
  curl -sS -i --max-time 10 -X POST http://phantomcorp/portal/login \
    --data-urlencode "user=p2-prueba-invalida" --data-urlencode "pass=credencial-invalida"
  curl -sS -i --max-time 10 -X POST http://phantomcorp/portal/login \
    --data-urlencode "user=' OR '1'='1' -- " --data-urlencode "pass=x"
  ```
  La primera devolvió `401 Unauthorized` y «Credenciales invalidas» (`evidencia/salidas/p2-r2-base.txt`). La segunda devolvió `200 OK`, «Bienvenido admin. Dashboard RRHH.» y `FLAG{final_sqli_foothold}` (`evidencia/salidas/p2-r2-acceso.txt`). El cambio de 401 a 200 con una contraseña inválida demuestra el bypass.
- **Impacto:** un usuario remoto sin credenciales válidas accede al dashboard de RRHH con el rol `admin`.
- **CVSS — justificación:** acceso remoto, sin privilegios ni interacción, con acceso no autorizado a un área administrativa (confidencialidad alta). No demostramos modificación de datos ni afectación de la disponibilidad en este punto.
- **Remediación:** reemplazar la construcción dinámica de la consulta por consultas parametrizadas / prepared statements. Aplicar privilegios mínimos a la cuenta de base de datos. Verificar el arreglo comprobando que la misma solicitud booleana recibe el mismo rechazo que las credenciales inválidas y no concede acceso.
- **Limitación:** no realizamos enumeración de tablas, extracción de datos ni modificaciones; el acceso mostrado no prueba por sí solo persistencia ni control del host.

### H-04 — Portal interno descubrible mediante `robots.txt` (informativa)

- **Severidad:** Informativa · sin CVSS asignado.
- **Ubicación:** `/robots.txt` y `/portal-rrhh`.
- **Descripción:** un recurso público anuncia la ruta de un portal interno no enlazado desde la portada. El acceso no autenticado permite ver su formulario de login.
- **Evidencia:** `evidencia/salidas/p1-robots.txt` y `evidencia/salidas/p1-r1-portal.txt`.
- **Impacto:** descubrimiento de la superficie de autenticación y de sus parámetros. Encontrar una página de login no es, por sí solo, una vulnerabilidad explotable, por lo que no le asignamos un score.
- **Remediación:** no tratar `robots.txt` ni una URL poco visible como control de acceso. Definir si el portal debe ser accesible desde esta red y aplicar autenticación y autorización efectivas según su finalidad.

## 5. Conclusión

El sistema «Clientes» quedó comprometido de principio a fin: desde internet y sin credenciales, un atacante puede ejecutar comandos como root y alcanzar los datos de 48.210 clientes. La cadena fue totalmente evitable y, sobre todo, redundante: no existe un único eslabón que la sostenga.

El punto importante para la remediación es que **arreglar solo la inyección SQL no corta el ataque**. El archivo `/backup/rrhh.conf` (H-02) se sirve sin autenticación y es alcanzable sin pasar por el portal; quien descubra esa ruta obtiene el token y llega igual a la ejecución de comandos (H-01) y a los datos. Los eslabones que efectivamente cortan la cadena son retirar ese archivo del servicio web y eliminar la ejecución de comandos de la API. La SQLi debe corregirse de todos modos, pero no es la contención principal.

La lección de postura general es que la seguridad no puede descansar en que una ruta permanezca oculta ni en que un token sea difícil de adivinar. Hace falta corregir las causas de raíz —consultas parametrizadas, secretos fuera del árbol web y rotados, servicio sin privilegios y sin ejecución de comandos arbitrarios— para que estas debilidades dejen de encadenarse.

Priorización de remediación:

1. **H-01 — API de reportes:** eliminar la ejecución de comandos y ejecutar el servicio sin privilegios de root.
2. **H-02 — Secretos expuestos:** retirar el archivo del directorio público, bloquear su acceso por HTTP y rotar credenciales y token.
3. **H-03 — Autenticación:** consultas parametrizadas y privilegios mínimos en la base de datos.

## 6. Anexo

### Estado del CTF

Los cuatro hitos fueron aceptados por el motor del laboratorio. El estado consolidado 4/4 se verificó de forma independiente el 30/10/2026 y se conserva en `evidencia/salidas/p5-status-final-4de4.txt`; la verificación del recorrido está en `evidencia/salidas/p5-verificacion-final.txt`.

```
   ✓  R1     Recon/enum: portal interno localizado
   ✓  R2     Explotacion: foothold por SQLi
   ✓  R3     Post: token de API looteado
   ✓  R4     Impacto: crown jewels (datos de clientes)
  4/4 (100%)
```

### Nota sobre la validación

El comando `./ctf submit` directo rechazó las flags por los finales de línea CRLF del manifiesto en este entorno Windows. Para validar usamos una copia temporal del manifiesto con finales de línea normalizados a LF, sin modificar el archivo original de `labs/`. La copia normalizada y el original son archivos distintos a nivel de bytes; la normalización solo afecta a la comprobación, no a las flags ni a las evidencias.

### Registro de evidencias

- **Bitácora de comandos:** `evidencia/comandos.txt`.
- **R1 — Reconocimiento:** `evidencia/salidas/p1-robots.txt`, `p1-r1-portal.txt`, `p1-inicio.txt`, `p1-control.txt`, `p1-submit.txt`.
- **R2 — Explotación:** `evidencia/salidas/p2-r2-base.txt`, `p2-r2-acceso.txt`, `p2-validacion-ctf.txt`.
- **R3 — Post-explotación:** `evidencia/salidas/p3-r3-evidencia.txt`, `p3-control.txt`, `p3-validacion-ctf.txt`.
- **R4 — Impacto:** `evidencia/salidas/p4-r4-identidad.txt`, `p4-r4-recurso.txt`, `p4-r4-conteo.txt`, `p4-r4-impacto.txt`, `p4-r4-submit.txt`.
- **Verificación final:** `evidencia/salidas/p5-status-final-4de4.txt`, `p5-verificacion-final.txt`.

El detalle paso a paso del procedimiento, con cada comando y la salida a la que corresponde, está en la bitácora `evidencia/comandos.txt` y en las respuestas crudas de `evidencia/salidas/`.
