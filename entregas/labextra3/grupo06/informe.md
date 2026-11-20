# Informe — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 06
**Fecha:** 30/10/2026

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

**Herramienta:** Codex (OpenAI).

- **Finalidad:** apoyo para revisar la consigna, implementar las defensas D1 y D2 y preparar una prueba HTTP local.
- **Partes asistidas:** cambio del banner, retirada de `/api/status`, script `evidencia/probar-d1-d2.py`, salidas y análisis sobre seguridad por oscuridad.
- **Verificación:** el script crea una base y un directorio de descargas temporales, inicia la copia del grupo únicamente en `127.0.0.1` y confirmó `GET /` con 200, un header `Server` sin producto ni versión y `/api/status` con 404. El verificador oficial se ejecutó, pero su corrida local tuvo fallos de conexión; por eso esa salida no se usa como prueba de D2.

**Herramienta:** ChatGPT (OpenAI).

- **Finalidad:** asistencia para comprender y corregir la exposición de `/backup`, preparar pruebas locales y redactar el análisis correspondiente.
- **Partes asistidas:** parche D3, script `evidencia/probar-d3.py` y análisis sobre `robots.txt` y autorización.
- **Verificación:** se ejecutaron pruebas HTTP sobre la copia del grupo utilizando una base de datos temporal. Se confirmó que `/backup` devuelve 404, que `robots.txt` no lo anuncia y que la página principal y la descarga legítima del manual siguen respondiendo 200. La verificación final integrada también confirma D3 dentro del 5/5.

**Herramienta:** OpenCode.

- **Finalidad del uso:** apoyo para revisar la consigna, analizar las evidencias disponibles y redactar el análisis de ataque/parche, el ranking de impacto, la conclusión y esta declaración.
- **Verificación:** se contrastó el contenido con el código, el diff y las salidas de pruebas guardadas. No se ejecutó el contenedor.

**Herramienta:** Claude (Anthropic), vía Claude Code.

**Finalidad y partes asistidas:** implementación del parche D5 en objetivo/server.py, redacción de la sección D5 en informe.md y de research.md.
**Verificación:** el parche se probó directamente con curl contra una instancia real del servidor parcheado y con tres corridas del verificador oficial, descartando antes una corrida con errores de conexión que daba un falso positivo. La flag D5 se obtuvo del verificador oficial, sin inventar resultados. Las afirmaciones del research se contrastaron contra las páginas oficiales de OWASP citadas antes de incluirlas.

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba                                                                        | Fix aplicado                                                                                                                                                                                               | Verificación                                                                                                                            |
| ------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| D1      | El header `Server` identificaba `PhantomServer/2.4.1-debug`                                  | Se reemplazó por el valor genérico `Servidor`; `evidencia/salidas/d1-d2-parche.diff`                                                                                                                       | `GET /` devuelve 200 y `Server: 'Servidor '`, sin producto ni versión; `d1-d2-despues.txt` y `verificador-final-5de5.txt`               |
| D2      | `/api/status` devolvía `debug:true`, ruta de la base y PID                                   | Se retiró el endpoint de diagnóstico público: responde 404 sin datos internos; `evidencia/salidas/d1-d2-parche.diff`                                                                                       | La prueba HTTP aislada recibe 404 y el cuerpo no contiene `debug` ni `pid`; `d1-d2-despues.txt` y `verificador-final-5de5.txt`          |
| D3      | `/backup` respondía 200 sin autorización y `robots.txt` lo anunciaba                         | Se eliminó la referencia en `robots.txt` y el endpoint público devuelve 404; `evidencia/salidas/d3-parche.diff`                                                                                            | `/backup` devuelve 404, `robots.txt` no contiene `/backup`; `d3-despues.txt` y `verificador-final-5de5.txt`                             |
| D4      | `admin'--` en usuario y `' OR 1=1 --` en contraseña permiten entrar sin credenciales válidas | Consulta fija con `?` y tupla `(user, pwd)`; `evidencia/salidas/d4-parche.diff`                                                                                                                            | Los bypasses devuelven 401 en pruebas propias y quedan bloqueados en `verificador-final-5de5.txt`                                       |
| D5      | Lectura fuera del directorio mediante `../centinela-p3.txt` y `../../../../etc/passwd`       | Confinamiento por ruta resuelta (`os.path.realpath` y comprobación contra el directorio de descargas); las rutas absolutas se rechazan además como política de entrada; `evidencia/salidas/d5-parche.diff` | Centinela y ruta absoluta bloqueados, `manual.txt` conserva 200 y el verificador final marca D5 bloqueada; `verificador-final-5de5.txt` |

## 2. Regresión funcional

Las pruebas reproducibles están en `evidencia/probar-d4.py`. Importan el módulo elegido sin modificarlo, emplean una base y directorio temporales y un servidor en `127.0.0.1` con puerto asignado por el sistema. El usuario adicional con apóstrofes existe solo en la base temporal de pruebas.

| Prueba sobre la copia                                                           | Resultado                 |
| ------------------------------------------------------------------------------- | ------------------------- |
| `GET /`                                                                         | 200, portal de empleados  |
| `admin` / `sup3r-s3cr3t0`                                                       | 200, bienvenida           |
| Contraseña incorrecta o usuario inexistente                                     | 401                       |
| `admin'--` como usuario                                                         | Antes 200; después 401    |
| `' OR 1=1 --` como contraseña                                                   | Antes 200; después 401    |
| `' OR '1'='1' --` como usuario                                                  | Antes 200; después 401    |
| Usuario `o'connor` y contraseña `clave'valida`, insertados como datos de prueba | 200 tras el parche        |
| Apóstrofe aislado o campos vacíos                                               | 401, sin error SQL        |
| `/descargar?archivo=manual.txt`                                                 | 200, contenido del manual |

Las URLs exactas y cuerpos se conservan en las salidas crudas. El primer intento de pruebas pasó los casos HTTP pero falló al borrar su base temporal: el propio script no había cerrado la conexión usada para crear el usuario de prueba. Se conserva `d4-antes-intento1.txt`; se corrigió el script con `db.close()` y se repitió correctamente antes de aplicar D4. No era un fallo del parche.

## 3. Evidencia de progreso

El verificador inicial se conserva sin editar en `verificador-inicial.txt`; en Windows reportó 1/5 porque su payload de D5 depende de `/etc/passwd`, inexistente en ese sistema. Por eso se añadió una prueba con un archivo centinela fuera del directorio permitido. La salida final cruda `verificador-final-5de5.txt` ejecuta las cinco comprobaciones contra la copia parcheada y confirma **5/5** sin errores de conexión.

Las cinco flags emitidas por esa verificación se registraron mediante `evidencia/registrar-flags-final.sh`, que crea una copia temporal del manifiesto con CRLF normalizado y no modifica archivos del laboratorio. La salida cruda `ctf-registro-final.txt` muestra la aceptación de D1–D5 y `status-extra3-final-5de5.txt` confirma el estado **5/5 (100%)**.

```text
╭────────────────────────────────────────────────────────────╮
│                   PROGRESO · LAB extra3                    │
╰────────────────────────────────────────────────────────────╯

 ✓  D1     Banner neutralizado (info leak de version)
 ✓  D2     Endpoint de debug apagado en produccion
 ✓  D3     Rutas sensibles blindadas (backup + robots)
 ✓  D4     Login parametrizado (SQLi bloqueado)
 ✓  D5     Path traversal bloqueado en /descargar

██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab extra3 COMPLETO! Ponete las pilas con la próxima unidad.
```

Para que la aplicación se ejecute tanto en Windows como en Linux, la copia usa `tempfile.gettempdir()` para su base SQLite y directorio de descargas. Esa función selecciona el directorio temporal de acuerdo con el entorno; la adaptación usa solo la biblioteca estándar y no modifica el objetivo de referencia ni el verificador.

## 4. Preguntas P1–P5

### P1 — Ataque, parche y comprobación de D4

Se eligió D4 para la demostración. Antes del cambio, las pruebas contra el código de referencia muestran que `GET /login?user=admin%27--&pass=x` respondía HTTP 200, y que tanto `' OR 1=1 --` como usuario o contraseña también permitían el acceso (HTTP 200). La salida completa está en `evidencia/salidas/d4-antes.txt`.

El diff `evidencia/salidas/d4-parche.diff` reemplaza la construcción de SQL por concatenación por una consulta fija con marcadores `?` y pasa `(user, pwd)` como parámetros. No se filtran caracteres ni se reconocen cadenas específicas. Después del cambio, esas mismas tres variantes responden HTTP 401, mientras las credenciales legítimas de `admin` responden HTTP 200; los resultados están en `evidencia/salidas/d4-despues.txt`. La verificación final integrada en `verificador-final-5de5.txt` confirma que D4 bloquea ambos bypasses junto con las otras cuatro defensas.

La evidencia es reproducible con `evidencia/probar-d4.py` contra el archivo de referencia en modo `antes` y contra `objetivo/server.py` en modo `despues`; la secuencia y el entorno originales constan en `evidencia/comandos.txt`.

### P2 — ¿Por qué eliminar `/backup` de `robots.txt` no equivale a protegerlo?

El archivo `robots.txt` sirve para indicarles a los rastreadores web qué rutas deberían evitar, pero no es un mecanismo de autenticación ni de autorización. Su contenido es público y sus indicaciones no impiden que un usuario solicite directamente una dirección.

En la versión vulnerable de PhantomCorp, `robots.txt` anunciaba la ruta `/backup`, que además respondía con HTTP 200 y devolvía información interna sin solicitar credenciales.

Eliminar únicamente esa referencia habría reducido la visibilidad del recurso, pero no solucionaría la vulnerabilidad, porque cualquier persona que conociera la ruta podría seguir accediendo a ella.

Por eso, en la defensa D3 realizamos dos modificaciones: eliminamos la referencia de `/backup` en `robots.txt` y deshabilitamos el endpoint público, que ahora devuelve HTTP 404 sin exponer el contenido del backup.

La prueba posterior confirmó que `/robots.txt` ya no publica la ubicación sensible y que `/backup` no entrega información. También verificamos que la página principal y la descarga legítima del manual continúan funcionando.

La conclusión es que ocultar una ruta no equivale a protegerla. La seguridad debe aplicarse sobre el recurso mediante autorización efectiva o eliminando su exposición pública cuando no es necesario que esté disponible. Como capa adicional, los backups deberían almacenarse fuera de la raíz servida por HTTP y, cuando sea posible, la cuenta del servidor web no debería poder leerlos.

### P3 — Banner y seguridad por oscuridad

Neutralizar el header `Server` es una defensa limitada pero útil: reduce la información disponible para _fingerprinting_. Antes, una solicitud ordinaria revelaba el producto `PhantomServer`, la versión `2.4.1` y que se trataba de una compilación de depuración. Después del parche, la prueba local recibe el valor genérico `Servidor`, sin esos metadatos.

No es una corrección suficiente de las vulnerabilidades de la aplicación. Un atacante puede descubrir la tecnología por otros headers, por el comportamiento de la aplicación, errores, código expuesto o pruebas activas; y ocultar una versión no impide SQLi, accesos no autorizados ni traversal. Presentarlo como solución completa sería seguridad por oscuridad: depender de que el atacante no conozca un dato en vez de imponer un control técnico.

En este caso se aplica como reducción de exposición complementaria, no como frontera de seguridad. Debe acompañarse de actualizaciones, controles de acceso, validación de entradas y el retiro de diagnósticos públicos. La evidencia `evidencia/salidas/d1-d2-despues.txt` demuestra solo que el banner dejó de identificar producto y versión.

### P4 — Por qué `user.replace("'", "")` no sustituye parametrizar

La propuesta altera el usuario pero conserva la construcción de SQL con entradas concatenadas. En este código también se incorpora `pass`: aunque se eliminen apóstrofes del usuario, la contraseña `' OR 1=1 --` conserva la capacidad de cambiar la condición de autenticación. La evidencia anterior al parche confirma que ese campo era un punto de inyección.

Además, borrar caracteres modifica datos válidos: `o'connor` se convertiría en `oconnor`. Aplicar el mismo filtro a la contraseña también cambiaría su significado. No hace falta afirmar que cualquier filtro de apóstrofes es eludible en todos los motores: en una combinación muy restringida puede bloquear ciertos ataques, pero no establece la separación estructural entre código SQL y datos, depende de todos los puntos de entrada y puede romper credenciales legítimas.

Con `execute(sql, (user, pwd))`, el SQL fijo contiene dos marcadores `?`, sin comillas alrededor. SQLite enlaza los valores sin reinterpretarlos como operadores, comentarios o parte de la sentencia. Por ello las entradas de ataque se buscan como cadenas literales y no encuentran credenciales coincidentes: devuelven 401. El caso válido con apóstrofes devuelve 200, mostrando que no se han eliminado caracteres para conseguir el bloqueo.

El alcance del cambio es la inyección de valores en esta consulta. No equivale a resolver autorización, almacenamiento seguro de contraseñas, transporte, protección contra intentos masivos u otros problemas del servidor. Los identificadores SQL dinámicos, si existieran, requerirían un diseño distinto; no se sustituyen con parámetros de valores.

### P5 — Ranking de impacto de D1–D5

Este orden prioriza impacto potencial sobre confidencialidad e integridad, facilidad de explotación y exposición demostrada en el entorno; no sustituye una evaluación de riesgo del despliegue real:

1. **D4 — Inyección SQL en el login.** En la prueba previa al parche, entradas en usuario o contraseña eludían la autenticación y devolvían HTTP 200. El acceso no autorizado puede exponer las funciones o datos disponibles tras el login. La evidencia confirma el bypass de autenticación; no demuestra por sí sola qué operaciones adicionales tendría una aplicación de producción.
2. **D5 — Path traversal en descargas.** La prueba controlada leyó con HTTP 200 un archivo centinela ubicado fuera del directorio de descargas. Esto demuestra lectura arbitraria fuera de la raíz prevista en ese entorno. El alcance depende de los permisos del proceso y de los archivos accesibles.
3. **D3 — Backup sin autorización.** El endpoint entregaba directamente un volcado descrito como datos de usuarios y se anunciaba en `robots.txt`. La exposición puede divulgar información sensible; quitar la pista no protege el recurso. El parche quita el anuncio y bloquea el acceso directo con 404.
4. **D2 — Filtración de estado y datos internos.** `/api/status` revela modo debug, rutas internas y PID, información que facilita reconocimiento y puede ayudar a encadenar otros fallos, pero la evidencia disponible no demuestra que por sí sola permita autenticación o lectura de datos.
5. **D1 — Banner con producto y versión.** Facilita identificar la tecnología y orientar el fingerprinting, pero no constituye por sí solo una vía de acceso. Ocultarlo reduce exposición de metadatos y no corrige vulnerabilidades explotables.

Para gerencia, el hallazgo prioritario es **D4**: el bypass de autenticación se demostró con entradas HTTP y habilita acceso sin credenciales válidas, por lo que compromete directamente el control de acceso. D5 también tiene impacto importante sobre confidencialidad, pero su alcance observado se limita a la lectura del centinela en el entorno de prueba. El ranking se basa en las pruebas y verificación final disponibles, no en una evaluación de una infraestructura de producción completa.

## 5. Conclusión

La corrección fue más exigente que explotar PhantomCorp: además de cerrar cada vector, hubo que preservar los flujos legítimos y comprobar el mecanismo de cada parche. El verificador final acredita 5/5 contra la copia del grupo, y las pruebas de regresión confirman portal, login y descarga. Esto no prueba que no existan fallos futuros o vectores no ensayados, pero sí que las cinco debilidades planteadas quedaron corregidas estructuralmente y verificadas con evidencia reproducible. La revisión cruzada de D1, registrada en `evidencia/salidas/p2-revision-d1.txt`, confirmó además el banner genérico y el 404 de `/api/status`.
