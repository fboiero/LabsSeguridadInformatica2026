# Informe — Laboratorio 07 · Explotación

**Grupo:** 06
**Fecha:** 23/10/2026 (última actualización: 28/10/2026)

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

**Claude Code y Codex (OpenAI).** Los usamos para armar la estructura inicial del informe y redactar las filas de R1 y R2, las respuestas P1 y P2 y sus comandos. Los payloads se enviaron con `curl --data-urlencode` desde la consola atacante contra `phantomcorp`, y las respuestas se guardaron sin editar en `evidencia/salidas/`. Codex también asistió en el mini-research.

**ChatGPT (OpenAI).** Lo usamos durante R5 para interpretar las respuestas HTTP y redactar la fila de R5, la respuesta P5 y los comandos. Comparamos el perfil propio con el del administrador y guardamos ambas respuestas originales.

**OpenCode.** Lo usamos durante R3 para probar separadores de comandos, guardar la evidencia y redactar la fila de R3 y la respuesta P3.

**Claude Code, revisión final.** Lo usamos para revisar la redacción del informe y del research, contrastar cada afirmación con las salidas guardadas, verificar las fuentes y volver a ejecutar el ejemplo de SQLite del research.

En ningún caso se leyó el código del servidor ni `solucion.md`: las consultas y comandos reconstruidos son inferencias a partir de las respuestas, salvo donde el propio servidor mostró el comando ejecutado (R3). Revisamos todo el contenido antes de incorporarlo.

## 1. Flags capturadas

```
   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ✓  R3     Inyeccion de comandos (RCE)
   ✓  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  ██████████████████████████████  5/5 (100%)
```

Salida completa de `./ctf status 07` en [status-07.txt](evidencia/salidas/status-07.txt). Ese estado se obtuvo el 28/10, después de volver a presentar R1, R2, R4 y R5 en la instalación donde se resolvió R3: el progreso de los validadores es local a cada máquina, y R5 se había validado antes en una copia temporal del validador ([r5-status-07.txt](evidencia/salidas/r5-status-07.txt), 1/5). Las respuestas «Correcta (ya la tenías)» de [r2-submit.txt](evidencia/salidas/r2-submit.txt) y [r3-submit.txt](evidencia/salidas/r3-submit.txt) corresponden a reenvíos de flags ya registradas.

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
| --- | --- | --- | --- | --- |
| SQLi auth (R1) | `POST /login` con `user=admin' --` y `pass=cualquiercosa` | Reconstruida: `SELECT ... WHERE user='admin' --' AND pass='cualquiercosa'`. Todo lo que sigue a `--` es comentario, así que la condición sobre `pass` no se evalúa. | La línea base (`user=test`, `pass=test`) devolvió `401 Credenciales invalidas`; el payload devolvió `200` con «Bienvenido admin (rol: admin)» y `FLAG{sqli_auth_bypass}`. El servidor nos trató como admin sin conocer su contraseña; no verificamos si además emitía una sesión reutilizable. Evidencia: [base](evidencia/salidas/r1-login-base.txt), [bypass](evidencia/salidas/r1-sqli-auth.txt), [envío](evidencia/salidas/r1-submit.txt). | Consulta parametrizada: `WHERE user = ? AND pass = ?` con los valores enlazados aparte, de modo que la comilla y el `--` llegan como parte del nombre. Además, comparar la contraseña contra un hash y no en la consulta. |
| SQLi UNION (R2) | `GET /buscar` con `q=Router' UNION SELECT * FROM secrets -- ` | Reconstruida: `SELECT <col1>, <col2> FROM <productos> WHERE <filtro con 'Router'> UNION SELECT * FROM secrets -- '...`. La comilla cierra el texto de búsqueda, el `UNION` agrega las filas de `secrets` y el `--` anula el resto. | La línea base mostró `Router industrial - $1200`; con el payload apareció `flag_union - $FLAG{sqli_union_dump}`. La fila de `secrets` salió con el mismo formato «nombre - $precio», lo que indica que `secrets` tiene dos columnas y que leímos la tabla sin autenticarnos. Evidencia: [base](evidencia/salidas/r2-buscar-base.txt), [UNION](evidencia/salidas/r2-sqli-union.txt), [envío](evidencia/salidas/r2-submit.txt). | Consulta parametrizada para el término de búsqueda (`WHERE nombre LIKE ?` con `'%' + q + '%'` como valor). La cuenta de la aplicación no debería poder leer `secrets` si el buscador solo necesita productos. |
| Command injection (R3) | `GET /herramientas/ping` con `host=127.0.0.1; cat /app/flags/cmdi.txt` | Observada en la respuesta, que repite el comando ejecutado: `$ ping -c1 127.0.0.1; cat /app/flags/cmdi.txt`. El `;` termina el `ping` y ejecuta `cat` en el mismo shell (`/bin/sh`). | Ejecución de comandos arbitrarios en el servidor con los privilegios del proceso web; la respuesta devolvió `FLAG{command_injection_rce}`. Antes listamos `/app` y `/app/flags` con `ls`. No verificamos con qué usuario corre el proceso. Evidencia: [base](evidencia/salidas/r3-ping-base.txt), [ls /app](evidencia/salidas/r3-ls-app.txt), [ls /app/flags](evidencia/salidas/r3-ls-flags.txt), [inyección](evidencia/salidas/r3-command-injection.txt). | No pasar por un shell: ejecutar `ping` con la lista de argumentos (`subprocess.run(["ping", "-c1", host])`, sin `shell=True`) y validar antes que `host` sea una IP o un nombre de host válido. |
| Path traversal (R4) | `GET /descargar` con `archivo=../flags/lfi.txt` | Reconstruida: `public/` + `../flags/lfi.txt` → `/app/flags/lfi.txt`. El listado de `/app` obtenido en R3 muestra `public/` y `flags/` en el mismo nivel, lo que es consistente con esa ruta. | La línea base (`catalogo.txt`) devolvió «Catalogo publico PhantomCorp.»; el payload devolvió `FLAG{path_traversal_lfi}`. Leímos un archivo fuera del directorio público. Evidencia: [base](evidencia/salidas/r4-traversal-base.txt), [traversal](evidencia/salidas/r4-traversal.txt). | Resolver la ruta final (`os.path.realpath`) y rechazar la solicitud si no queda dentro de `/app/public`; mejor aún, servir archivos por un identificador asociado a una lista cerrada de nombres. |
| IDOR (R5) | `GET /perfil?id=1` (línea base: `id=3`) | Ruta pedida: `/perfil?id=1`. El servidor devuelve el perfil con ese `id` sin relacionarlo con quien lo pide; las solicitudes no llevaban sesión ni credenciales. | Con `id=3` obtuvimos el perfil de `jperez`; con `id=1`, el de `admin` con `rol: admin` y su `nota_privada`, que contenía `FLAG{idor_broken_access}`. Cualquiera que pueda llegar al endpoint lee perfiles ajenos cambiando el número. Evidencia: [id=3](evidencia/salidas/r5-idor-base.txt), [id=1](evidencia/salidas/r5-idor-admin.txt). | Exigir sesión en `/perfil` y, en el servidor, devolver el perfil solo si su `id` coincide con el del usuario autenticado o si este tiene un rol que lo autorice; en cualquier otro caso, `403`. |

En todos los casos nos limitamos a la lectura que pedía cada reto. No modificamos datos, no enumeramos otras tablas, archivos o perfiles, y no buscamos persistencia ni escalada desde la ejecución de comandos de R3.

Sobre R3: además del `;`, probamos otros separadores (`|`, `&&`) y la sustitución `$(...)`; según la [bitácora](evidencia/comandos.txt), los separadores ejecutaron el segundo comando y `$(...)` no mostró salida visible. Esas salidas no quedaron guardadas en `evidencia/salidas/`. La línea base muestra `/bin/sh: 1: ping: not found`: el contenedor no tiene `ping`, pero eso no impide la inyección, porque el shell ejecuta igual el comando que sigue al `;`.

## 3. Preguntas de análisis

### P1 — Por qué funciona el bypass (con la consulta)

Por el comportamiento observado, el login arma una consulta del tipo `SELECT ... FROM usuarios WHERE user='<user>' AND pass='<pass>'`, pegando los valores del formulario dentro del texto SQL. No vimos el código del servidor, así que los nombres de tabla y columnas son supuestos; la estructura es la que explica las dos respuestas.

Con `user=admin' --`, la consulta queda:

```sql
SELECT ... FROM usuarios WHERE user='admin' --' AND pass='cualquiercosa'
```

La comilla del payload cierra el texto de `user`. El `--` abre un comentario de línea, y el motor descarta todo lo que viene después: la comilla que quedaba suelta y la condición `AND pass=...`. Lo que se ejecuta en la práctica es `WHERE user='admin'`, que encuentra al usuario sin mirar la contraseña. El payload no adivina la clave: la saca de la consulta. Funciona porque el servidor mezcla en el mismo texto el código SQL y los datos que escribe el usuario.

### P2 — Por qué el `UNION` necesita el mismo número de columnas

`UNION` junta los resultados de dos `SELECT` en una sola tabla, fila debajo de fila. Para eso cada fila tiene que tener la misma cantidad de columnas; si no, el motor no sabe cómo ubicar los valores del segundo `SELECT` y devuelve un error. En R2 el buscador muestra dos campos (nombre y precio), y `SELECT * FROM secrets` funcionó porque `secrets` también tiene dos columnas. Por eso la fila inyectada apareció con el formato «nombre - $precio»: `flag_union` ocupó el lugar del nombre y la flag el del precio.

Si no supiéramos cuántas columnas hay, se puede averiguar de dos formas. Una es agregar `ORDER BY 1 --`, `ORDER BY 2 --`, etc., hasta que el número supere la cantidad de columnas y la respuesta cambie. La otra es probar `UNION SELECT NULL --`, `UNION SELECT NULL,NULL --` y seguir sumando hasta que la consulta deje de fallar; `NULL` sirve porque es compatible con cualquier tipo. En este laboratorio no hizo falta, porque la consigna indicaba las dos columnas.

### P3 — Qué sigue después del RCE

Con ejecución de comandos, un atacante pasaría de explotar la falla a asegurar y ampliar el acceso:

1. **Reconocer el host:** con qué usuario corre el proceso (`id`), qué hay en el sistema y en las variables de entorno, y a qué redes llega. En R3 vimos que `/app` contiene `server.py`, el código de la aplicación, que un atacante leería para buscar credenciales u otras fallas.
2. **Conseguir una shell estable:** en vez de un comando por solicitud HTTP, una shell interactiva.
3. **Persistir:** dejar una forma de volver aunque se corrija la falla, como una tarea programada, una clave SSH agregada o un archivo malicioso dentro de la aplicación.
4. **Escalar privilegios y moverse:** si el proceso no es root, buscar cómo llegar a root, y usar el host como trampolín hacia otras redes.

Esto es lo que se practica en el Lab 08. Acá nos quedamos en la lectura de `cmdi.txt`; tampoco sabemos si el proceso corre como root, porque no ejecutamos `id` y los archivos leídos eran legibles por cualquier usuario.

### P4 — Por qué parametrizar mata la SQLi de raíz

Con una consulta parametrizada, el texto SQL se envía al motor con marcadores (`?`) en lugar de los valores, y el motor lo analiza y fija su estructura antes de recibir los datos. Los valores llegan después, por separado, y se usan solo como valores. No importa qué contengan: una comilla, un `--` o un `UNION` dentro del valor son caracteres de ese texto, no sintaxis SQL, porque la estructura ya quedó definida.

Eso es lo que significa «de raíz»: filtrar comillas o palabras clave intenta reconocer los datos peligrosos, y siempre puede faltar algún caso; parametrizar elimina el mecanismo, porque los datos nunca se interpretan como código. Aplicado a R1, `admin' --` se buscaría como un nombre de usuario literal y no encontraría ninguno; en R2, el texto del `UNION` sería simplemente un término de búsqueda sin resultados. En el research mostramos esto con un ejemplo en SQLite. La parametrización tiene un límite: sirve para valores, no para nombres de tablas o columnas, que si tienen que ser dinámicos se eligen de una lista cerrada.

### P5 — Dónde va el control de acceso (IDOR)

En el servidor, en cada solicitud y para cada objeto. El cliente controla todo lo que manda: en R5 bastó con cambiar el `id` en la URL con `curl`, sin pasar por ninguna interfaz. Ocultar el número, usar un botón deshabilitado o validar en JavaScript no cambia nada, porque la solicitud se puede armar a mano.

Hay que distinguir dos controles. La autenticación responde quién hace la solicitud; en R5 ni siquiera existía, porque las solicitudes no llevaban sesión. La autorización responde si esa persona puede ver ese perfil en particular. El servidor tiene que obtener el usuario de la sesión, no de un parámetro, y comparar: si el perfil pedido no es el suyo y no tiene un rol que lo habilite, responde `403`. La regla por defecto tiene que ser denegar, de modo que un endpoint nuevo o un caso no previsto quede cerrado y no abierto.

## 4. Bitácora de comandos

Todos los comandos se ejecutaron desde la consola atacante (`cyberlab-attacker`) contra `phantomcorp`. Por problemas con WSL, en varias sesiones se invocaron desde Windows con `docker exec`, y las flags se presentaron desde Git Bash en la raíz del repositorio. La lista completa, con las líneas base y el destino de cada salida, está en [evidencia/comandos.txt](evidencia/comandos.txt).

```bash
# R1 — POST /login con user=admin' -- y pass=cualquiercosa, enviados con --data-urlencode
# R2
curl -sS -i -G http://phantomcorp/buscar --data-urlencode "q=Router' UNION SELECT * FROM secrets -- "
# R3
curl -sS -i -G http://phantomcorp/herramientas/ping --data-urlencode 'host=127.0.0.1; cat /app/flags/cmdi.txt'
# R4
curl -sS -i -G http://phantomcorp/descargar --data-urlencode "archivo=../flags/lfi.txt"
# R5
curl -sS -i "http://phantomcorp/perfil?id=1"
```
