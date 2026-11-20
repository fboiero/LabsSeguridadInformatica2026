# Informe — Laboratorio 07 · Explotación (entrega académica, cátedra Seguridad Informática UTN FRVM)

**Grupo:** 14 · **Integrantes:** ver `INTEGRANTES.md` · **Fecha:** 19/11/2026

> **Estado de la entrega:** este equipo no tiene Docker, por lo que el entorno `phantomcorp`
> (entorno de laboratorio provisto por la cátedra, de uso exclusivo académico) **no se pudo
> levantar**. No hay flags, salidas ni capturas reales de las explotaciones R1-R5.
> Todo lo que depende del entorno esta marcado **PENDIENTE (requiere Docker)**. Las secciones
> teoricas (mecanismo, impacto, defensa, P1-P5) estan completas. Los payloads de la tabla son
> **hipotesis teoricas derivadas del enunciado del lab, NO verificadas contra el target**, y
> sirven solo como material de estudio para este laboratorio didáctico.

## 0. Declaracion de uso de IA

- **Herramienta:** Claude (modelo Claude Sonnet 5.5, Anthropic) via Claude Code (CLI), con acceso al repositorio.
- **Uso:** estructura y redaccion del informe y del research a partir del `README.md` del lab y de conocimiento general; una demo local en `src/demo_sqli_local.py`.
- **Que NO hizo:** no se levanto el entorno, no se capturo ninguna flag, no se invento salida alguna. No se leyo `solucion.md` ni el codigo fuente del servidor (`entorno/`).
- **Verificacion:** la unica ejecucion real es la demo local (sqlite en memoria, datos propios, no es el lab); su salida se reproduce tal cual en la seccion 4.1. El grupo debe revisar todo y contrastarlo con el entorno real cuando se pueda correr.

## 1. Flags capturadas (salida de `./ctf status 07`)

**PENDIENTE (requiere Docker).** Comandos desde la raiz del repo, para que un integrante con Docker los corra:

```bash
make setup            # suma sqlmap a la consola
./ctf lab 07          # levanta phantomcorp y abre la guia
make shell            # consola del atacante; ahi se corren los curl de la seccion 4
# por cada reto resuelto:
./ctf submit 07 R1 'FLAG{...}'     # ... R2, R3, R4, R5
./ctf status 07                    # pegar aca la salida real
```

| Reto | Flag | Estado |
|---|---|---|
| R1 SQLi auth | - | PENDIENTE (requiere Docker) |
| R2 SQLi UNION | - | PENDIENTE (requiere Docker) |
| R3 Command injection | - | PENDIENTE (requiere Docker) |
| R4 Path traversal | - | PENDIENTE (requiere Docker) |
| R5 IDOR | - | PENDIENTE (requiere Docker) |

## 2. Tabla de explotacion

Columnas "Payload" y "resultante": **hipotesis teorica a validar en el entorno real** (el estado de cada reto es PENDIENTE). Las consultas/comandos/rutas son reconstrucciones plausibles a partir del README; el codigo real del servidor no fue consultado y puede diferir (por ejemplo, nombres de columnas).

| Vuln | Payload usado (hipotesis) | Consulta/comando/ruta resultante (reconstruida) | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) - CWE-89, OWASP A03 | usuario `admin' --`, clave cualquiera (el valor figura como pista en el README) | `SELECT user, rol FROM users WHERE user='admin' --' AND pass='...'` | Sesion como admin sin conocer su clave: bypass de autenticacion. | Consulta parametrizada (marcadores en vez de concatenar), hash de contrasenas con sal comparado en codigo, mensajes de error genericos, cuenta de BD con minimos privilegios. |
| SQLi UNION (R2) - CWE-89, A03 | agregar al buscador una clausula UNION de dos columnas apuntando a la tabla `secrets` (nombres de columnas a descubrir en vivo) | consulta original con un `UNION SELECT` anexado sobre `secrets`, forma ilustrativa a confirmar | Lectura de cualquier tabla accesible por la cuenta de BD (credenciales, secretos, PII). | Parametrizar tambien ese valor, cuenta de solo lectura acotada a las tablas necesarias, no exponer errores SQL crudos, WAF solo como capa adicional. |
| Command injection (R3) - CWE-78, A03 | encadenar al parametro `host` un comando adicional de lectura de archivo (separador de shell + comando) | comando de red original seguido del comando encadenado, forma ilustrativa asumiendo concatenacion a shell | Ejecucion de comandos con los privilegios del servicio (RCE): lectura de archivos, pivote, persistencia. | No invocar shell (pasar argumentos como lista, no como string armado), validar el host contra lista blanca de formato IP/hostname, usuario sin privilegios, contenedor sin red saliente. |
| Path traversal (R4) - CWE-22, A01 | nombre de archivo con secuencia de subida de directorio hacia la carpeta de flags (ruta mencionada en el README; cantidad de niveles a ajustar) | apertura de archivo que resuelve fuera del directorio publico previsto | Lectura de archivos arbitrarios legibles por el proceso (flags, configuracion, claves). | Resolver la ruta final y verificar que quede bajo el directorio base permitido, o aceptar solo nombres de una lista blanca / IDs; rechazar secuencias de subida de directorio. |
| IDOR (R5) - CWE-639 / CWE-285, OWASP A01 | pedir el perfil propio y luego otro id cercano (el propio es id=3 segun el README) | consulta de perfil por id sin comprobar que ese id pertenezca a la sesion activa | Acceso a datos de otros usuarios, incluido potencialmente el admin (confidencialidad). | Autorizacion en el servidor: derivar el objeto desde la sesion autenticada (no desde el parametro) y verificar pertenencia en cada request; denegar por defecto. Ids no secuenciales son defensa en profundidad, nunca el control en si. |

## 3. Preguntas de analisis

**P1 - por que funciona el bypass (con la query).**
El servidor arma el SQL pegando el input sin separar datos de codigo: `SELECT user, rol FROM users WHERE user='<user>' AND pass='<pass>'`. Si el valor de usuario cierra la comilla del literal y agrega un comentario de linea (`--`), todo lo que sigue en la consulta (la comparacion de la contrasena) deja de interpretarse como SQL. La condicion efectiva pasa a ser solo "el usuario es admin", que devuelve esa fila sin evaluar la contrasena nunca. El texto que el usuario escribio cambio la estructura de la consulta: el dato se volvio codigo. (El motor real que usa PhantomCorp y su sintaxis exacta de comentario quedan PENDIENTE de verificar.) La demo local `src/demo_sqli_local.py` reproduce este mecanismo sobre una base propia, comparando la version concatenada contra la parametrizada.

**P2 - por que el UNION necesita igual numero de columnas.**
`UNION` apila los resultados de dos `SELECT` en un unico conjunto de filas, y un conjunto de filas tiene un numero fijo de columnas: por eso ambos `SELECT` deben devolver la misma cantidad (y tipos compatibles entre si, segun el motor). Si no coinciden, el motor devuelve un error de desajuste de columnas. Para descubrir la cantidad sin saberla de antemano hay dos tecnicas equivalentes: (a) ordenar por un numero de columna creciente hasta que la consulta falle; el ultimo numero que no da error es la cantidad de columnas; (b) ir probando un UNION con uno, luego dos, luego tres valores nulos, hasta que deje de dar error, porque un valor nulo es compatible con cualquier tipo de columna. Como el servidor es verboso con los errores SQL segun el README, esos mensajes guian el ajuste. Una vez calzado el numero de columnas, se buscan nombres reales de tablas/columnas consultando el catalogo propio del motor.

**P3 - que es lo siguiente que haria un atacante real despues del RCE.**
Con ejecucion de comandos en el servidor, el siguiente paso tipico es: (1) reconocimiento local rapido del sistema (usuario, version del sistema, variables de entorno, red interna); (2) busqueda de credenciales o secretos accesibles desde ese host (claves de BD en archivos de configuracion, tokens); (3) conseguir una via de acceso mas comoda y estable que no dependa de reinyectar comandos uno por uno via HTTP; (4) establecer **persistencia** -el tema del Lab 08- para sobrevivir a un reinicio del contenedor o a que la vulnerabilidad se parchee; (5) desde ahi, escalada de privilegios dentro del host y movimiento hacia otros servicios de la red interna; (6) finalmente, el objetivo de negocio del ataque: exfiltracion de datos o uso del host comprometido para otros fines (el patron del Ejemplo B del README, sobre routers reclutados en botnets). La mitigacion de este riesgo no esta en impedir el primer comando sino en limitar lo que ese comando puede lograr: usuario sin privilegios, sistema de archivos de solo lectura, egreso de red restringido y monitoreo.

**P4 - por que parametrizar mata la SQLi de raiz.**
Con una consulta parametrizada, el motor de base de datos recibe **por separado** el texto SQL (con marcadores de posicion) y los valores a usar. El SQL se parsea y se planifica usando solo esos marcadores, antes de que el motor sepa cuales son los valores reales: la estructura de la consulta queda fija en ese momento. Los valores se envian despues y se ligan a los marcadores como datos puros, sin volver a pasar por el parser SQL. Por eso una entrada con comillas o comentarios deja de ser peligrosa: se vuelve simplemente el valor literal que se busca, que no matchea a nadie si no existe. No es un tema de "escapar" caracteres especiales -un enfoque fragil, que depende del motor, del encoding y de que no se olvide ningun caso- sino de haber eliminado por diseno la posibilidad de que un valor altere la gramatica de la consulta. Limite importante: los marcadores solo parametrizan *valores*; nombres de tabla o de columna, si vienen del usuario, siguen necesitando lista blanca porque no se pueden pasar como parametro. Esto se verifico localmente: la misma entrada produjo comportamiento distinto segun se usara concatenacion de texto o marcadores de posicion (seccion 4.1).

**P5 - por que el control de acceso del IDOR no puede depender del cliente, y donde va.**
El cliente (navegador, `curl`, un proxy) esta siempre bajo control de quien lo usa: puede cambiar cualquier parametro de la URL, cualquier campo de un formulario, cualquier cookie o header antes de enviar la peticion. Que el cliente "no cambie el id" no es un control de seguridad, es una esperanza; ocultar el link en la interfaz o validarlo solo del lado del navegador no impide mandar la peticion a mano. Por eso la verificacion tiene que vivir **en el servidor, en cada request, en el momento de acceder al objeto**: tomar la identidad del usuario desde la sesion autenticada (nunca desde un parametro que el cliente controla) y comprobar explicitamente que ese usuario tiene derecho sobre el recurso pedido (porque es el dueno, por su rol, o por una lista de acceso) antes de devolverlo. El criterio por defecto debe ser denegar, no permitir. Usar identificadores dificiles de adivinar reduce la enumeracion casual pero no reemplaza esa verificacion: sin ella, alguien que consiga un id ajeno por cualquier otra via igual accede.

## 4. Bitacora de comandos

### 4.1 Ejecutado realmente (demo local en Python/sqlite3, no es el entorno del lab)

```text
$ python -I src/demo_sqli_local.py
VULNERABLE: SELECT user, rol FROM users WHERE user='admin' --' AND pass='cualquiera' -> [('admin', 'admin')]
SEGURO    : SELECT user, rol FROM users WHERE user=? AND pass=? -> params ("admin' --", 'cualquiera') -> []
OK
```

### 4.2 PENDIENTE (requiere Docker) - pasos para un integrante del grupo dentro de `make shell`

Los endpoints y parametros surgen del `README.md` del lab. Hay que ajustar los valores exactos segun las respuestas reales del entorno, aprovechando que es verboso con los errores.

```bash
# R1 - endpoint de login, probar el payload de bypass descripto en la seccion de teoria del README
# R2 - endpoint de busqueda: primero contar columnas (ver P2), despues anexar la consulta a la tabla de secretos
#      y, una vez resuelto a mano, repetir con sqlmap como indica el README
# R3 - endpoint de la herramienta de red: encadenar un comando de lectura sobre la carpeta de flags
# R4 - endpoint de descarga: subir de directorio desde la carpeta publica hasta la carpeta de flags
# R5 - endpoint de perfil: comparar la respuesta con el id propio contra la respuesta con otro id

# entrega de cada flag obtenida
./ctf submit 07 R1 'FLAG{...}'   # repetir para R2, R3, R4, R5
./ctf status 07
```

Nota para quien ejecute esto: si algun endpoint requiere sesion o cookie (por ejemplo el de perfil o el de herramientas tras loguearse), pasarla con las opciones de cookie de curl usando la que se obtenga al resolver R1; confirmar el comportamiento exacto en el entorno real antes de entregar.
