# Entregable — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 14 · **Integrantes:** Peron, Fede (@fedeeperon) · Gomez Redondo, Laureano (@Laureano-GR) · Cesano, Martín (@martincesano) · Gaido, Martín (@martingaidoo) · Chiapero, Valentina (@valechiapero)

**Declaración de uso de IA:** Usamos IA para redactar el informe y las respuestas
P1–P5. El parcheo del `server.py` (D1–D5), la verificación con
`verificar-defensa.py` (0/5 → 5/5) y la regresión funcional los hicimos nosotros.

---

## 1. Tabla de defensas (antes → después)

Diff completo en `evidencia/salidas/diff-parche.txt`. Verificador final en
`evidencia/salidas/verificador-final-5de5.txt`.

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación (bloqueado) |
|---|---|---|---|
| D1 Banner | `Server: PhantomServer/2.4.1-debug` filtra producto+versión | `server_version="web"`, `sys_version=""` | `Server: 'web'` (sin producto ni versión) |
| D2 Debug | `GET /api/status` → 200 con `debug:true`, `pid`, ruta de DB | el endpoint responde 404 (apagado en prod) | `/api/status → 404` |
| D3 Rutas | `/backup` → 200 sin auth y `robots.txt` lo listaba | `/backup → 404` y `robots.txt` con `Disallow:` vacío | `/backup → 404`; robots no menciona /backup |
| D4 SQLi | `user=admin'--` y `' OR 1=1 --` logueaban | consulta **parametrizada** (`WHERE user=? AND password=?`) | ambos bypass bloqueados |
| D5 Traversal | `archivo=../../../../etc/passwd` devolvía `/etc/passwd` | `os.path.basename()` + chequeo de `commonpath` dentro de DESCARGAS | `/etc/passwd` no se filtra (404/403) |

## 2. Regresión funcional

Ver `evidencia/salidas/regresion-funcional.txt`:
- `GET /` → 200.
- Login legítimo `admin` / `sup3r-s3cr3t0` → `<h1>Bienvenido, admin</h1>`.
- `GET /descargar?archivo=manual.txt` → descarga el manual.
- `GET /descargar?archivo=../../../../etc/passwd` → bloqueado (no filtra `root:`).

La app sigue funcionando: los parches cortan el ataque sin romper el uso legítimo.

## 3. Evidencia de progreso

- `evidencia/salidas/verificador-inicial-0de5.txt` → 0/5 (objetivo original).
- `evidencia/salidas/verificador-final-5de5.txt` → 5/5 (copia parchada).
- `evidencia/salidas/ctf-status.txt` → D1–D5 en ✓ (5/5).

## 4. Preguntas P1–P5

- **P1 (D4, antes/después).**
  - *Antes:* `GET /login?user=admin'--&pass=x` → `<h1>Bienvenido, admin</h1>`
    (la query interpolaba el string: `... WHERE user = 'admin'--' AND ...`, el
    `--` comenta el resto).
  - *Parche (diff):* se reemplazó la concatenación por
    `db.execute("SELECT user FROM usuarios WHERE user = ? AND password = ?", (user, pwd))`.
  - *Después:* mismo ataque → `401 Credenciales inválidas`. El input ya no es
    código, es dato. (Ver `diff-parche.txt`.)
- **P2 (D3).** Sacar la ruta del `robots.txt` solo la **oculta**: sigue
  respondiendo 200 a quien la adivine o la encuentre por fuerza bruta de rutas.
  **Proteger** la ruta (404/401/403, auth) es la defensa **real**: aunque el
  atacante conozca `/backup`, no obtiene nada. robots.txt es una directiva para
  crawlers, no un control de acceso — de hecho **publicita** rutas sensibles.
- **P3 (D1).** Ocultar el banner es **seguridad por oscuridad**: sube el costo de
  reconocimiento (el atacante no sabe de una qué versión explotar), pero **no
  arregla** ninguna vulnerabilidad. Ayuda como capa extra (menos info gratis al
  atacante); engaña si se la toma como defensa suficiente. La versión vieja sigue
  siendo vulnerable aunque no la anuncies: lo real es parchear/actualizar.
- **P4 (D4).** `user.replace("'", "")` no alcanza: (a) hay otros vectores
  (comillas dobles, `;`, comentarios, codificaciones, payloads sin comilla en
  campos numéricos); (b) es una lista negra, siempre incompleta; (c) rompe datos
  legítimos con apóstrofo (`O'Brien`). La **consulta parametrizada** es
  estructural porque separa el *código SQL* de los *datos*: el driver envía la
  query y los valores por canales distintos, así el input nunca se interpreta
  como SQL. No hay nada que "limpiar".
- **P5 (ranking por impacto).**
  1. **D4 SQLi** — el más grave: bypass de autenticación + lectura/escritura de
     la base → compromiso total de datos y cuentas. A gerencia: "un atacante
     entra como admin sin contraseña y accede a toda la base de usuarios".
  2. **D5 Path traversal** — lectura de archivos arbitrarios del servidor
     (`/etc/passwd`, configs con secretos).
  3. **D2 Debug en prod** — filtra rutas internas, PID y ubicación de la DB:
     munición para los otros ataques.
  4. **D3 /backup expuesto** — filtra un dump sin auth.
  5. **D1 Banner** — el de menor impacto directo: solo facilita el fingerprinting.

## 5. Conclusión

Romper PhantomCorp (labs 05–07) fue más fácil que arreglarla: atacar necesita
**un** agujero; defender exige cerrarlos **todos** y además no romper la
funcionalidad legítima. Varias defensas (D1, D3-robots) son solo ocultamiento y
no reemplazan el fix estructural (parametrizar, proteger rutas, validar rutas de
archivo). Endurecer es trabajo sistemático; explotar, oportunista.
