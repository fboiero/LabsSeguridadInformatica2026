# Informe — Lab Extra 3: Defendé PhantomCorp

- **Grupo:** 10
- **Integrantes:** Belén Rocío Ramello (`@belramello`), Carolina Paula Corazza (`@carocor1`), Chiara Agustina Kordek (`@chiarakordek`) y Juan Pablo Saby (`@JuanSaby`).
- **Fecha:** 30/10/2026
**Declaración de uso de asistentes de IA:**

De acuerdo con lo normado en `CONTRIBUTING.md` y `docs/PROTOCOLO-EVIDENCIA.md`:

- **¿El grupo utilizó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto |
|---|---|---|---|
| Antigravity (Google DeepMind / Gemini) | redacción técnica de explicaciones analíticas, síntesis de argumentos gerenciales y revisión conceptual frente a guías OWASP. | Redacción y fundamentación técnica en las secciones de análisis P4 y P5 de `informe.md`. | Validación manual por parte de los integrantes y analsis transversal final por el agente integrado en Antigravity contrastando cada afirmación técnica contra el código de `server.py`, las corridas reales del verificador (`verificar-defensa.py`, `verificar-regresion.py`) y las salidas crudas en `evidencia/salidas/`. |

*El grupo declara que comprende el contenido íntegro de lo entregado y que cualquiera de sus integrantes puede explicar y defender oralmente en vivo cada parte del código, de los parches y del análisis presentado, independientemente de la asistencia recibida.*

---

## 1. Tabla de defensas

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación |
|---|---|---|---|
| D1 | La respuesta HTTP revelaba `PhantomServer/2.4.1-debug`. | El servidor ya no anuncia nombre ni versión en el encabezado `Server`. | El verificador recibió `Server: ''`; D1 quedó aprobada. |
| D2 | `GET /api/status` respondía 200 con `debug`, ruta de base de datos y PID. | Se deshabilitó el endpoint de debug; responde 404. | `GET /api/status -> 404`; D2 quedó aprobada. |
| D3 | `robots.txt` revelaba `/backup` y esa ruta devolvía información sin autorización. | Se quitó la ruta del archivo de robots y `/backup` ahora responde 404. | El verificador confirmó 404 y que `robots.txt` no nombra `/backup`; D3 quedó aprobada. |
| D4 | Datos de login concatenados al SQL permitían los dos bypass del verificador. | Se usa `?` con los valores enlazados como parámetros de SQLite. | Ambos bypass quedaron bloqueados y el login válido siguió funcionando; D4 quedó aprobada. |
| D5 | `archivo=../../../../etc/passwd` podía leerse fuera del directorio de descargas. | La ruta se canonicaliza y solo se sirve si permanece dentro de la raíz permitida y es un archivo. | El verificador devolvió 404 para la ruta externa; la descarga de `manual.txt` funcionó; D5 quedó aprobada. |

### Nota de verificación en Windows

El verificador oficial usa `/etc/passwd`, que no es un archivo de Windows. Para que la comprobación D5 no aprobara por ausencia del archivo, se preparó una fixture local controlada con el marcador `root:lab-extra-fixture` fuera de la carpeta de descargas. La copia vulnerable leyó esa fixture mediante el mismo payload y devolvió 200; la copia endurecida rechazó el acceso con 404. No se leyó ningún archivo real del sistema.

## 2. Regresión funcional

Después de los parches se verificaron estas funciones:

- `GET /`: HTTP 200.
- Login válido de la consigna: HTTP 200.
- Login inválido: HTTP 401.
- Descarga de `manual.txt`: HTTP 200 y contenido esperado.
- Intento de traversal a la fixture externa: HTTP 404, sin revelar el marcador.

La salida cruda está en `evidencia/salidas/02-regresion-funcional.txt`; el script reproducible es `evidencia/verificar-regresion.py`.

## 3. Evidencia de progreso

- El objetivo original obtuvo 0/5 defensas; salida en `evidencia/salidas/00-verificacion-inicial.txt`.
- La copia del grupo obtuvo 5/5; salida en `evidencia/salidas/01-verificacion-final.txt`.
- `./ctf status extra3` registró las cinco defensas; salida en `evidencia/salidas/03-status-extra3.txt`.
- Los comandos se enumeran en `evidencia/comandos.txt`.
- Captura real de `./ctf status extra3`: `evidencia/status-extra3.png`.

## 4. Preguntas P1–P5

### P1 — Antes y después

Antes del cambio, `BaseHTTPRequestHandler` enviaba `Server: PhantomServer/2.4.1-debug`. El verificador reconocía el producto y la versión. Se neutralizó el banner configurando `server_version` y `sys_version` sin datos identificatorios; la petición de prueba recibió un encabezado `Server` vacío y D1 pasó. La evidencia del ataque inicial y la salida final está en los archivos de verificación de la sección anterior.

### P2 — ¿Por qué no alcanza con quitar `/backup` de `robots.txt`?

`robots.txt` es una convención dirigida a rastreadores bien comportados: les pide qué rutas no indexar, pero no autentica ni autoriza nada, y un cliente que ignore el archivo —un navegador, un script o un atacante— puede pedir la ruta igual. Por eso, sacar `/backup` de `robots.txt` solo deja de anunciar que la ruta existe; si el servidor sigue respondiendo contenido en `/backup` para cualquiera que la pida directamente, el recurso sigue expuesto, solo que ahora hay que adivinarla o descubrirla por otro medio (fuerza bruta de rutas, un enlace filtrado, un escaneo) en lugar de leerla en un archivo público.

La defensa real es la segunda: que el propio servidor decida, en el código que maneja la petición, si esa ruta puede responder y con qué contenido, sin depender de que el cliente coopere. Es la diferencia entre ocultar la puerta y cerrarla con llave.

En este laboratorio, D3 implementó ambas capas porque no son excluyentes, pero quedó claro cuál es la que protege. En `objetivo/server.py`, `robots.txt` ya no lista `/backup` (devuelve `User-agent: *\nDisallow:\n`, sin rutas), y **además** `/backup` responde `404` directamente, sin pedir ninguna credencial:

```python
elif path == "/backup":
    # D3: el recurso sensible no está disponible sin autorización.
    self._txt(404, "404 - no existe")
```

La verificación lo distingue como dos comprobaciones separadas (tabla, sección 1): que `robots.txt` no mencione `/backup` y, por separado, que `GET /backup` devuelva `404`. Si solo se hubiera tocado `robots.txt` y la ruta siguiera devolviendo 200 con su contenido, el verificador habría aprobado la ocultación pero reprobado el acceso: la ruta seguiría ahí para cualquiera que la pidiera por otro medio. Lo que efectivamente cerró la exposición fue que el servidor dejara de servir el recurso, no que dejara de nombrarlo.

### P3 — Seguridad por oscuridad

D1 reduce la información pasiva que el encabezado revela, pero no corrige las vulnerabilidades de la aplicación. Ocultar producto y versión puede dificultar una identificación rápida, aunque un atacante todavía puede inferir tecnología con otras respuestas y pruebas. Por eso el cambio es una medida complementaria de reducción de exposición, no una barrera de acceso ni un sustituto de corregir D2–D5.

### P4 — ¿Por qué no conviene quitar comillas con `replace`?

Usar `user.replace("'", "")` elimina un carácter, pero mantiene el problema de fondo: la entrada se concatena dentro de una instrucción SQL. Es un filtro manual cuya eficacia depende del contexto de la consulta y de las reglas de sintaxis y escape del motor; no establece una separación entre datos y código. Además, altera nombres legítimos que contienen apóstrofos. Aunque pueda bloquear un payload puntual, eso no lo convierte en una defensa estructural.

En este laboratorio hay un caso concreto: filtrar solamente `user` deja intacto `pass`, que también se concatenaba en la consulta original. El segundo ataque del verificador usa `user=x` y `pass=' OR 1=1 --`; la comilla cierra el valor de la contraseña, `OR 1=1` vuelve verdadera la condición y `--` comenta el resto. Por eso quitar comillas únicamente del usuario no evita ese bypass. Aplicar filtros manuales a ambos campos tampoco es la solución recomendada: seguiría dependiendo de transformar correctamente cada entrada antes de construir SQL.

La solución implementada en D4, en `objetivo/server.py`, es:

```python
cur = db.execute(
    "SELECT user FROM usuarios WHERE user = ? AND password = ?",
    (user, pwd),
)
```

El texto de la consulta es fijo y los dos `?` son marcadores de valores. SQLite recibe `user` y `pwd` por separado, mediante la tupla de parámetros, y los trata como datos, no como instrucciones SQL. Una entrada como `admin'--` se compara como un nombre literal: sus comillas y guiones no pueden modificar el `WHERE` ni comentar la comprobación de contraseña. Lo importante es pasar los valores como segundo argumento de `execute`, sin interpolarlos ni concatenarlos previamente.

La evidencia guardada en `evidencia/salidas/00-verificacion-inicial.txt` muestra que los dos bypass funcionaban; `evidencia/salidas/01-verificacion-final.txt` registra ambos bloqueados tras el cambio. Además, `evidencia/salidas/02-regresion-funcional.txt` confirma que el login legítimo sigue devolviendo HTTP 200 y el inválido HTTP 401. Estas pruebas respaldan el resultado de D4 para los casos ensayados, sin afirmar que el verificador cubra todos los ataques posibles.

### P5 — Ranking de gravedad

A partir de las pruebas ejecutadas y los efectos comprobados en el laboratorio, se establece la siguiente priorización de los hallazgos de seguridad (ordenados de mayor a menor criticidad):

| Puesto | Hallazgo | Severidad | Justificación resumida |
|---|---|---|---|
| **#1** | **D4** — SQL Injection en `/login` | **Crítica** | Anulación total del control de acceso; permite autenticarse como administrador sin credenciales legítimas. |
| **#2** | **D5** — Path Traversal en `/descargar` | **Alta** | Ruptura del confinamiento del sistema de archivos; permite leer archivos arbitrarios del servidor host. |
| **#3** | **D3** — Ruta `/backup` expuesta sin autenticación | **Media** | Fuga directa de recurso administrativo sensible listado abiertamente en `robots.txt`. |
| **#4** | **D2** — Endpoint `/api/status` activo en producción | **Baja-Media** | Divulgación de metadatos internos (modo debug, PID, ruta absoluta de base de datos) que asiste al atacante. |
| **#5** | **D1** — Banner informativo en encabezado `Server` | **Baja / Informativa** | Reconocimiento pasivo de tecnología y versión (`PhantomServer/2.4.1-debug`); no compromete datos por sí solo. |

#### Justificación del puesto #1 para la gerencia

Si tuviéramos que presentar este análisis ante la dirección o gerencia de la empresa, el hallazgo prioritario e insoslayable es **D4 (SQL Injection en `/login`)**.

La autenticación es el perímetro fundamental que sostiene la confianza, la confidencialidad y la auditoría de cualquier aplicación corporativa. D4 no representa una simple fuga de datos aislada, sino la quiebra absoluta de ese mecanismo de control: mediante una única petición HTTP no autenticada (`/login?user=admin'--&pass=x` o `/login?user=x&pass=' OR 1=1 --`), cualquier usuario externo puede suplantar la identidad del administrador (`admin`) y obtener acceso inmediato a la aplicación con privilegios plenos. Desde la perspectiva de negocio y gestión de riesgos, que una entidad no autorizada pueda asumir el rol de mayor jerarquía operativa destruye la trazabilidad de las acciones y compromete de raíz la integridad de las operaciones de la empresa.

#### Relación con los efectos observados y jerarquía de riesgos

- **D4 vs. D5 (Nivel Crítico/Alto):** D5 es un hallazgo de severidad muy alta porque quiebra el aislamiento entre el servidor web y el sistema operativo subyacente, permitiendo la lectura arbitraria de archivos fuera de la carpeta pública de descargas (en el lab, la lectura de `/etc/passwd` o de la fixture externa con `root:lab-extra-fixture`). No obstante, en este entorno D5 se limitó a una lectura no autenticada de archivos del host; no otorgó capacidades de escritura ni ejecución remota de comandos. En cambio, D4 concedió acceso interactivo directo con la máxima identidad de la aplicación (`admin`), motivo por el cual encabeza la prioridad. Ambos hallazgos interactúan además de forma peligrosa: con D5 se podría apuntar a leer el archivo de base de datos SQLite cuya ruta absoluta fue expuesta por D2.
- **D3 (Nivel Medio):** Ocupa una posición intermedia. El verificador demostró que `/backup` devolvía HTTP 200 sin exigir autenticación alguna, además de encontrarse señalada públicamente en `robots.txt`. En un entorno productivo real, un endpoint de backup desprotegido suele ser crítico si contiene volcados de bases de datos o secretos; en la prueba concreta del laboratorio, el impacto demostrado se limitó a un mensaje estático de migración, por lo que su severidad observada es menor que la de D4 y D5.
- **D2 y D1 (Nivel Bajo):** Son hallazgos de exposición de información. D2 reveló parámetros del entorno productivo (`debug: true`, PID y la ruta interna de la base de datos). Aunque no permite tomar control directo del servidor, provee información valiosa que alimenta otros ataques (como la ruta exacta de la base de datos para intentar descargarla mediante D5). Finalmente, D1 es el hallazgo de menor prioridad: divulgar `PhantomServer/2.4.1-debug` facilita la fase de reconocimiento pasivo del atacante, pero por sí solo no altera el estado de la aplicación ni expone datos del negocio.

#### Limitaciones de la evidencia y alcance demostrado

Para no confundir el impacto potencial teórico con el impacto efectivamente demostrado en las pruebas de laboratorio (`evidencia/salidas/00-verificacion-inicial.txt`, `evidencia/salidas/01-verificacion-final.txt` y `evidencia/salidas/02-regresion-funcional.txt`), deben señalarse las siguientes limitaciones:

1. **Alcance de la inyección SQL (D4):** Las pruebas demostraron de manera concluyente el *bypass* de autenticación mediante dos entradas específicas (`admin'--` y `' OR 1=1 --`). Sin embargo, no se demostró la ejecución de consultas múltiples destructivas (como `DROP` o `UPDATE`) ni la ejecución de comandos en el sistema operativo. El controlador utiliza la biblioteca estándar `sqlite3` de Python y el método `execute()`, el cual procesa una única sentencia SQL por invocación y no admite *stacked queries* separadas por punto y coma. Tampoco se demostró extracción masiva de datos mediante `UNION SELECT`, ya que la vista solo proyecta el identificador de usuario en el mensaje de bienvenida.
2. **Naturaleza de la lectura en Path Traversal (D5):** La evidencia confirmó que la aplicación permitía leer archivos arbitrarios legibles por el proceso fuera de la ruta autorizada. La prueba no demostró escritura, borrado ni ejecución remota de código (LFI/RFI ejecutable). Asimismo, la prueba original del verificador apuntaba a `/etc/passwd` (propio de entornos Unix/Linux), lo cual en Windows requirió generar una fixture controlada externa para verificar que la vulnerabilidad residía en la lógica de la aplicación y no en un falso positivo por inexistencia del archivo objetivo.
3. **Representatividad del verificador automático:** Los scripts `verificar-defensa.py` y `verificar-regresion.py` constituyen pruebas funcionales y dinámicas acotadas a patrones conocidos. Que los cinco ataques hayan arrojado resultado bloqueado demuestra que los vectores probados fueron neutralizados con éxito, pero no equivale a una prueba exhaustiva de ausencia total de otras vulnerabilidades o variantes no contempladas en las pruebas.

## 5. Conclusión

La consigna invierte la lógica de los laboratorios ofensivos: ya no alcanza con encontrar una entrada, sino que hay que cerrar cada fallo y comprobar que la aplicación conserve sus funciones legítimas. En esta entrega, las cinco defensas pasaron el verificador y las funciones principales no presentaron regresiones. El grupo completará las respuestas pendientes y revisará el informe antes de entregar.
