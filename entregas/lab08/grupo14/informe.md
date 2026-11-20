# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 14 · **Integrantes:** ver [`INTEGRANTES.md`](INTEGRANTES.md) · **Fecha:** 19/11/2026

## 0. Declaración de uso de IA

- **Herramienta:** Claude (modelo Claude Sonnet 5.5, de Anthropic) usado a través de Claude Code (CLI), con acceso al repositorio del grupo (worktree de la rama `lab08-grupo14`).
- **Para qué se usó:**
  - Lectura y resumen del enunciado (`labs/lab08-postexplotacion/README.md`), la rúbrica y `docs/entregable.md` para armar la estructura de esta entrega.
  - Redacción de este informe y de `research.md` a partir de la teoría del enunciado y de conocimiento general de post-explotación (SUID/GTFOBins, pivoting, gestión de secretos).
  - Implementación de la función `buscar_flag()` en `src/recolector.py` (el TODO del esqueleto) y de un self-check (`src/test_recolector.py`) que mockea las respuestas HTTP para verificar la lógica sin red.
- **Qué NO se hizo con IA:** no se leyó ni se usó `labs/lab08-postexplotacion/solucion.md` en ningún momento. No se inventaron flags, salidas de comandos ni evidencia: este equipo **no tiene Docker instalado**, por lo que el entorno del lab (`./ctf lab 08`, `make shell-victima`) no pudo levantarse. Las partes que dependen de ejecutar el lab quedan marcadas abajo como **PENDIENTE (requiere Docker)**, con los comandos exactos que hay que correr para completarlas.
- **Cómo se verificó lo generado por la IA:**
  - El código de `buscar_flag()` se corrió localmente contra datos simulados (`src/test_recolector.py`, sin red, sin Docker) y pasó: `PYTHONUTF8=1 python3 test_recolector.py` → `OK: todos los self-checks pasaron`.
  - Las afirmaciones teóricas (SUID, `-p` de GTFOBins, pivoting, `.env`/`.bash_history`) se contrastaron contra el propio README del lab y contra las fuentes citadas en `research.md`.
  - Un integrante del grupo revisó el diff antes de incorporarlo.

## 1. Flags capturadas

**PENDIENTE (requiere Docker).** Este equipo no pudo levantar el entorno del lab
porque no tiene Docker instalado. Para completar esta sección, correr desde la
**raíz del repo** (no desde el host víctima):

```bash
make setup                 # una sola vez
./ctf lab 08                # levanta el host comprometido + el host interno (DB)
make shell-victima          # entra como 'operador' al host comprometido
# ... resolver R1-R5 adentro del host víctima (ver sección 2) ...
# desde la raíz del repo, afuera del host víctima:
./ctf submit 08 R1 'FLAG{...}'
./ctf submit 08 R2 'FLAG{...}'
./ctf submit 08 R3 'FLAG{...}'
./ctf submit 08 R4 'FLAG{...}'
./ctf submit 08 R5 'FLAG{...}'
./ctf status 08
```

Pegar acá la salida real de `./ctf status 08` una vez resueltos los 5 retos.

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host | **PENDIENTE (requiere Docker).** Desde `make shell-victima`, identificar usuario, sistema y red del host comprometido. | `id ; whoami ; hostname ; uname -a` / `env` / `ip addr ; cat /etc/hosts` / `ls -la /opt /var/www /home` (según el enunciado, hay una nota de deploy en `/opt` que no debería estar ahí — R1). | Pegar la salida real de los comandos de arriba. | No dejar en el host notas, scripts de deploy ni comentarios con información operativa; usar gestores de configuración/CI que no dejen rastro en el filesystem productivo. |
| Loot de credenciales | **PENDIENTE (requiere Docker).** Buscar secretos en archivos de configuración e historial de comandos. | `cat /var/www/.env` / `cat ~/.bash_history` / `grep -rai "pass\|secret\|token" /var/www 2>/dev/null` (R2). | Pegar el contenido relevante encontrado (credenciales, tokens) una vez localizado. | No versionar ni dejar `.env` en el servidor de producción; usar un *vault* (Vault, AWS Secrets Manager, SSM Parameter Store) o variables de entorno inyectadas en runtime y rotadas; limpiar `.bash_history` o deshabilitarlo para cuentas de servicio. |
| Privesc (SUID) | **PENDIENTE (requiere Docker).** Buscar binarios con bit SUID activo y no estándar, y usarlo para leer `/root/flag.txt` (R3). | `sudo -l 2>/dev/null` / `find / -perm -4000 -type f 2>/dev/null` → identificar el binario anómalo → consultar GTFOBins para ese binario → ejecutarlo con la técnica indicada (p. ej., para una copia SUID de `bash`: `/ruta/al/binario -p`, que mantiene los privilegios **efectivos** del dueño del archivo en vez de bajarlos al UID real). | Pegar la salida de `find / -perm -4000 -type f` con el binario anómalo resaltado, y la salida de `id`/`whoami` antes y después de explotarlo (demostrando `euid=0`/root). | Auditar periódicamente binarios SUID (`find / -perm -4000`) contra una lista blanca conocida del sistema operativo; quitar el bit SUID de cualquier binario no estándar (`chmod u-s`); si se necesita ejecutar algo como root, usar `sudo` con reglas específicas (`sudo -l`) en vez de SUID genérico. |
| Pivoting | **PENDIENTE (requiere Docker).** Alcanzar el host interno `phantomcorp-db`, inalcanzable desde la consola del atacante, usando el host comprometido como trampolín (R4). | Desde `make shell-victima`: `curl -s http://phantomcorp-db/` (y, si hace falta, resolver con `cat /etc/hosts` o DNS interno). Desde la consola del atacante (`make shell`), el mismo `curl` debería fallar (host no alcanzable / sin ruta). | Pegar la respuesta exitosa del `curl` desde la víctima y el error/timeout del mismo `curl` desde la consola del atacante, mostrando el contraste. | Segmentar redes de verdad (el hecho de que el host comprometido SÍ llegue a la red interna es el problema): aplicar *firewalling* y reglas de egreso entre la DMZ y la red interna incluso para tráfico que "sale" desde un host ya confiable; principio de mínimo privilegio de red (solo los puertos/servicios que el host web realmente necesita hablar con la DB, nada más); monitoreo de conexiones salientes anómalas desde hosts de la DMZ. |

## 3. Automatización

Se completó `src/recolector.py` (función `buscar_flag`), copiado del esqueleto
del lab (`labs/lab08-postexplotacion/src/recolector.py`) a esta entrega.

```python
def buscar_flag(base: str, desde: int, hasta: int) -> tuple[int, str] | None:
    CLAVES_NORMALES = {"nombre", "area"}
    for id_ in range(desde, hasta + 1):
        legajo = consultar_legajo(base, id_)
        if legajo is None:
            continue  # 404 u otro error: no es este, seguimos
        extra = set(legajo) - CLAVES_NORMALES
        if not extra:
            continue  # legajo normal, nada raro
        clave_flag = next((k for k in extra if "flag" in k.lower()), next(iter(extra)))
        return id_, legajo[clave_flag]
    return None
```

Enumera cada legajo con `consultar_legajo()` (ya provista en el esqueleto), y
detecta el legajo con el flag porque trae una clave adicional a las esperadas
(`nombre`, `area`). Apenas lo encuentra, corta el recorrido (`return`) sin
seguir consultando el resto del rango. Los 404 y otros errores de red ya son
manejados por `consultar_legajo()` (devuelve `None`), y acá se los trata como
"seguir probando con el siguiente id".

**Verificación sin Docker.** Como no se puede alcanzar `phantomcorp-db` sin
levantar el entorno, se agregó `src/test_recolector.py`: mockea
`consultar_legajo()` con datos simulados (4 legajos, uno con una clave `flag`)
y comprueba que `buscar_flag()` encuentra el legajo correcto, corta apenas lo
encuentra (no sigue consultando los ids siguientes) y devuelve `None` cuando no
hay flag en el rango o todos los ids fallan. Salida real de correrlo:

```
$ cd entregas/lab08/grupo14/src
$ PYTHONUTF8=1 python3 test_recolector.py
OK: todos los self-checks pasaron
```

**PENDIENTE (requiere Docker).** Corrida real contra el host interno, desde
`make shell-victima`:

```bash
python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
```

Pegar acá la salida real (`[+] Flag en el legajo id=...: FLAG{...}`).

## 4. Preguntas de análisis

**P1 — SUID y el flag `-p`.**
Un binario con el bit SUID (*Set User ID*) activado se ejecuta con el **UID
efectivo del dueño del archivo**, no con el del usuario que lo invoca. Si el
dueño es `root` y el binario permite, de alguna forma, ejecutar comandos o leer
archivos arbitrarios (por ejemplo una copia SUID de un intérprete como `bash`,
`python` o una utilidad como `find`/`vim`), cualquier usuario que pueda
ejecutarlo obtiene efectivamente privilegios de `root`, sin necesidad de
contraseña ni exploit de memoria: es un escalamiento directo por
*misconfiguration*. Muchos de estos intérpretes, por seguridad, al detectar
que el UID real y el UID efectivo difieren, bajan sus privilegios al UID real
(*drop privileges*) antes de hacer algo peligroso. La flag `-p` (presente en
`bash` y documentada en GTFOBins) le indica al binario que **no** haga ese
*drop*: mantiene el UID/GID efectivo (el del dueño, `root`) durante toda la
ejecución, por lo que la shell resultante queda corriendo como `root` en vez
de caer de nuevo al usuario real.

**P2 — el pivoting (por qué el atacante no llegaba y vos sí).**
La red está segmentada: existe una red "externa"/DMZ donde vive el servidor
web (`phantomcorp-web`), visible desde Internet, y una red "interna" donde
vive la base de datos (`phantomcorp-db`), que **no** tiene ninguna ruta ni
regla de firewall que la haga alcanzable desde afuera. La consola del
atacante solo tiene conectividad a la red externa, así que cualquier
`curl http://phantomcorp-db/` desde ahí falla (sin ruta / resuelve a nada).
El servidor web comprometido, en cambio, **sí** está conectado a ambas redes
(es su función legítima: hablarle a la base de datos para atender pedidos),
así que una vez que el atacante tiene ejecución de comandos en ese servidor,
puede usarlo como trampolín: emite el `curl` desde ahí, donde la ruta de red
hacia `phantomcorp-db` sí existe. Eso es pivoting: el host comprometido no es
el objetivo final, es el puente hacia una red que antes era invisible.

**P3 — cómo evitar secretos en `.env`/`.bash_history`.**
La causa raíz es tratar el filesystem del servidor como lugar seguro para
guardar secretos en texto plano. Prácticas que lo evitan: (1) gestión
centralizada de secretos (Vault, AWS Secrets Manager/SSM Parameter Store,
Doppler) que los inyecta en runtime como variables de entorno efímeras y
nunca quedan escritos en disco; (2) nunca commitear `.env` (usar `.env.example`
sin valores reales y `.gitignore`); (3) para el historial de shell, deshabilitar
o limpiar el historial en cuentas de servicio, no operar manualmente con
secretos en la línea de comandos (pasarlos por archivos con permisos
restringidos o por stdin, nunca como argumento visible en `ps`/`history`); y
(4) rotación periódica de credenciales, para que un secreto filtrado tenga
vida útil corta.

**P4 — qué decidiste vos que el script no decide solo.**
El script automatiza la *repetición* (recorrer 250 ids), pero varias
decisiones quedaron en manos humanas al escribirlo: (a) **qué contar como
"encontrado"** — decidimos que la señal es una clave fuera de las esperadas
(`nombre`, `area`), no un valor fijo; eso requiere conocer la forma de los
datos normales de antemano; (b) **cuándo parar** — decidimos cortar
inmediatamente al primer hallazgo en vez de recolectar todos los legajos y
filtrar después, para minimizar requests contra un servicio ajeno; (c) **cómo
tratar los errores** — decidimos que un 404 o un error de red en un id
individual no debe abortar todo el barrido, sino saltar ese id y seguir (la
alternativa, frenar ante el primer error, hubiera sido inútil con un rango de
250); (d) **los límites del rango y el `timeout`** — valores que el script no
infiere solo, los fija quien lo invoca según lo que sabe del objetivo. Un
agente que orqueste esto (Lab 09) todavía necesitaría que un humano le dé esos
criterios (qué es éxito, cuándo parar, qué tolerar como error) o, en el mejor
caso, que los infiera de un objetivo explícito — pero esa inferencia sigue
siendo una decisión de alto riesgo que conviene mantener supervisada,
especialmente en un contexto ofensivo real.

**P5 — defensa para SUID y para pivoting.**
- **SUID:** auditar el sistema regularmente con `find / -perm -4000 -type f` y
  compararlo contra una lista blanca de binarios SUID estándar de la
  distribución; cualquier binario SUID que no esté en esa lista (una copia de
  `bash`, `python`, etc.) se remueve o se le saca el bit (`chmod u-s`).
  Complementariamente, restringir con AppArmor/SELinux qué puede hacer un
  binario SUID aunque el bit esté puesto.
- **Pivoting:** segmentación de red real con firewall entre la DMZ (donde vive
  el servidor web) y la red interna (donde vive la base de datos), permitiendo
  solo los puertos/protocolos estrictamente necesarios para que el servidor
  web le hable a la DB — nunca "toda la red interna visible porque un host de
  la DMZ está en ambas". Sumar monitoreo de conexiones salientes inusuales
  desde hosts de la DMZ hacia la red interna, para detectar el pivot cuando
  ocurra aunque no se lo haya podido prevenir del todo.
