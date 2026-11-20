# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 06
**Fecha:** 23/10/2026 (última actualización: 28/10/2026)

| Nombre y apellido  | Legajo | Usuario de GitHub |
| ------------------ | -----: | ----------------- |
| Martín Beccereca   |  15154 | martinbeccereca   |
| María Belén Benito |  14625 | belubenito603     |
| Alejo De Miguel    |  15138 | AlejoDM           |
| Tomás Giudici      |  14977 | TomasGiudici      |
| Carolina Suppo     |  15057 | carosuppo         |

## 0. Declaración de uso de IA

**Codex (OpenAI).** Lo usamos para organizar la evidencia y redactar la primera versión de la fila de loot, la respuesta P2 y el mini-research. Las credenciales y flags consignadas salen de comandos que ejecutamos dentro del entorno del Lab 08, y las fuentes del research se leyeron antes de incorporarlas.

**Claude Code.** Lo usamos para ejecutar el reconocimiento de R1 sobre `/opt` en el host víctima, consolidar `evidencia/comandos.txt` y redactar la fila de recon y su análisis. Los comandos se ejecutaron como `operador` y la salida se guardó sin editar en `evidencia/salidas/`. En la revisión final también lo usamos para corregir la redacción del informe y del research, contrastar las afirmaciones con las salidas guardadas, verificar las fuentes, redactar el esbozo del pipeline (bonus) en el research y limpiar los comentarios de plantilla de `src/recolector.py` (sin cambiar su lógica).

**ChatGPT (OpenAI).** Lo usamos para implementar y probar `buscar_flag()` en `src/recolector.py`, interpretar respuestas HTTP y redactar la sección de automatización, la respuesta P4 y los comandos de R5. El script se ejecutó como `operador` dentro de la víctima contra `phantomcorp-db`.

**OpenCode.** Lo usamos para ejecutar el pivoting de R4, guardar sus salidas (`r4-pivot-victima.txt`, `r4-pivot-atacante.txt`, `r4-submit.txt`) y redactar la fila de pivoting, su análisis, la respuesta P5 y el bloque de R4 en la bitácora. Los comandos se ejecutaron en la víctima como `operador` y en la consola atacante, y la flag fue aceptada por `./ctf submit 08 R4` desde la raíz del repositorio.

En todos los casos revisamos el contenido antes de incorporarlo.

## 1. Flags capturadas

| Reto                    | Flag                                | Evidencia                                                                                                                                                                                                          |
| ----------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| R1 — Recon del host     | `FLAG{post_situational_awareness}`  | [r1-recon-opt.txt](evidencia/salidas/r1-recon-opt.txt), [r1-submit.txt](evidencia/salidas/r1-submit.txt)                                                                                                          |
| R2 — Loot               | `FLAG{loot_credentials_found}`      | [r2-loot-env.txt](evidencia/salidas/r2-loot-env.txt)                                                                                                                                                               |
| R3 — Privesc (SUID)     | `FLAG{privesc_suid_root}`           | [r3-suid-enumeracion.txt](evidencia/salidas/r3-suid-enumeracion.txt), [r3-privesc-identidad.txt](evidencia/salidas/r3-privesc-identidad.txt), [r3-privesc-flag.txt](evidencia/salidas/r3-privesc-flag.txt)       |
| R4 — Pivoting           | `FLAG{pivot_internal_host}`         | [r4-pivot-victima.txt](evidencia/salidas/r4-pivot-victima.txt), [r4-pivot-atacante.txt](evidencia/salidas/r4-pivot-atacante.txt), [r4-submit.txt](evidencia/salidas/r4-submit.txt)                               |
| R5 — Automatización     | `FLAG{automation_pays_off}`         | [r5-recolector.txt](evidencia/salidas/r5-recolector.txt), [r5-status-08.txt](evidencia/salidas/r5-status-08.txt)                                                                                                  |

El estado final de `./ctf status 08` es 5/5 ([status-08.txt](evidencia/salidas/status-08.txt)). Ese archivo muestra una consolidación del 28/10: las cinco flags se volvieron a presentar desde la raíz del repositorio y el validador respondió «Correcta (ya la tenías)» en todas, es decir, no son cinco validaciones nuevas de ese día sino la confirmación del progreso registrado. Antes de eso, R5 se había validado con una copia temporal del validador dentro de la consola atacante, que mostraba solo ese reto (1/5, [r5-status-08.txt](evidencia/salidas/r5-status-08.txt)), y R4 con el validador del repositorio ([r4-submit.txt](evidencia/salidas/r4-submit.txt)).

## 2. Informe de post-explotación

| Fase           | Qué hicimos                                                                                                                                                                  | Comando/técnica                                                                                                                                                                                      | Evidencia                                                                                                                                                                                                 | Defensa                                                                                                                                                                                                                                        |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recon del host | Como `operador`, confirmamos identidad y host y enumeramos `/opt`. Encontramos una nota de despliegue legible por el usuario limitado.                                      | `id`, `hostname`, `hostname -I`, `ls -la /opt /opt/phantom-deploy`, `cat /opt/phantom-deploy/DEPLOY_NOTES.txt`                                                                                    | [r1-recon-opt.txt](evidencia/salidas/r1-recon-opt.txt): `uid=1000(operador)`, host `phantomcorp`, `DEPLOY_NOTES.txt` con permisos `-rw-r--r--` y la línea `deploy_token=FLAG{post_situational_awareness}`. | No dejar notas ni artefactos de despliegue en el servidor; si un archivo es necesario, restringir su lectura a la cuenta que lo usa. Revisar el filesystem resultante de cada deploy antes de pasarlo a producción.                           |
| Loot           | Leímos el archivo de configuración de la aplicación con la misma cuenta limitada.                                                                                            | `ls -la /var/www`, `cat /var/www/.env`                                                                                                                                                              | [r2-loot-env.txt](evidencia/salidas/r2-loot-env.txt): `.env` de `root:root` con permisos `0644`; contiene `DB_HOST`, `DB_USER=phantom_app`, `DB_PASS` y `APP_SECRET=FLAG{loot_credentials_found}`.       | Quitar el permiso de lectura para otros usuarios (`chmod 640` con el grupo del servicio, o `600`), entregar la credencial desde un gestor de secretos y rotar la contraseña expuesta.                                                         |
| Privesc (SUID) | Buscamos binarios SUID y encontramos uno no estándar, `/usr/local/bin/system-check`. Lo ejecutamos con `-p` y leímos `/root/flag.txt`.                                     | `find / -type f -perm -4000 2>/dev/null`, `ls -l`, `sha256sum` contra `/bin/bash`, `system-check -p -c 'id'`, `system-check -p -c 'cat /root/flag.txt'`                                           | [r3-suid-enumeracion.txt](evidencia/salidas/r3-suid-enumeracion.txt) lista `system-check` junto a binarios SUID habituales; [r3-privesc-identidad.txt](evidencia/salidas/r3-privesc-identidad.txt) muestra `uid=1000(operador) ... euid=0(root)`; [r3-privesc-flag.txt](evidencia/salidas/r3-privesc-flag.txt) contiene la flag. | Quitar el bit SUID con `chmod u-s /usr/local/bin/system-check` y controlar en cada despliegue que la lista de binarios SUID coincida con una línea base aprobada.                                                                             |
| Pivoting       | Desde la víctima resolvimos y consultamos `phantomcorp-db`; desde la consola atacante repetimos la consulta como contraste.                                                 | Víctima: `ip addr`, `cat /etc/hosts`, `getent hosts phantomcorp-db`, `curl -isS http://phantomcorp-db/`. Atacante: `hostname -I`, `getent hosts phantomcorp-db`, `curl http://phantomcorp-db/`. | [r4-pivot-victima.txt](evidencia/salidas/r4-pivot-victima.txt): interfaces 172.21.0.3 y 172.20.0.3, `phantomcorp-db` en 172.20.0.2, `HTTP/1.0 200 OK` con la flag. [r4-pivot-atacante.txt](evidencia/salidas/r4-pivot-atacante.txt): solo 172.21.0.2 y `curl: (6) Could not resolve host`. | Filtrar el tráfico entre zonas con política de denegación por defecto: desde la red de aplicación, permitir solo el puerto que la aplicación usa y solo desde su proceso o cuenta de servicio. La base debe exigir autenticación propia. |

### Recon del host

La salida de R1 muestra que el proceso corría como `uid=1000(operador)` en `phantomcorp`. En `/opt` había un solo directorio, `phantom-deploy`, de `root:root`, con un archivo `DEPLOY_NOTES.txt` legible por cualquier usuario. Su contenido era `PhantomCorp - notas de despliegue (NO borrar)` y `deploy_token=FLAG{post_situational_awareness}`.

Que una cuenta de aplicación pueda leer una nota de despliegue indica que el proceso de deploy dejó artefactos operativos en el servidor. El nombre `deploy_token` sugiere que en un caso real podría servir para autenticar un despliegue, pero no verificamos contra qué servicio se usaría ni si estaba vigente. Encontrar el archivo no implica privilegios elevados: eso se evaluó recién en R3.

### Loot

`/var/www/.env` pertenecía a `root:root` con permisos `0644`, por lo que `operador` podía leerlo. Incluía el host de la base, el usuario `phantom_app`, su contraseña y `APP_SECRET` con la flag. El problema no es que el archivo exista, sino que cualquier cuenta local lo pueda leer: con esa contraseña, el acceso a la base interna depende solo de llegar a ella por red.

No probamos la contraseña contra la base ni contra otros sistemas, así que no sabemos qué permisos tiene `phantom_app` ni si la credencial se reutiliza.

### Privesc (SUID)

La enumeración devolvió nueve binarios SUID. Ocho son habituales en Debian (`passwd`, `su`, `mount`, `umount`, `chfn`, `chsh`, `gpasswd`, `newgrp`); el noveno, `/usr/local/bin/system-check`, está en `/usr/local`, la ubicación reservada para software instalado a mano y no por los paquetes de la distribución. Comparamos su SHA-256 con el de `/bin/bash` y coincidió, lo que indica que es una copia de Bash con otro nombre. La salida de esa comparación no quedó guardada; el comando figura en la [bitácora](evidencia/comandos.txt).

Ejecutado con `-p`, el proceso mostró `uid=1000(operador)` y `euid=0(root)`: el usuario real sigue siendo `operador`, pero el efectivo es root, y eso alcanza para leer `/root/flag.txt`. No buscamos persistencia ni otras vías de escalada.

### Pivoting

```text
┌─────────────────────┐             ┌───────────────────────────┐             ┌─────────────────────┐
│  Consola atacante   │   labnet    │  Host víctima             │ internalnet │  Host interno       │
│  attacker           ├────────────►│  phantomcorp              ├────────────►│  phantomcorp-db     │
│  172.21.0.2         │ 172.21.0/16 │  172.21.0.3 + 172.20.0.3  │ 172.20.0/16 │  172.20.0.2         │
└─────────────────────┘             └───────────────────────────┘             └─────────────────────┘
```

La víctima tiene una interfaz en cada red (`eth0` 172.21.0.3 y `eth1` 172.20.0.3). Desde ahí, `phantomcorp-db` resuelve a 172.20.0.2 y responde `HTTP/1.0 200 OK` con un JSON que dice «Base de datos interna. Acceso restringido a la LAN.» y la flag. La consola atacante solo tiene 172.21.0.2; `getent` no resuelve el nombre y `curl` termina con el error 6 (`Could not resolve host`).

La diferencia entre los dos puntos de vista es de posición en la red: la víctima pertenece a `internalnet` y el atacante no. El fallo del atacante es de resolución de nombres. No intentamos conectarnos por IP a 172.20.0.2, así que la prueba no muestra un bloqueo por IP; lo que sí muestra es que el atacante no tiene ninguna interfaz en 172.20.0.0/16, lo que es consistente con que no tenga ruta hacia esa red. No montamos túneles ni proxies: el pivote consistió en usar la víctima como punto de presencia y se limitó a la ruta raíz del servicio. Tampoco usamos las credenciales de R2 contra la base.

## 3. Automatización

Completamos `buscar_flag()` en [src/recolector.py](src/recolector.py). La función recorre los IDs del rango recibido, consulta cada legajo con `consultar_legajo()` (provista por la cátedra) y devuelve el ID y el valor apenas encuentra la clave `legajo_oculto`, que es la que distingue al legajo especial de los normales (`nombre` y `area`). Los errores HTTP, incluido el 404 de un legajo inexistente, y los errores de red se convierten en `None` y el recorrido sigue. El rango y la URL base se pasan por argumentos, y solo usa la biblioteca estándar.

Lo ejecutamos como `operador` dentro de la víctima, porque `phantomcorp-db` solo se alcanza desde ahí:

```text
$ python3 /tmp/recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
[*] Enumerando legajos 1..250 en http://phantomcorp-db
[+] Flag en el legajo id=187: FLAG{automation_pays_off}
```

El script se detuvo en el legajo 187, así que hizo 187 consultas y no 250. También lo corrimos con los rangos 1–5 y 251–251 para comprobar el caso sin hallazgo; en ambos terminó informando que no encontró el flag. Esas dos salidas no se guardaron en `evidencia/salidas/`; los comandos están en la [bitácora](evidencia/comandos.txt).

## 4. Preguntas de análisis

### P1 — ¿Por qué un binario SUID es peligroso? ¿Qué hace el flag `-p`?

Un binario con el bit SUID se ejecuta con el UID efectivo de su dueño y no con el de quien lo invoca. Tiene usos legítimos y acotados: `passwd` es SUID de root porque tiene que escribir `/etc/shadow`, pero solo hace esa operación. El riesgo aparece cuando el binario es una herramienta de propósito general que permite ejecutar comandos o leer y escribir archivos arbitrarios. Si además pertenece a root, cualquier usuario que lo ejecute obtiene privilegios de root para todo lo que esa herramienta permita hacer. GTFOBins recopila, para muchos binarios comunes, la invocación que logra esto.

En PhantomCorp el caso es el más directo posible: `system-check` es una copia de Bash con SUID de root. Bash tiene una protección propia: si arranca con UID efectivo distinto del real, baja el efectivo al real antes de ejecutar nada. La opción `-p` (modo privilegiado) desactiva ese descenso y conserva el UID efectivo. Por eso `system-check -p -c 'id'` mostró `euid=0(root)` con `uid=1000(operador)`, y sin `-p` el mismo binario habría corrido como `operador`.

### P2 — ¿Por qué el atacante no alcanzaba `phantomcorp-db` y desde la víctima sí?

Porque la consola atacante está solo en `labnet` y `phantomcorp-db` solo en `internalnet`; la víctima está en las dos (ver el diagrama de la sección de pivoting). El servicio se presenta como «Acceso restringido a la LAN» ([p2-pivot-apoyo.txt](evidencia/salidas/p2-pivot-apoyo.txt)), es decir, confía en la ubicación de red del cliente. Al comprometer la víctima quedamos dentro de esa ubicación, y un `curl` desde ahí bastó. Eso es pivotear: usar el host comprometido como punto de apoyo hacia una red que no estaba expuesta.

### P3 — ¿Qué práctica evita que los secretos queden en `.env` y `.bash_history`?

Para el `.env`, la práctica central es no guardar credenciales estáticas en archivos que lean otras cuentas. La aplicación debería obtenerlas en tiempo de ejecución desde un gestor de secretos, con acceso limitado a su propia identidad. Si el archivo es inevitable, debe tener permisos restrictivos (no `0644`), quedar fuera del control de versiones y contener solo lo necesario. Una credencial que ya quedó expuesta, como la de R2, se rota.

Para el historial, la práctica es no pasar contraseñas ni tokens como argumentos en la línea de comandos, porque quedan en `.bash_history` y también son visibles en la lista de procesos mientras el comando corre. Conviene leerlos desde un archivo protegido, desde la entrada estándar o desde el gestor de secretos. En este laboratorio el loot salió del `.env`; no encontramos secretos en un historial.

### P4 — ¿Qué decidimos nosotros que el script no decide solo?

El script repite una consulta y aplica una regla; todo lo demás lo decidimos nosotros:

- **Qué consultar y desde dónde.** Elegimos `phantomcorp-db` porque R4 mostró que solo se alcanza desde la víctima, y por eso el script corre ahí.
- **El rango.** 1 a 250 sale de la consigna; el script no sabe cuántos legajos existen.
- **Qué cuenta como hallazgo.** Antes de escribir la condición consultamos un legajo normal con `curl` y vimos qué claves tenía; la regla «tiene `legajo_oculto`» la definimos nosotros.
- **Cuándo parar.** Cortar en el primer hallazgo fue una decisión de diseño para no hacer consultas innecesarias.
- **Qué hacer con el resultado.** El script imprime la flag; presentarla, documentarla y no usar los datos de los demás legajos lo decidimos nosotros.

Un agente podría tomar algunas de estas decisiones, por ejemplo deducir la regla a partir de las respuestas, pero el alcance autorizado y el límite de lo que se hace con los datos tienen que seguir fijados por una persona. En el research esbozamos cómo se encadenarían recon, enumeración y explotación en un solo pipeline, y dónde quedarían esos controles.

### P5 — Mitigación para el privesc por SUID y para el pivoting

**SUID.** La corrección puntual es `chmod u-s /usr/local/bin/system-check`, o directamente borrar el archivo, ya que es una copia de Bash sin función legítima. Para que no vuelva a pasar, cada despliegue debería comparar la salida de `find / -perm -4000 -type f` con una línea base aprobada y bloquear el pase si aparece un binario nuevo; una herramienta de integridad como AIDE puede alertar sobre cambios de permisos. Sin el bit SUID, `operador` no puede leer `/root/flag.txt` por esta vía, aunque eso no descarta otras escaladas que no buscamos.

**Pivoting.** La víctima tiene que llegar a la base solo para lo que la aplicación necesita. La mitigación concreta es una regla de firewall en la víctima o en el borde de `internalnet` que, por defecto, deniegue el tráfico hacia `phantomcorp-db` y permita solo el puerto del servicio que usa la aplicación, idealmente solo desde su cuenta de servicio. Además, la base no debería confiar en la ubicación de red («acceso restringido a la LAN») y tendría que exigir autenticación propia. Con esa regla, el `curl` que ejecutó `operador` desde una shell habría sido rechazado; monitorear las conexiones entre zonas permitiría además detectar el intento.

## 5. Bitácora de comandos

Los comandos de cada reto, con fecha y punto de ejecución, están en [evidencia/comandos.txt](evidencia/comandos.txt). Todos se ejecutaron en los contenedores del Lab 08.
