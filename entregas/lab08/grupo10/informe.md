# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 10 · **Fecha:** 30/10/2026

| Integrante | Legajo | GitHub |
|---|---:|---|
| Belén Rocío Ramello | 15226 | [@belramello](https://github.com/belramello) |
| Carolina Paula Corazza | 15239 | [@carocor1](https://github.com/carocor1) |
| Chiara Agustina Kordek | 14719 | [@chiarakordek](https://github.com/chiarakordek) |
| Juan Pablo Saby | 15026 | [@JuanSaby](https://github.com/JuanSaby) |

## 0. Declaración de uso de IA

Se consultó Codex para aclarar dudas conceptuales y recibir apoyo puntual con la preparación de partes del informe. La ejecución práctica y validación del recolector se realizaron
en Docker.

## 1. Flags capturadas

Se obtuvieron en los contenedores locales del laboratorio y las cinco fueron aceptadas por el verificador oficial:

| Reto | Flag | Evidencia resumida |
|---|---|---|
| R1 | `FLAG{post_situational_awareness}` | Nota legible en `/opt/phantom-deploy/DEPLOY_NOTES.txt`. |
| R2 | `FLAG{loot_credentials_found}` | Campo `APP_SECRET` de `/var/www/.env`; otros valores se omiten por ser credenciales. |
| R3 | `FLAG{privesc_suid_root}` | Lectura de `/root/flag.txt` con el binario SUID y `bash -p`; `id` mostró `euid=0(root)`. |
| R4 | `FLAG{pivot_internal_host}` | Respuesta de `http://phantomcorp-db/` desde la víctima. |
| R5 | `FLAG{automation_pays_off}` | Hallazgo del recolector en el legajo 187. |

Salida resumida de `./ctf status 08`:

```text
R1 ✓  Reconocimiento del host comprometido
R2 ✓  Loot de credenciales
R3 ✓  Escalada de privilegios (SUID)
R4 ✓  Pivoting al host interno
R5 ✓  Automatizacion (fuerza bruta de legajos)
5/5 (100%) — Lab 08 COMPLETO
```

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host | Entré como `operador` en `phantomcorp`. `uname -a` identificó Linux sobre WSL2; `ip addr` mostró dos interfaces de red (172.19.0.3 y 172.20.0.2). | `id; whoami; hostname; uname -a; ip addr; cat /etc/hosts; ls -la /opt/phantom-deploy` | `id` devolvió UID/GID 1000; la nota de despliegue en `/opt/phantom-deploy/DEPLOY_NOTES.txt` contenía R1. | No dejar tokens en notas legibles para usuarios de servicio; restringir permisos y retirar artefactos de despliegue. |
| Loot | Revisé el historial de `operador` y el `.env`; el archivo contenía credenciales de DB y una clave de aplicación. En este informe se omiten las credenciales y solo se conserva la flag del reto. | `cat /home/operador/.bash_history`; `grep '^APP_SECRET=' /var/www/.env` | El historial mostraba comandos previos sobre `.env` y el host interno; `APP_SECRET` devolvió R2. | No guardar secretos en `.env` legibles ni en historiales; usar un gestor de secretos, permisos mínimos, credenciales temporales y rotación/revocación. |
| Privesc (SUID) | Hallé `/usr/local/bin/system-check`, una copia SUID de Bash propiedad de root. | `ls -l /usr/local/bin/system-check`; `/usr/local/bin/system-check -p -c 'id; cat /root/flag.txt'` | `ls -l` mostró `-rwsr-xr-x root root`; `id` dentro del shell devolvió `euid=0(root)` y se leyó R3. | Quitar SUID a copias de shells; auditar el inventario SUID, aplicar mínimo privilegio y alertar por cambios de permisos. |
| Pivoting | Desde el atacante, `phantomcorp-db` no resolvió/conectó (timeout al resolver). Desde la víctima, la consulta HTTP llegó al host interno. | Desde atacante: `curl --connect-timeout 2 http://phantomcorp-db/`; desde víctima: `curl http://phantomcorp-db/` | La víctima recibió JSON con el nombre del host y R4; la consola atacante agotó el tiempo de resolución. | Segmentar redes, limitar flujos salientes y conexiones entre servicios, y monitorear tráfico de servidores expuestos. |

## 3. Automatización

`src/recolector.py` recorre el rango inclusivo indicado, consulta cada legajo y busca un campo no presente en los registros normales (`id`, `nombre`, `area`). Cuando encuentra un valor de texto en un campo adicional, devuelve el legajo y corta el recorrido. Los errores de consulta y las respuestas 404 se manejan en `consultar_legajo()`.

Copié el archivo al contenedor víctima y lo ejecuté con el servicio interno disponible:

```text
docker cp entregas/lab08/grupo10/src/recolector.py cyberlab-phantomcorp:/tmp/recolector.py
docker exec -u operador cyberlab-phantomcorp \
python3 /tmp/recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
```

Salida observada: `Flag en el legajo id=187: FLAG{automation_pays_off}` (código de salida 0). El informe omite las credenciales que aparecieron en `.env`.

## 4. Preguntas de análisis

**P1 — SUID y el flag `-p`.** El bit SUID hace que un ejecutable se inicie con el UID efectivo de su propietario, que puede ser `root`, aunque lo invoque un usuario sin privilegios. Por eso, un binario SUID con funciones que permitan ejecutar otros comandos puede cruzar la frontera de privilegios. En Bash, `-p` evita que el shell descarte el UID efectivo privilegiado al arrancar. En este reto, el `id` dentro de `system-check -p` confirmó `euid=0(root)`.

**P2 — El pivoting.** La consola atacante no pudo resolver el nombre `phantomcorp-db`; la víctima, conectada a ambas redes, sí recibió respuesta HTTP de ese host. La diferencia observada demuestra que la víctima servía de pivote hacia la red interna.

**P3 — Cómo evitar secretos en `.env` y `.bash_history`.** No incluir secretos en comandos interactivos ni en archivos de configuración legibles por usuarios que no los necesitan. Usar un gestor de secretos con acceso autenticado y auditado, inyectar credenciales con alcance y duración limitados en tiempo de ejecución, restringir permisos, rotar credenciales y evitar que procesos o diagnósticos las vuelquen a logs. Si un secreto pudo quedar expuesto, rotarlo; borrar el archivo o el historial no invalida la credencial.

**P4 — Qué decidiste vos que el script no decide solo.** Una persona define el objetivo autorizado, el rango de IDs, el ritmo de las consultas y qué respuesta cuenta como hallazgo. También interpreta el resultado, decide si hay que detener la actividad y evita recolectar o divulgar datos que no son necesarios. El script solo repite las solicitudes y aplica la condición programada; no evalúa autorización, impacto ni contexto.

**P5 — Defensa para SUID y pivoting.** Para SUID: reducir el inventario a lo estrictamente necesario, revisar propietarios y permisos, quitar el bit a copias o utilidades que no lo requieran y alertar ante cambios. Para comprobar que la medida funciona, un administrador audita el inventario de binarios SUID —por ejemplo con `find / -perm -4000 -type f`— y lo contrasta contra una línea base aprobada: la verificación es exitosa si no aparecen copias SUID innecesarias ni utilidades que no deberían tener el bit. Para pivoting: segmentar la red interna, limitar con reglas de firewall qué servicios puede alcanzar el servidor web, restringir y monitorear su tráfico saliente, y exigir autenticación en los servicios internos. Para verificarlo, desde el propio servidor web se intenta alcanzar el host de base de datos en su puerto —por ejemplo con una conexión de prueba— y se confirma que el firewall la rechaza y que el intento queda registrado como bloqueado: la defensa funciona si el servidor web no llega directamente a la base.
