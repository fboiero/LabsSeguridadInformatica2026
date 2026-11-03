# Evidencia — Lab 07 (validación contra el entorno Docker oficial)

Esta carpeta contiene la corrida de los cinco exploits **contra el target
`phantomcorp` del entorno Docker de la cátedra** (no en local), junto con la
salida del motor de evaluación.

| Archivo | Qué es |
|---|---|
| `exploits-docker.txt` | Transcripción completa de los 5 ataques (R1–R5) ejecutados desde la consola atacante (`cyberlab-attacker`) contra `http://phantomcorp`, con el baseline y el payload de cada reto. |
| `ctf-status-07.txt` | Salida de `./ctf status 07` tras entregar las 5 flags: `5/5 (100%)`. Las flags se validaron contra los hashes `sha256` de `labs/lab07-explotacion/retos.manifest`. |

## Cómo se reprodujo

```bash
make setup                 # construye la consola atacante (una vez)
make lab N=07              # levanta phantomcorp + atacante en la red cyberlab_labnet
make shell                 # entra a la consola atacante
./exploits/sqli.sh         # R1 y R2  (default: http://phantomcorp)
./exploits/parte2.sh       # R3, R4 y R5
# o, todo junto:
./exploits/run-all.sh
```

Luego, desde la raíz del repo, en el host:

```bash
./ctf submit 07 R1 'FLAG{sqli_auth_bypass}'
./ctf submit 07 R2 'FLAG{sqli_union_dump}'
./ctf submit 07 R3 'FLAG{command_injection_rce}'
./ctf submit 07 R4 'FLAG{path_traversal_lfi}'
./ctf submit 07 R5 'FLAG{idor_broken_access}'
./ctf status 07
```

## Hallazgos propios de correr en el Docker oficial (no visibles en local)

1. **El binario `ping` no está instalado en el contenedor del target.** El
   comando base (`ping -c1 127.0.0.1`) devuelve `ping: not found`, y aun así la
   inyección de R3 **funciona**: el separador `;` ejecuta el segundo comando
   independientemente de que el primero falle. Esto refuerza el punto del
   laboratorio — el problema no es `ping`, es que el input se concatena a una
   shell.
2. **El proceso web corre como `root` (`uid=0`).** Verificado inyectando `id`
   (`host=127.0.0.1; id` → `uid=0(root) gid=0(root)`). El RCE de R3 es, por lo
   tanto, ejecución de comandos **como root**: máximo impacto posible, y una
   mala práctica de despliegue (el servicio debería correr sin privilegios).
