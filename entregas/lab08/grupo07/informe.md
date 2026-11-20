# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha:** 2026-11-19 (America/Buenos_Aires)

> Esta edición cubre el bloque de Lorenzo: R1, R2 y P3. R3–R5, el recolector y las otras preguntas se completan por sus responsables antes de integrar el informe grupal.

## 0. Declaración de uso de IA

Se usó OpenAI Codex como asistente con acceso a la terminal local para preparar y ejecutar la enumeración del contenedor víctima, capturar los resultados, investigar fuentes sobre gestión de secretos y redactar el bloque asignado. La IA ejecutó los comandos registrados. No se leyó el código del objetivo para obtener flags. El objetivo compiló desde una copia temporal con solo los finales de línea normalizados a LF, porque el checkout de Windows convertía `setup.sh` a CRLF y el shebang fallaba; las fuentes originales y la configuración de red no se modificaron. Lorenzo debe revisar y poder explicar la evidencia antes de la entrega final.

## 1. Flags capturadas

Estado observado con `./ctf status 08`:

```text
R1  Reconocimiento del host comprometido                  resuelto
R2  Loot de credenciales                                   resuelto
R3  Escalada de privilegios (SUID)                         pendiente
R4  Pivoting al host interno                               pendiente
R5  Automatizacion (fuerza bruta de legajos)               pendiente
Progreso: 2/5 (40%)
```

La salida completa está en `evidencia/salidas/status-08.txt`.

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host (R1) | Confirmé la identidad `operador`, el host `phantomcorp` y dos interfaces en redes Docker distintas. Enumeré `/opt` y encontré una nota de despliegue con un token. | `id; whoami; hostname; uname -a; ip addr; ls -la /opt; find /opt -maxdepth 2 -type f ...` | `evidencia/salidas/r1-r2-recon-loot.txt`; nota `/opt/phantom-deploy/DEPLOY_NOTES.txt`; R1 fue aceptado por el CTF. | No dejar notas/artefactos de despliegue con tokens en el host. Retirar los artefactos temporales y rotar/revocar secretos expuestos. |
| Loot (R2) | Leí `/var/www/.env` y el historial de `operador`. El `.env` contiene parámetros de DB y un secreto de aplicación, con permisos `0644`; el historial observado registra comandos de inspección, sin una contraseña en texto plano. | `ls -la /var/www; cat /var/www/.env; ls -la /home/operador; cat /home/operador/.bash_history` | `evidencia/salidas/r1-r2-recon-loot.txt`; R2 fue aceptado por el CTF. | Sacar secretos del webroot, limitar acceso del servicio y del sistema de archivos, usar un gestor de secretos con credenciales de alcance mínimo y rotación; evitar escribir secretos en comandos/historial. |
| Privesc (SUID) | Pendiente — bloque de Guadalupe. | Pendiente. | Pendiente. | Pendiente. |
| Pivoting | Pendiente — bloque de Guadalupe. | Pendiente. | Pendiente. | Pendiente. |

## 3. Automatización

Pendiente — implementación y operación a cargo de Fernando.

## 4. Preguntas de análisis

**P1 — SUID y `-p`:** pendiente — bloque de Guadalupe.

**P2 — pivoting:** pendiente — bloque de Lautaro.

**P3 — cómo evitar secretos en `.env` y `.bash_history`:** el `.env` observado guarda credenciales y un secreto en `/var/www`, accesible desde la cuenta `operador`; poner variables en un archivo con nombre oculto no lo protege. El archivo debe quedar fuera del webroot y con acceso restringido, pero los permisos por sí solos no sustituyen una gestión de secretos: en despliegue conviene inyectarlos desde un gestor central, con identidad de workload, privilegio mínimo, vigencia limitada, auditoría y rotación/revocación si se exponen. Para el shell, no se deben pasar contraseñas como argumentos ni pegarlas en comandos que puedan quedar en el historial o en logs; se usan entradas secretas del cliente, descriptores de archivo o mecanismos de credenciales del gestor. `HISTCONTROL`/`HISTIGNORE` sirven como higiene de historial, pero no son un control de seguridad equivalente. En la evidencia de esta sesión, `.bash_history` contiene comandos de inspección, no el valor de la contraseña. [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) · [GNU Bash Reference Manual — Bash Variables](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html).

**P4 — decisiones del script:** pendiente — bloque de Fernando.

**P5 — defensas SUID y pivoting:** pendiente — bloque de Lautaro.

## 5. Bitácora de comandos

Los comandos completos están en `evidencia/comandos.txt`; las salidas crudas de identidad, host, R1 y R2 están en `evidencia/salidas/r1-r2-recon-loot.txt`. Las flags se enviaron desde el host con `./ctf submit 08`; el estado resultante se adjunta.
