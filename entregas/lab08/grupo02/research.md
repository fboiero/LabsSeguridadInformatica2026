# Research — Lab 08 · Post-explotación y automatización

Material de apoyo del `informe.md`. Tácticas, técnicas y herramientas usadas en la
post-explotación de PhantomCorp.

---

## 1. Encuadre (MITRE ATT&CK)

La post-explotación encadena varias tácticas sobre un host ya comprometido:

| Fase del lab | Táctica ATT&CK | Técnica representativa |
|---|---|---|
| Recon del host | Discovery — `TA0007` | `T1082` System Information Discovery, `T1016` System Network Configuration Discovery |
| Loot de credenciales | Credential Access — `TA0006` | `T1552.001` Credentials In Files (`.env`), `T1552.003` Bash History |
| Escalada de privilegios | Privilege Escalation — `TA0004` | `T1548.001` Setuid/Setgid |
| Pivoting | Lateral Movement — `TA0008` | `T1021` Remote Services / uso del host como proxy interno |
| Automatización | Collection / Exfiltration | barrido programático del endpoint interno |

---

## 2. Herramientas y técnicas

| Tool / técnica | Para qué | Comando base |
|---|---|---|
| `id` / `whoami` / `uname -a` | ¿Quién soy? ¿Qué sistema? | `id ; uname -a` |
| `ip addr` / `/etc/hosts` | ¿A qué redes llego? (detectar dual-homing) | `ip addr` |
| `find / -perm -4000` | Listar binarios SUID | `find / -perm -4000 -type f 2>/dev/null` |
| GTFOBins (bash SUID) | Escalar a root con una copia SUID de bash | `./system-check -p` |
| `curl` | Alcanzar el host interno (pivot) y enumerar la API | `curl -s http://phantomcorp-db/` |
| `urllib` (Python stdlib) | Automatizar el barrido de 250 legajos | `python3 recolector.py` |

---

## 3. GTFOBins — por qué `bash -p` escala

[GTFOBins](https://gtfobins.github.io/) cataloga binarios de Unix y cómo abusarlos
cuando tienen permisos especiales. Para `bash` con bit SUID, la receta es ejecutarlo
con `-p`:

```
bash -p        # mantiene euid heredado del SUID → shell con privilegios del dueño
```

Un shell normalmente **descarta** el euid elevado al arrancar (medida de seguridad).
`-p` ("privileged mode") desactiva ese descarte, así que si el binario es SUID-root,
quedás con `euid=0`. El binario del lab (`/usr/local/bin/system-check`) es una copia
de bash renombrada: su tamaño (1.412.096 bytes) coincide con el de bash, y el prompt
resultante (`system-check-5.2#`) confirma que es bash 5.2.

---

## 4. Segmentación de red y pivoting

El host víctima tenía **dos interfaces**:

- `eth0` → `172.19.0.3/16` (red externa `labnet`, la que ve el atacante)
- `eth1` → `172.18.0.3/16` (red interna `internalnet`, donde vive `phantomcorp-db`)

La DB solo escucha en la red interna. El atacante, sin ruta a `172.18.0.0/16`, no la
alcanza. El host comprometido sí, porque está conectado a ambas: se convierte en
**pivot**. Es el patrón de las grandes brechas: el equipo comprometido inicialmente
(un web público) es irrelevante; el daño viene de usarlo para saltar a la red interna.

---

## 5. De la automatización al agente (puente al Lab 09)

El `for` de bash y el `recolector.py` hacen lo mismo que haría un operador humano,
pero a velocidad de máquina. La diferencia con un **agente** (Lab 09) no es la
repetición —eso ya lo automatiza el script— sino la **toma de decisiones**: un agente
recibe un objetivo ("encontrá datos sensibles en la red interna") y decide por su
cuenta qué endpoint atacar, qué rango barrer y cómo reconocer un hallazgo. En este lab
esas decisiones las tomamos nosotros y las dejamos escritas en el código; el agente
las deriva del contexto. Entender cómo se encadena y automatiza a mano es requisito
para después dirigir —y auditar— un agente que lo hace solo.

---

## 6. Referencias

- MITRE ATT&CK — Discovery (TA0007), Credential Access (TA0006), Privilege Escalation
  (TA0004), Lateral Movement (TA0008): https://attack.mitre.org/tactics/enterprise/
- GTFOBins — bash: https://gtfobins.github.io/gtfobins/bash/
- MITRE ATT&CK — T1548.001 Setuid and Setgid: https://attack.mitre.org/techniques/T1548/001/
- OWASP — Secrets Management Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- Python docs — urllib.request: https://docs.python.org/3/library/urllib.request.html

> Uso responsable: toda la post-explotación se ejecutó exclusivamente contra los
> contenedores del lab de la cátedra. Fuera de un entorno autorizado, estas técnicas
> constituyen acceso no autorizado y daño informático (Ley 26.388).
