# Mini-research — Laboratorio 08

**Tema elegido:** **B — Pivoting y túneles**: cómo se pivotea de verdad (SSH tunneling, chisel, proxychains), más allá de un simple `curl`.

## Desarrollo

En el lab, el pivot fue un `curl` desde la víctima al host interno: alcanza para
probar conectividad (R4), pero no da un canal reutilizable para correr otras
herramientas contra el segmento interno. En un engagement real se arma un **túnel**.

- **SSH port forwarding.** Con una sesión SSH hacia el host pivote se crean tres
  tipos de reenvío: **local** (`ssh -L 1521:phantomcorp-db:80 user@pivote`) expone
  un servicio interno en un puerto del atacante; **remoto** (`-R`) hace lo inverso,
  útil cuando el pivote no puede iniciar conexiones salientes hacia el atacante;
  y **dinámico** (`-D 1080`) levanta un **proxy SOCKS** por el que puede salir
  cualquier herramienta, sin abrir un forward por puerto. Es el método "nativo"
  cuando hay SSH y credenciales/clave.
- **chisel.** Cuando no hay SSH, `chisel` arma un túnel TCP/UDP sobre HTTP
  (servidor en el atacante, cliente en el pivote, o al revés), con un modo SOCKS
  (`chisel server --reverse` + `chisel client R:socks`). Sirve para atravesar
  NAT/firewalls que solo dejan pasar HTTP y para reverse tunnels cuando el interno
  no es alcanzable directamente.
- **proxychains.** No crea el túnel: **encamina** las herramientas existentes
  (`proxychains nmap ...`, `proxychains curl ...`) a través de un proxy SOCKS ya
  montado (el de `ssh -D` o el de chisel). Así se corre recon/explotación contra
  el segmento interno sin que la herramienta sepa del túnel.

El patrón típico es encadenar: SSH/chisel levanta un SOCKS en el pivote;
proxychains manda nmap y lo que haga falta por ese SOCKS; recién ahí el host
interno queda "a tiro" como si fuera local.

## Fuentes (mín. 3, verificables)

1. OpenSSH — manual de `ssh(1)`, opciones `-L`, `-R`, `-D` (port forwarding): https://man.openbsd.org/ssh
2. `chisel` — túnel TCP/UDP sobre HTTP con modo SOCKS (repositorio oficial): https://github.com/jpillora/chisel
3. `proxychains-ng` — encaminar conexiones de programas a través de proxies SOCKS/HTTP: https://github.com/rofl0r/proxychains-ng

## Reflexión (3–5 líneas)

Un `curl` prueba que el pivot existe, pero no es operación: para auditar el
segmento interno hace falta un canal estable. SSH dinámico es lo más limpio
cuando está disponible; chisel cubre los casos sin SSH o con solo HTTP saliente;
proxychains reusa las herramientas de siempre sobre ese canal. La defensa es la
otra cara: si el host de la frontera no pudiera abrir conexiones arbitrarias al
interno, ninguno de estos túneles prendería. El control está en la segmentación y
el egress, no en esconder la IP del host interno.
