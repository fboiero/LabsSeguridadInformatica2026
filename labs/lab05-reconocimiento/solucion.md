# Solución — Laboratorio 05 (SOLO DOCENTE)

> **No compartir con alumnos.** Esta guía es para corrección y para asistir en
> consulta. Las flags van ofuscadas en `server.py` y verificadas por hash en
> `retos.manifest`; acá están en claro con el camino para obtenerlas.

## Levantar el entorno

```bash
make setup           # una vez
make lab N=05        # atacante + phantomcorp
make shell           # entrar a la consola
```

## Flags y cómo se obtienen

| Reto | Flag | Comando (desde la consola atacante) |
|---|---|---|
| R1 | `FLAG{high_port_secret_service}` | `nmap -Pn -p- phantomcorp` revela `31337`; luego `ncat phantomcorp 31337` |
| R2 | `FLAG{banner_grab_proftpd_135}` | `ncat phantomcorp 21` (el banner llega solo) |
| R3 | `FLAG{http_headers_leak_info}` | `curl -I phantomcorp` → header `X-Backend-Flag` |
| R4 | `FLAG{recon_hidden_path}` | `curl -s phantomcorp/robots.txt` → ruta `/panel-interno-9x2f` → `curl -s phantomcorp/panel-interno-9x2f` |
| R5 | `FLAG{dev_service_exposed}` | `curl -s phantomcorp:8080/status` |

Entrega: `./ctf submit 05 R1 'FLAG{...}'`

## Salida esperada de nmap

```
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
8080/tcp  open  http-proxy
31337/tcp open  Elite
```

Con `-sV`, el 21 identifica `ProFTPD 1.3.5`, el 80 `PhantomServer 2.4.1`.

## Clave de clasificación (mapa de superficie)

| Puerto | Producto/versión | Clasificación esperada |
|---|---|---|
| 21 | ProFTPD 1.3.5 | **Crítico.** CVE-2015-3306 (`mod_copy`, `SITE CPFR/CPTO`) → lectura/escritura arbitraria y RCE. CVSS v2 10.0. El banner de versión basta para determinarlo. |
| 80 | PhantomServer 2.4.1 (ficticio) | Bajo por sí mismo, pero **filtra** vía headers y `robots.txt`. Se evalúa que detecten el info leak, no un CVE. |
| 8080 | phantom-dev-api (Werkzeug 2.0.1) | **Alto.** Servicio de desarrollo en producción con `debug:true`. Werkzeug con debugger habilitado → RCE por la consola de depuración. Se evalúa el razonamiento, no un CVE puntual. |
| 31337 | "maintenance shell" en puerto no estándar | **Alto por diseño.** Servicio de administración expuesto en puerto alto = clásico backdoor/olvido. Se evalúa que noten que un puerto alto no lo hace "seguro por oscuridad". |

## Errores típicos a mirar en la corrección

- Marcar todo "crítico" sin fundamentar → penalizar como en la matriz CIA del lab01.
- Confundir `SERVICE` (adivine de nmap) con `VERSION` (evidencia real).
- No correr `-p-` y perderse el 31337 → oportunidad para P1.
- Inventar un CVE para el 80 o el 8080 → rechazo del componente.
