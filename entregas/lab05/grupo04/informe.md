# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 04
**Integrantes:**
- Uriel Olivero — @uRIELoLIVERO
- Jeremias Antunez — @JereAntunez
- Facundo Anil — @FacundoAnil4
- Matias Lelli — @LelliMatias
---

## 0. Declaración de uso de IA

Se utilizó **Claude (Anthropic)** como asistente durante el laboratorio. Su uso fue el siguiente:

- **Ampliación `escaner.py`:** Claude generó la implementación de `parsear_puertos()` y `leer_banner()`. Asistencia en la revisión del desarrollo de las funciones del esqueleto de código. Se verificó leyendo el código y probándolo contra el target PhantomCorp con distintos rangos de puertos y con entradas inválidas (puerto 0, 70000, texto, rango invertido).
- **Guía del laboratorio:** orientación paso a paso para preparar el entorno (WSL2, Docker, conversión de finales de línea CRLF) y para ordenar los comandos de recon.
- **Informe:** Claude ayudó a estructurar el análisis comparativo de servicios y a redactar el borrador de este informe a partir de las salidas de comandos que obtuvimos nosotros.
- **Research:** Claude redactó el borrador de research.md (tema A) a partir de fuentes que buscó y citó. El grupo lo revisó leyéndolo completo y verificando las fuentes.
- **Cómo se verificó:** cada afirmación del mapa se contrastó con la salida de `nmap -sV`, los banners y los headers guardados en `/loot`. El CVE y su puntaje CVSS se cotejaron con la ficha de NVD.

---

## 1. Parte práctica — flags capturadas

jerem@Jere:/mnt/c/Users/jerem/PycharmProjects/LabsSeguridadInformatica2026$ ./ctf status 05

  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 05                      │                                                                                                                                                               
  ╰────────────────────────────────────────────────────────────╯                                                                                                                                                               

   ✓  R1     Puerto oculto en rango alto (barrido completo)
   ✓  R2     Banner grabbing del servicio FTP
   ✓  R3     Fuga de informacion en headers HTTP
   ✓  R4     Enumeracion de rutas via robots.txt
   ✓  R5     Servicio dev expuesto en produccion

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 05 COMPLETO! Ponete las pilas con la próxima unidad.
---

## 2. Mapa de superficie de ataque

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| 21 | FTP | ProFTPD 1.3.5 (`21/tcp open ftp ProFTPD 1.3.5`; banner `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`) | `nmap -sV -p-` y banner grabbing con `ncat` | CVE-2015-3306 (`mod_copy`, comandos `SITE CPFR/CPTO`) | 10.0 (v2) según la cátedra. | **Crítica** | Es el único servicio con un CVE público asociado a su versión exacta. Permite copiar archivos sin autenticación, lo que puede escalar a ejecución remota. Es vulnerable por versión; no se probó que `mod_copy` esté cargado ni se explotó. |
| 80 | HTTP | PhantomServer/2.4.1 (`Server: PhantomServer/2.4.1`, `X-Powered-By: PhantomCMS 2.4.1`) | `nmap -sV`, `curl -I` y `curl /robots.txt` | Ninguno (producto ficticio, no se asigna CVE) | N/A | **Media** | No es explotable por sí mismo, pero filtra producto y versión en los headers, expone un header interno `X-Backend-Flag` y su `robots.txt` revela `/panel-interno-9x2f`, un panel interno accesible sin autenticación. Es el punto de entrada de la cadena de recon. |
| 8080 | HTTP (API de desarrollo) | Werkzeug httpd 2.0.1 (Python 3.9.2) según nmap; `phantom-dev-api` `0.9.3-DEV` según `/status` | `nmap -sV` y `curl :8080/` y `curl :8080/status` | Ninguno verificado | N/A | **Alta** | Servicio de desarrollo en producción: `"version":"0.9.3-DEV"` y `"debug":true`. El modo debug de Werkzeug puede habilitar ejecución de código, pero no verificamos que la consola de depuración sea alcanzable. Se clasifica por el razonamiento, no por un CVE. |
| 31337 | Desconocido (nmap: `Elite?`) | No se pudo determinar producto ni versión. Banner: `PhantomCorp maintenance shell v0.1 -- acceso no autorizado prohibido` | `nmap -sV -p-` y banner grabbing con `ncat` | Ninguno (no hay producto identificado) | N/A | **Alta** | Interfaz de mantenimiento expuesta en un puerto alto. Un puerto no estándar no es seguridad por oscuridad. Solo se leyó el banner, no se interactuó con el servicio, por eso no se puede acotar el impacto real. |

### Evidencia de respaldo

`nmap -Pn -sV -p- phantomcorp` (fragmento):

```
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     ProFTPD 1.3.5
80/tcp    open  http    PhantomServer/2.4.1
8080/tcp  open  http    Werkzeug httpd 2.0.1 (Python 3.9.2)
31337/tcp open  Elite?
Not shown: 65531 closed tcp ports (reset)
```

Banner del puerto 21 (`ncat phantomcorp 21`):

```
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]
```

Headers del puerto 80 (`curl -I phantomcorp`):

```
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: <valor omitido: ver /loot/headers_80.txt>
```

`robots.txt` (`curl -s phantomcorp/robots.txt`):

```
User-agent: *
Disallow: /admin
Disallow: /panel-interno-9x2f
# Recordatorio infra: /panel-interno-9x2f sigue accesible desde afuera. Migrar a VPN.
```

`curl phantomcorp:8080/status`:

```
{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,"flag":"<omitida>"}
```

Archivos completos en la carpeta `evidencia/` de esta entrega: nmap_default.txt, nmap_full.txt, nmap_sV.txt, banner_31337.txt, banner_ftp.txt, headers_80.txt, robots.txt, panel_oculto.txt, admin_status.txt, dev_root.txt y dev_status.txt.
---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**

En nuestro caso, el escaneo default (`nmap -Pn phantomcorp`) **también encontró** el puerto 31337 
como `Elite`, porque nmap lo incluye entre sus 1000 puertos más comunes. Los dos escaneos mostraron 
los mismos 4 puertos. Lo que cambia es la garantía: el default dejó 996 puertos cerrados sin mirar 
los otros ~64.500, mientras que `-p-` revisó los 65535 y confirmó que había 65531 cerrados. Un 
servicio en un puerto alto no común (como el 8081 del ejemplo A del enunciado) sí se perdería con 
el default. La regla operativa es correr siempre `-p-` en un recon, porque si no el "no hay nada más" 
es una suposición y no un hecho. El costo fue chico: 0,14 s contra 0,75 s en el escaneo de puertos, 
aunque `-sV -p-` tardó 88 s.

**P2 — El servicio dev en producción.**

La evidencia está en la respuesta de `/status`: `"version":"0.9.3-DEV"` y `"debug":true`, más un 
mensaje de ayuda en la raíz (`phantom-dev-api. Proba /status`) y un servidor Werkzeug, un servidor 
de desarrollo. Es un problema aunque no tenga un CVE porque expone información interna sin 
autenticación (nombre del servicio, versión, estado de debug) y habilita reconocimiento adicional. 
Con el debug activo, además, puede ofrecer ejecución de código. No verificamos que la consola de 
depuración fuera alcanzable. Además un servicio de desarrollo no pasa por el ciclo de parches ni 
de revisión de seguridad de producción, así que la falta de un CVE no significa que sea seguro.

**P3 — La ironía de `robots.txt`.**

`robots.txt` se creó para indicar a los crawlers de buscadores qué rutas no indexar, es decir, para 
controlar el SEO. Es público y voluntario, no es un control de acceso. Por eso, al listar 
`Disallow: /panel-interno-9x2f`, termina funcionando como un mapa de rutas sensibles para un 
atacante, y el comentario "sigue accesible desde afuera. Migrar a VPN" confirma que el panel está 
expuesto. Entramos a esa ruta con `curl` y respondió sin autenticación. Esto no aplica a todo el 
archivo: `/admin` respondió **404**, así que `robots.txt` mezcla una ruta inexistente con una real. 
El comentario HTML del index (`TODO(infra): sacar el panel interno de produccion`) filtra lo mismo 
por otro lado.

**P4 — Pasivo vs. activo.**

Recon pasivo es reunir información sin interactuar con el objetivo (por ejemplo `whois` o `dig` 
sobre un dominio público, certificados, buscadores). Recon activo es interactuar con él. Todo lo 
que hicimos contra `phantomcorp` fue **activo**: `nmap` (miles de intentos de conexión), `ncat` 
a los puertos 21 y 31337, y `curl` a los puertos 80 y 8080. Nada de eso es pasivo. En un servidor 
real con logging habrían quedado registradas las conexiones del escaneo (muchos SYN a puertos cerrados 
desde la misma IP, muy llamativo para un IDS) y las peticiones HTTP, incluyendo `/robots.txt`, 
`/panel-interno-9x2f`, `/admin` y `/status`. El `nmap -sV` es especialmente ruidoso por los 
sondeos que envía a cada puerto.

**P5 — Ahora sos el defensor.**

1. **Puerto 21 (ProFTPD 1.3.5).** Actualizar a una versión soportada que corrija CVE-2015-3306 o 
2. deshabilitar `mod_copy` si no se usa. Además, restringir el acceso por firewall a las IP que lo 
3. necesiten, y evaluar reemplazar FTP por SFTP. Esto elimina el hallazgo más crítico del mapa.
2. **Puerto 8080 (API de desarrollo).** Retirar el servicio de desarrollo de producción, o como 
3. mínimo desactivar `debug`, ponerlo detrás de autenticación y limitarlo a la red interna o 
4. a `localhost`. Hay que quitar también el endpoint `/status` o evitar que devuelva datos internos.

Medidas complementarias para otros hallazgos: mover `/panel-interno-9x2f` detrás de VPN (como ya 
dice el propio comentario del `robots.txt`), eliminar los headers `X-Powered-By` y `X-Backend-Flag`, 
y cerrar o filtrar el puerto 31337.

---

## 4. Bitácora de comandos

```bash
# Desde la raíz del repo
make setup
./ctf lab 05
make shell

# Dentro de la consola del atacante
ping -c1 phantomcorp
nmap -Pn phantomcorp | tee /loot/nmap_default.txt
nmap -Pn -p- phantomcorp | tee /loot/nmap_full.txt
nmap -Pn -sV -p- phantomcorp | tee /loot/nmap_sV.txt
ncat -w2 phantomcorp 31337 </dev/null | tee /loot/banner_31337.txt
ncat -w2 phantomcorp 21 </dev/null | tee /loot/banner_ftp.txt
curl -I phantomcorp | tee /loot/headers_80.txt
curl -s phantomcorp/robots.txt | tee /loot/robots.txt
curl -s phantomcorp/panel-interno-9x2f | tee /loot/panel_oculto.txt
curl -s -o /dev/null -w "%{http_code}\n" phantomcorp/admin     # 404
curl -s phantomcorp:8080/ | tee /loot/dev_root.txt
curl -s phantomcorp:8080/status | tee /loot/dev_status.txt

# Entrega de flags (desde la raíz del repo, fuera de la consola)
./ctf submit 05 R1 'FLAG{...}'
./ctf submit 05 R2 'FLAG{...}'
./ctf submit 05 R3 'FLAG{...}'
./ctf submit 05 R4 'FLAG{...}'
./ctf submit 05 R5 'FLAG{...}'
./ctf status 05
```

---

## 5. Conclusión

El reconocimiento activo de PhantomCorp expuso cuatro servicios y mostró que lo grave no está en 
un solo punto, sino en la suma de pequeñas fugas de información. El hallazgo más crítico es 
el **puerto 21**: ProFTPD 1.3.5 es vulnerable por versión a CVE-2015-3306, no requiere credenciales 
y tiene exploit público. Le siguen el **servicio de desarrollo del 8080** (debug activo en producción) 
y la **interfaz de mantenimiento del 31337**, ambos de riesgo alto por diseño, aunque ninguno tenga un 
CVE verificado. El **puerto 80** es de riesgo medio por sí mismo, pero funciona como la puerta de 
entrada del recon: sus headers y su `robots.txt` llevaron directamente a un panel interno sin autenticación.

Aprendimos que identificar y clasificar vale más que listar puertos: el mismo `nmap` que mostró cuatro 
puertos abiertos solo se volvió un hallazgo cuando le sumamos versión, banner y evidencia. También 
aprendimos a distinguir lo probado de lo inferido: no explotamos nada y dejamos explícito qué quedó 
sin verificar (la carga de `mod_copy`, la consola de debug del 8080 y la función del servicio del 31337). 
La prioridad para la defensa es actualizar o cerrar el FTP, retirar el servicio de desarrollo de 
producción y dejar de publicar información interna en headers y `robots.txt`.

