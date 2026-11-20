# Entregable — Lab Extra: SSRF

**Grupo:** 14 · **Integrantes:** Peron, Fede (@fedeeperon) · Gomez Redondo, Laureano (@Laureano-GR) · Cesano, Martín (@martincesano) · Gaido, Martín (@martingaidoo) · Chiapero, Valentina (@valechiapero)

**Declaración de uso de IA:** Usamos IA para redactar el informe y las respuestas
P1–P5. El levantado del entorno (`make lab N=extra`), la explotación del SSRF
desde la consola atacante y la verificación con `./ctf submit` los hicimos nosotros.

---

## 1. Hallazgos

Entorno: `phantomcorp` (web pública, en `labnet` + `internalnet`) expone
`/preview?url=` que **fetchea cualquier URL desde el servidor**;
`phantomcorp-intra` vive **solo** en `internalnet`. La consola atacante está en
`labnet`: no alcanza la intranet directamente (ver
`evidencia/salidas/00-acceso-directo-falla.txt`). El SSRF es el puente.

### R1 — Panel interno en localhost → `FLAG{ssrf_localhost_panel_interno}`
`/preview?url=http://127.0.0.1:9000/`: el panel admin escucha solo en localhost
del server público; al pedírselo al propio server, nos lo devuelve con la
"Deploy key".

### R2 — Descubrir la intranet → `FLAG{ssrf_intranet_descubierta}`
`/preview?url=http://phantomcorp-intra/`: el server resuelve el nombre en
`internalnet` y trae la home de la intranet, inalcanzable para nosotros directamente.

### R3 — Exfiltrar backup de clientes → `FLAG{ssrf_backup_clientes}`
`/preview?url=http://phantomcorp-intra/backups/clientes.json`: trae un backup
con CUIT de clientes reales y el claim de integridad (la flag).

## 2. Las flags

`./ctf status extra` → R1, R2, R3 en ✓ (3/3, 100%). Ver `evidencia/salidas/ctf-status.txt`.

## 3. Preguntas P1–P5

- **P1.** La intranet está en `internalnet` (red `internal: true`), aislada de
  `labnet` donde está el atacante → "no alcanzable desde afuera". Pero
  `phantomcorp` está en **ambas** redes y acepta fetchear URLs arbitrarias: se
  convierte en **proxy confuso** (confused deputy). El componente que la hizo
  alcanzable es `/preview` (el SSRF): usa la pata del server en `internalnet`
  para traernos lo que nosotros no podemos pedir.
- **P2.** Puerto cerrado (`127.0.0.1:9999`) → `502` con
  `Connection refused`; puerto abierto (`:9000`) → `200` con el contenido. Esa
  diferencia de respuesta es un **oráculo de escaneo de puertos**: variando el
  puerto y mirando error-vs-contenido, mapeamos qué servicios internos están
  vivos, sin tocarlos directamente. (Ver `P2-oraculo-puertos.txt`.)
- **P3.** *Hallazgo:* **Exposición de datos de clientes vía SSRF.**
  - *Activo afectado:* backup `clientes.json` de la intranet (CUIT y razón
    social de clientes: Aconcagua SRL, Comechingones SA).
  - *Vector:* SSRF en `GET /preview?url=` del portal público → acceso a
    `http://phantomcorp-intra/backups/clientes.json`.
  - *Impacto:* fuga de datos personales/comerciales (CUIT) a través del
    perímetro; posible incumplimiento de protección de datos.
  - *Evidencia:* `evidencia/salidas/R3-backup-clientes.txt`.
- **P4.** Mitigaciones para `/preview`, de mejor a peor:
  1. **Allowlist de destinos** (solo dominios/hosts explícitamente permitidos).
     La más robusta; limitación: hay que mantener la lista y puede ser
     restrictiva para el caso de uso real.
  2. **Resolver el DNS y validar la IP resultante** contra rangos privados/
     loopback/link-local (127/8, 10/8, 172.16/12, 192.168/16, 169.254/16) y
     **re-chequear tras redirecciones**. Limitación: cuidado con
     **rebinding DNS** (el nombre resuelve distinto entre validación y fetch) y
     con formatos raros de IP.
  3. **Blocklist de strings** (`localhost`, `127.0.0.1`). La peor: se evade
     trivialmente con `http://2130706433:9000/` (IP decimal, lo probamos en
     `P4-bypass-ip-decimal.txt`), `http://[::1]/`, `0177.0.0.1`, o un dominio
     que resuelve a 127.0.0.1. Filtrar texto no sirve: hay que validar la IP real.
     Complemento: aislar el fetcher sin acceso a redes internas y sin seguir redirects.
- **P5.** `169.254.169.254` es el **metadata service** de las nubes (AWS/GCP/
  Azure): un endpoint interno que entrega metadatos de la instancia, incluidas
  **credenciales temporales de rol IAM**. Un SSRF en una app cloud que llegue a
  esa IP permite robar esas credenciales y pivotar a toda la cuenta cloud
  (S3, bases, etc.) — mucho más grave que leer una intranet. Por eso IMDSv2
  (token obligatorio) existe. En este lab el impacto se limita a la red interna;
  en cloud, el SSRF escala a compromiso de la cuenta.

## 4. Conclusión

La segmentación de red no alcanza si un servicio con una pata en la red interna
acepta fetchear URLs arbitrarias: se vuelve el ariete del atacante. La defensa
real es validar el **destino resuelto** (allowlist / IP privadas), no filtrar strings.
