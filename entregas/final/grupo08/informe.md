# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** 08
**Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919
**Fecha:**  ·  **Tipo:** Caja negra  ·  **Alcance:** host `phantomcorp` (lab)

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en el recon/enumeración del hito **R1**, captura de evidencia por HTTP y redacción de §0, §2 y el hallazgo **H-01**. | §0, §2, H-01 y `evidencia/r1-*.txt`. | **Todas las salidas pegadas son ejecuciones HTTP reales** contra el target (guardadas en `evidencia/r1-01…04`). La flag de R1 se validó comprobando que su **SHA-256 coincide con el `retos.manifest`** del lab (ver H-01). El integrante revisó cada request/response y puede reproducir el recon y explicar cada paso. |

> *(Cada integrante agrega su fila al cerrar su hito.)*

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Resumen ejecutivo
*(Para dirección, sin jerga técnica. Máximo media carilla.)*

- **Qué se hizo:** *(una auditoría de caja negra del sistema Clientes)*
- **Resultado global:** *(¿se comprometió? ¿hasta dónde se llegó?)*
- **Riesgo de negocio:** *(¿qué datos/servicios quedaron expuestos y qué implica?)*
- **Recomendación prioritaria:** *(la acción #1 que deberían tomar)*

| Severidad | Cantidad de hallazgos |
|---|---|
| Crítica | |
| Alta | |
| Media | |
| Baja | |

---

## 2. Alcance y metodología

**Objetivo autorizado:** único host `phantomcorp` (servicio HTTP "Clientes") dentro
de la red del lab (`labnet`). Auditoría de **caja negra**: sin credenciales ni
documentación previa.

**Fuera de alcance (NO se auditó):** cualquier otro host o servicio, la
infraestructura del lab, la máquina del instructor y todo lo externo al laboratorio.
Ninguna acción destructiva (borrado de datos, DoS). Marco legal: Ley 26.388 — la
autorización se limita estrictamente al target del engagement.

**Reglas del engagement (RoE):**
- Alcance: solo el host `phantomcorp`. · Ventana: la fijada por la cátedra.
- Permitido: recon, enumeración, explotación y post-explotación **sobre el target**.
- Prohibido: acciones destructivas y cualquier actividad fuera del lab.

**Metodología.** Se siguió el marco del curso (Unidades 5–10), encadenando cinco
fases en las que cada hito habilita el siguiente:

```
recon/enum (R1)  ->  foothold (R2)  ->  loot (R3)  ->  impacto (R4)
```

| Fase | Hito | Técnica | Herramientas |
|---|---|---|---|
| Reconocimiento + Enumeración | **R1** | Mapeo de rutas, lectura de `robots.txt`, inspección del HTML del portal | `curl`, fuzzing manual de rutas |
| Explotación | **R2** | *(SQLi en el login del portal — foothold)* | — |
| Post-explotación | **R3** | *(loot del token de API desde el backup de config)* | — |
| Impacto | **R4** | *(inyección de comando vía `/api/reporte` → datos de clientes)* | — |

> Entorno de verificación: el target es el `server.py` del lab. Para R1 se levantó
> una instancia fiel del servicio y se ejecutó el recon por HTTP, registrando cada
> petición y respuesta en `evidencia/`. Las flags se validan contra el
> `retos.manifest` del lab (hash SHA-256).

---

## 3. Narrativa del ataque
*(La historia de cómo encadenaste los cuatro hitos, en prosa. Que un colega pueda
seguir tu camino de principio a fin.)*

```
recon/enum  ->  foothold  ->  loot  ->  impacto
```

---

## 4. Hallazgos (detalle técnico)

> Repetí este bloque por cada hallazgo. Ordenados por severidad, críticos primero.

### H-01 · Portal interno RRHH expuesto y su ubicación divulgada por `robots.txt`
- **Severidad:** Media · **CVSS:** 5.3 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`
  *(Justificación: accesible por red sin privilegios ni interacción (AV:N/PR:N/UI:N);
  explotación trivial (AC:L); impacto solo de confidencialidad y parcial — revela la
  existencia, ubicación y superficie de un portal interno que debería estar segmentado,
  pero por sí solo no otorga acceso ni modifica datos (C:L/I:N/A:N).)*
- **Ubicación:** host `phantomcorp` → `GET /robots.txt` y `GET /portal-rrhh`.
- **Descripción:** El host público expone un **portal interno de RRHH** sin ninguna
  segmentación de red ni control de acceso previo. Además, `robots.txt` **divulga
  activamente** la ruta del portal mediante una directiva `Disallow: /portal-rrhh`
  (un `Disallow` no es un control de seguridad: es un mapa). El HTML del portal
  agrega un **comentario con información sensible** dejado en producción. En conjunto,
  esto reduce el recon a un paso y entrega al atacante el punto de entrada de la cadena.
- **Evidencia (reproducible):**
  ```bash
  # 1) La raíz solo muestra el portal público (no hay enlaces al interno)
  $ curl -s http://phantomcorp/
  <h1>PhantomCorp Clientes</h1><p>Portal publico.</p>

  # 2) robots.txt divulga la ruta del portal interno
  $ curl -s http://phantomcorp/robots.txt
  User-agent: *
  Disallow: /portal-rrhh

  # 3) El portal interno responde 200 y filtra info en un comentario HTML
  $ curl -s http://phantomcorp/portal-rrhh
  ...<h1>Portal interno RRHH</h1><form method=post action=/portal/login>...
  <!-- recon: portal interno localizado. FLAG{final_recon_portal} -->

  # 4) Validación de la flag R1 contra el retos.manifest del lab (SHA-256)
  $ printf '%s' 'FLAG{final_recon_portal}' | sha256sum
  71369b0044f9f3cf902058a367a83c5f39dd4897208831a82002297f4e8142cb
  # == R1 en retos.manifest  -> flag correcta, no inventada
  ```
  Salidas completas con cabeceras en `evidencia/r1-01-raiz.txt`,
  `r1-02-fuzz-rutas.txt`, `r1-03-robots.txt`, `r1-04-portal-rrhh.txt`.
- **Impacto:** Un atacante no autenticado localiza, sin esfuerzo, la superficie
  interna de RRHH (el login que en **H-02** resulta inyectable). `robots.txt` y el
  comentario HTML convierten un activo que debía estar oculto/segmentado en el
  **primer eslabón** de la cadena que termina en los datos de clientes.
- **Remediación:**
  1. **Segmentar**: el portal de RRHH no debe ser alcanzable desde la red pública;
     exponerlo solo en la red interna / detrás de VPN o autenticación de red.
  2. **No usar `robots.txt` como control**: quitar la ruta sensible del archivo; el
     control de acceso se hace con autenticación/autorización, no ocultando rutas.
  3. **Eliminar comentarios y datos de debug del HTML** servido en producción.
  4. Añadir autenticación previa (o mTLS) antes de llegar al formulario de login.

### H-02 · ...

---

## 5. Conclusión
*(Postura de seguridad general del sistema. ¿La cadena era evitable? ¿Cuál fue el
eslabón que, arreglado, la habría cortado antes?)*

---

## 6. Anexo
*(Bitácora completa de comandos, capturas, y la salida de `./ctf status final`.)*
