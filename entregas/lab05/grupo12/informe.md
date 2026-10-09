# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la estructuración del informe, documentación técnica del procedimiento de captura de flags y verificación de salidas de comandos.
- **Partes originadas o modificadas:** Sección 1 (Parte práctica — flags capturadas).
- **Verificación humana:** Se validó cada una de las 5 flags capturadas contra el entorno de PhantomCorp y los hashes oficiales en `retos.manifest`, contrastando las respuestas de los servicios en los puertos 21, 80, 8080 y 31337.

---

## 1. Parte práctica — flags capturadas

Salida de `./ctf status 05`:

```text
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
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|
| **R1** | Barrido completo de puertos (`-p-`) | `ncat -w2 phantomcorp 31337 </dev/null` | `FLAG{high_port_secret_service}` |
| **R2** | Banner grabbing FTP | `ncat phantomcorp 21` | `FLAG{banner_grab_proftpd_135}` |
| **R3** | Análisis de headers HTTP (`-I`) | `curl -sI http://phantomcorp/` | `FLAG{http_headers_leak_info}` |
| **R4** | Enumeración de rutas (`robots.txt`) | `curl -s http://phantomcorp/panel-interno-9x2f` | `FLAG{recon_hidden_path}` |
| **R5** | Servicio dev expuesto | `curl -s http://phantomcorp:8080/status` | `FLAG{dev_service_exposed}` |

---

## 2. Mapa de superficie de ataque *(Pendiente)*

*(A incorporar en el siguiente commit)*

---

## 3. Preguntas de análisis *(Pendiente — a completar por el equipo)*

**P1 — El puerto que el escaneo default se perdió.**
*(A completar por el equipo)*

**P2 — El servicio dev en producción.**
*(A completar por el equipo)*

**P3 — La ironía de `robots.txt`.**
*(A completar por el equipo)*

**P4 — Pasivo vs. activo.**
*(A completar por el equipo)*

**P5 — Ahora sos el defensor.**
*(A completar por el equipo)*

---

## 4. Bitácora de comandos *(Pendiente — a completar por el equipo)*

```bash
# A completar por el equipo
```
