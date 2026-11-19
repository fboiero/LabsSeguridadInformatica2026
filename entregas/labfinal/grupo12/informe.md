# Informe de Penetration Test — PhantomCorp "Clientes"

**Cliente:** PhantomCorp S.A.  ·  **Auditor (grupo):** Grupo 12  
**Integrantes:**
- Gerbaudo, Mateo (Legajo: 14157) — `@gerbaudo19`
- Mariatti, Matias (Legajo: 13293) — `@matiasmariatticasc`
- Colque Condo, Luis Alvaro (Legajo: 14994) — `@ColqueAlvaro`
- Rodriguez, Gonzalo (Legajo: 15310) — `@Gonza149`

**Fecha:** 19 de Noviembre de 2026  ·  **Tipo:** Caja negra (Black Box)  ·  **Alcance:** host `phantomcorp` (Red interna del laboratorio)

---

## 0. Declaración de uso de IA

* **¿Usaron herramientas de IA generativa (ChatGPT, Claude, Gemini, Copilot, etc.)?** Sí.
* **¿Cuáles y con qué propósito?** Se utilizó **Google Antigravity** como asistente de redacción y pair-programming para la estructuración Markdown del informe pericial y la formulación del resumen ejecutivo directivo.
* **¿Qué partes del trabajo fueron generadas o modificadas por IA?** Plantillas iniciales de tablas Markdown y asistencia de estilo para comunicación ejecutiva; los hallazgos técnicos, análisis de riesgo y verificaciones de flags fueron auditados y realizados por el equipo.
* **¿Cómo validaron que el código generado sea correcto y seguro?** Comprobación directa sobre el contenedor del lab, verificación de la flag de reconocimiento en el HTML y cálculo de vectores CVSS v3.1 conforme al estándar First.org.

---

## 1. Resumen ejecutivo

Durante el mes de noviembre de 2026, el equipo de auditoría del **Grupo 12** inició una evaluación de seguridad ofensiva de tipo **Caja Negra (Black Box)** sobre la plataforma web **"Clientes"** de **PhantomCorp S.A.** El objetivo pericial es determinar la postura de seguridad del activo frente a amenazas externas no autenticadas, evaluar la eficacia de los controles perimetrales y medir el impacto real sobre la confidencialidad de la información corporativa.

### Resultado global
Partiendo de una posición externa sin credenciales previas ni conocimiento de la topología interna, el equipo logró identificar la superficie expuesta no enlazada del portal interno de Recursos Humanos a través del archivo de directivas de indexación, sentando las bases del compromiso inicial del sistema.

### Riesgo de negocio
El sistema aloja activos de altísima confidencialidad correspondientes a la cartera de clientes de PhantomCorp S.A. Una intrusión exitosa sobre el servicio expone a la organización a:
1. **Sanciones regulatorias severas:** Incumplimiento crítico de la **Ley Nacional de Protección de Datos Personales (Ley 25.326)** ante la filtración de registros con DNI y datos identificatorios.
2. **Incumplimiento de estándares de la industria:** Riesgo de no conformidad con **PCI-DSS** si la información de tarjetas de crédito no cuenta con cifrado robusto en reposo y en tránsito.
3. **Pérdida de reputación comercial:** Daño a la marca corporativa y pérdida de confianza por parte de los clientes.

### Recomendación prioritaria
Restringir el acceso público a paneles administrativos y de soporte mediante listas de control de acceso (ACLs) o VPN corporativa, y no confiar en directivas como `robots.txt` para mantener ocultos recursos sensibles del negocio.

### Matriz de hallazgos identificados

| Severidad | Cantidad de hallazgos | Estado / Asignación |
|---|:---:|---|
| **Crítica** | 1 | H-01: Inyección de Comandos RCE en API (A cargo de Gonzalo Rodriguez) |
| **Alta** | 2 | H-02: SQLi en Formulario de Login (A cargo de Matías Mariatti)<br>H-03: Exposición de Backups y Tokens (A cargo de Luis Alvaro Colque) |
| **Media** | 1 | H-04: Divulgación de Rutas en `robots.txt` (A cargo de Mateo Gerbaudo) |
| **Baja** | 0 | — |
| **Total** | **4** | **Auditoría en proceso coordinado por el Grupo 12** |

---

<!-- ========================================================================= -->
<!-- SECCIÓN 2: ALCANCE Y METODOLOGÍA (A redactar por Matías Mariatti)         -->
<!-- ========================================================================= -->
## 2. Alcance y metodología
*(Sección asignada a Matías Mariatti — Grupo 12)*

---

<!-- ========================================================================= -->
<!-- SECCIÓN 3: NARRATIVA DEL ATAQUE (A redactar por Luis Alvaro Colque)        -->
<!-- ========================================================================= -->
## 3. Narrativa del ataque
*(Sección asignada a Luis Alvaro Colque — Grupo 12)*

---

## 4. Hallazgos (detalle técnico)

<!-- ========================================================================= -->
<!-- H-01 (CRÍTICA): Inyección de Comandos RCE (A redactar por Gonzalo Rodriguez) -->
<!-- ========================================================================= -->
### H-01 · Inyección de Comandos del Sistema Operativo (RCE) en API de Reportes
*(Hallazgo técnico asignado a Gonzalo Rodriguez — Grupo 12)*

---

<!-- ========================================================================= -->
<!-- H-02 (ALTA): Inyección SQL en Login de RRHH (A redactar por Matías Mariatti)-->
<!-- ========================================================================= -->
### H-02 · Inyección SQL (SQLi) en Formulario de Autenticación de RRHH
*(Hallazgo técnico asignado a Matías Mariatti — Grupo 12)*

---

<!-- ========================================================================= -->
<!-- H-03 (ALTA): Exposición de Backups (A redactar por Luis Alvaro Colque)     -->
<!-- ========================================================================= -->
### H-03 · Exposición Pública de Archivos de Respaldo y Fuga de Token de API
*(Hallazgo técnico asignado a Luis Alvaro Colque — Grupo 12)*

---

<!-- ========================================================================= -->
<!-- H-04 (MEDIA): Divulgación en robots.txt (A cargo de Mateo Gerbaudo)        -->
<!-- ========================================================================= -->
### H-04 · Divulgación de Rutas Críticas en `robots.txt` y Metadatos en Comentarios HTML
- **Auditor responsable:** Mateo Gerbaudo (`@gerbaudo19`)
- **Severidad:** **Media**  
- **CVSS v3.1:** `5.3` (Media) · **Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`  
  *Justificación del score:* Vector de red (AV:N), complejidad baja (AC:L), sin privilegios requeridos (PR:N), sin interacción de usuario (UI:N), sin cambio de alcance (S:U), impacto bajo en confidencialidad (C:L) por descubrimiento pasivo de la superficie administrativa, sin impacto directo en integridad ni disponibilidad.
- **CWE:** CWE-200: *Exposure of Sensitive Information to an Unauthorized Actor* y CWE-548: *Exposure of Information Through Directory Listing*.
- **Ubicación:** Recursos `GET /robots.txt` y `GET /portal-rrhh`.
- **Descripción:**  
  El archivo estándar de directivas para motores de búsqueda (`robots.txt`) contiene una regla que expone de forma explícita la ruta administrativa no enlazada del portal de Recursos Humanos (`Disallow: /portal-rrhh`). Asimismo, el código fuente HTML del portal incluye comentarios dejados durante el desarrollo que confirman la naturaleza del panel interno y revelan la primera bandera del compromiso (`FLAG{final_recon_portal}`).
- **Evidencia reproducible:**  
  1. Consulta del archivo `robots.txt`:
     ```bash
     curl -s http://phantomcorp/robots.txt
     ```
     *Salida obtenida:*
     ```text
     User-agent: *
     Disallow: /portal-rrhh
     ```
  2. Consulta del recurso `/portal-rrhh` extrayendo el comentario HTML:
     ```bash
     curl -s http://phantomcorp/portal-rrhh | grep "<!--"
     ```
     *Salida obtenida:*
     ```html
     <!-- recon: portal interno localizado. FLAG{final_recon_portal} -->
     ```
- **Impacto:**  
  Permite a cualquier atacante externo realizar un reconocimiento pasivo trivial, localizando de inmediato la interfaz de autenticación administrativa sin generar tráfico anómalo ni activar sistemas de detección de intrusiones (IDS/IPS).
- **Remediación:**  
  1. **Eliminar rutas privadas de `robots.txt`:** No utilizar `robots.txt` como mecanismo de control de acceso ni de seguridad por oscuridad.
  2. **Controles de acceso a nivel perimetral:** Proteger el acceso a `/portal-rrhh` mediante listas de control de acceso (ACLs) basadas en IP o exigir conexión a través de la VPN interna de PhantomCorp.
  3. **Depuración de metadatos:** Implementar en el pipeline de despliegue una etapa de sanitización que remueva automáticamente los comentarios HTML de depuración en entornos productivos.

---

<!-- ========================================================================= -->
<!-- SECCIÓN 5: CONCLUSIÓN Y POSTURA (A redactar por Gonzalo Rodriguez)        -->
<!-- ========================================================================= -->
## 5. Conclusión y postura de seguridad
*(Sección asignada a Gonzalo Rodriguez — Grupo 12)*

---

<!-- ========================================================================= -->
<!-- SECCIÓN 6: ANEXO Y STATUS DEL CTF (A completar por Gonzalo Rodriguez)      -->
<!-- ========================================================================= -->
## 6. Anexo
*(Sección asignada a Gonzalo Rodriguez — Grupo 12)*
