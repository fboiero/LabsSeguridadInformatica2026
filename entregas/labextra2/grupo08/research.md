# Research — Lab Extra 2: El repo que delata

**Grupo:** 08 · **Autor (Parte 2):** Joaquin Moyano (@Joaco919)  
**Declaración de uso de IA:** se utilizó Claude Code (Anthropic) como asistente de investigación técnica, estructuración comparativa y redacción. El análisis comparativo, las evaluaciones operativas y las fuentes citadas fueron verificadas y validadas por el autor.

---

## Opción A — Herramientas reales del ecosistema de secretos en Git

La gestión de secretos en sistemas de control de versiones distribuidos requiere abordar dos problemas técnicamente disjuntos: la **detección** (evitar que ingresen o identificarlos tempranamente) y la **limpieza / remediación histórica** (expurgar objetos del grafo de Git).

```
                  ┌─────────────────────────────────────────────────────────┐
                  │                 CICLO DE VIDA DEL DATO                  │
                  └─────────────────────────────────────────────────────────┘
                                               │
            [Pre-commit / CI]                  │            [Post-incidente]
                   ▼                           │                   ▼
        ┌─────────────────────┐                │        ┌─────────────────────┐
        │      DETECCIÓN      │                │        │      LIMPIEZA       │
        ├─────────────────────┤                │        ├─────────────────────┤
        │ • Gitleaks          │                │        │ • git-filter-repo   │
        │ • TruffleHog        │                │        │ • BFG Repo-Cleaner  │
        └─────────────────────┘                │        └─────────────────────┘
```

---

### 1. Herramientas de Detección

#### A. Gitleaks
- **Qué busca y cómo funciona:**
  Gitleaks es un analizador SAST ligero escrito en Go. Evalúa archivos y commits buscando secretos mediante reglas basadas en expresiones regulares (regex) combinadas con **análisis de entropía de Shannon** para discriminar cadenas pseudoaleatorias de texto común. Permite escanear el working tree, commits individuales o todo el árbol histórico.
- **Implementación en un pipeline de CI:**
  Se integra como un step en GitHub Actions o GitLab CI ejecutándose sobre cada pull request. Para optimizar el tiempo de ejecución en repositorios grandes, se utiliza el modo incremental analizando únicamente el rango de commits introducido en la rama (`git diff ${GITHUB_BASE_REF}...${GITHUB_SHA}`):
  ```yaml
  - name: Run Gitleaks
    uses: gitleaks/gitleaks-action@v2
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  ```
- **Qué NO resuelve:**
  1. *Falsos positivos/negativos:* Secretos con baja entropía (ej. contraseñas comunes como `admin123`) o formatos desconocidos son omitidos.
  2. *Verificación de vigencia:* Gitleaks es un analizador puramente sintáctico; no sabe si la clave encontrada está activa, expirada o si corresponde a un mock de pruebas.
  3. *Inmutabilidad de Git:* Detectar el secreto en CI ocurre *después* de que el commit fue creado y pusheado al servidor; no impide que el secreto ya resida en el historial remoto mientras el pipeline corre.

#### B. TruffleHog (v3)
- **Qué busca y cómo funciona:**
  TruffleHog escanea historias de Git, sistemas de archivos, buckets S3 y logs. Su mayor diferenciador radica en la **verificación activa de credenciales (active validation)**: cuenta con más de 800 detectores que no solo buscan patrones sintácticos, sino que realizan una solicitud HTTP ligera contra la API del proveedor (AWS, GitHub, Slack, etc.) para comprobar si la credencial es válida en tiempo real.
- **Implementación en un pipeline de CI:**
  Se corre como job bloqueante en el pipeline de validación antes del merge:
  ```bash
  docker run --rm -v "$PWD:/repo" trufflesecurity/trufflehog:latest git file:///repo --only-verified
  ```
  El flag `--only-verified` filtra únicamente aquellos hallazgos donde la clave respondió afirmativamente en el proveedor, reduciendo los falsos positivos prácticamente a cero.
- **Qué NO resuelve:**
  1. *Riesgo operacional durante la verificación:* La consulta contra la API del proveedor puede generar alertas en el SOC del proveedor, disparar rate limits o activar bloqueos no deseados.
  2. *Secretos internos:* Claves propietarias o internas (como el token de PhantomCorp o llaves de bases de datos internas) no tienen endpoint público contra el cual verificarse.
  3. *Neutralización:* Identificar la clave no revoca el acceso ni remueve los objetos de los clones distribuidos.

---

### 2. Herramientas de Limpieza y Reescritura

Cuando un secreto ya se encuentra integrado en commits viejos o ramas abandonadas, se vuelve imprescindible expurgar el objeto de la base de datos de Git.

| Característica | `git-filter-repo` | BFG Repo-Cleaner |
|---|---|---|
| **Tecnología base** | Python 3 (motor oficial recomendado por Git) | Java / Scala |
| **Rendimiento** | Muy alto (utiliza `fast-export` y `fast-import`) | Extremadamente rápido en repos grandes |
| **Sintaxis y filtros** | Completo y flexible (expresiones regulares, paths, autores, callbacks en Python) | Simplificado (reemplazo por strings fijas o regex básicas) |
| **Estado del proyecto** | Activo, estándar oficial recomendado tras la depreciación de `git filter-branch` | Proyecto maduro en modo mantenimiento |
| **Seguridad por diseño** | Exige trabajar sobre un clon fresco (`--fresh`) para evitar daño accidental | No protege proactivamente el árbol de trabajo |

#### A. `git-filter-repo`
- **Mecanismo:**
  Procesa el flujo de datos entre `git fast-export` y `git fast-import`. Reescribe los árboles (trees), commits y tags eliminando referencias al archivo o reemplazando cadenas de texto exactas sin dejar rastros en los blobs resultantes.
- **Uso típico para eliminar un archivo con secretos:**
  ```bash
  git clone --no-local --bare . ../repo-limpio.git
  cd ../repo-limpio.git
  git-filter-repo --invert-paths --path .env.pasarela --path notas_investigacion.txt
  git-filter-repo --replace-text <(echo 'regex:PHANTOM_API_TOKEN\s*=\s*"[^"]*"==>PHANTOM_API_TOKEN = "***REDACTED***"')
  ```
- **Qué NO resuelve:**
  1. **Clones y copias remotas:** No tiene alcance sobre forks existentes, copias locales de otros miembros del equipo ni caches de la plataforma remota (GitHub / GitLab).
  2. **Validez del secreto:** La clave sigue funcionando en los servidores hasta que sea rotada en el proveedor.
  3. **Rotura de trazabilidad:** Modifica los SHA-1 de todos los commits derivados, invalidando firmas GPG, cerrando pull requests abiertos y rompiendo enlaces de tickets externos (Jira, GitHub Issues).

#### B. BFG Repo-Cleaner
- **Mecanismo:**
  Optimizado para ser entre 10 y 50 veces más rápido que `git filter-branch`. Busca archivos por nombre (`--delete-files`) o textos específicos (`--replace-text`) y modifica únicamente los commits afectados y sus descendientes, preservando intencionalmente la punta de `HEAD` para evitar pérdida de código actual.
- **Qué NO resuelve:**
  Al priorizar la facilidad de uso frente a la flexibilidad total, no permite reescrituras complejas dependientes del contexto y comparte el límite ontológico de toda reescritura: **lo que fue extraído por terceros no puede ser borrado mediante software**.

---

## Pregunta de cierre (obligatoria)

> **GitHub escanea pushes públicos buscando secretos y avisa a los proveedores (AWS, etc.) para revocarlos. ¿Por qué eso NO te salva igual? Mencioná al menos dos ventanas de exposición que quedan abiertas.**

El programa de escaneo de secretos de GitHub (*Secret Scanning Partner Program*) es una medida valiosa de defensa reactiva, pero **no garantiza inmunidad** frente a un incidente de seguridad. Existen al menos dos ventanas críticas de exposición que quedan desprotegidas:

### 1. La ventana de explotación automatizada (Race condition con bots adversarios)
El flujo de alerta de GitHub opera mediante un pipeline asíncrono:
1. El dev hace push al repositorio público.
2. GitHub ingesta el commit, ejecuta sus expresiones regulares de proveedores asociados y genera una notificación vía API o webhook hacia el proveedor (ej. AWS, Azure, Datadog).
3. El proveedor recibe la alerta, identifica la cuenta afectada y ejecuta la acción correctiva (ej. adjuntar la política restrictiva `AWSCompromisedKeyQuarantineV2` o revocar la llave).

Este ciclo suele tardar entre **2 y 15 minutos**.  
Por el contrario, los actores maliciosos monitorean el feed público de eventos de GitHub (`https://api.github.com/events`) en tiempo real mediante conexiones HTTP persistentes o WebSockets. La detección y prueba de la credencial por parte de un bot ofensivo toma entre **30 y 90 segundos**. En esa ventana de oportunidad (*window of opportunity*), los scripts de los atacantes automatizan el aprovisionamiento de clústeres para criptominado, la exfiltración de bases de datos o la creación de usuarios con persistencia administrativa antes de que la cuarentena del proveedor se aplique.

### 2. Inexistencia de convenios para credenciales internas o proveedores no afiliados
GitHub Secret Scanning solo cuenta con acuerdos de revocación automática con un centenar de proveedores de primer nivel (AWS, Google Cloud, Microsoft, Stripe, Slack, etc.).  
El sistema **no cubre en absoluto**:
- Credenciales internas o propietarias (ej. el token `PHANTOM_API_TOKEN` o el `staging_key` del caso estudiado).
- Claves privadas SSH (`id_rsa`, `id_ed25519`).
- Secretos de pasarelas de pago regionales o servicios fintech locales sin convenio corporativo con GitHub.
- Conexiones a bases de datos on-premise (`postgres://user:pass@host/db`).

Para la totalidad de estos secretos, GitHub no emite ninguna notificación al emisor ni puede revocar el acceso. La credencial permanece activa y vulnerable en los servidores de la empresa hasta que un auditor humano la detecte o el atacante culmine su intrusión.

---

## Fuentes consultadas

1. **Git Project Documentation:** *git-filter-repo: Man Page and User Manual*, Michael Haggerty, 2024. [https://github.com/newren/git-filter-repo](https://github.com/newren/git-filter-repo)
2. **Gitleaks Repository & Documentation:** Zachary Rice, *Audit git repos for secrets*, 2024. [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
3. **Truffle Security:** *TruffleHog v3: Active Credential Verification Architecture*, 2024. [https://trufflesecurity.com/trufflehog](https://trufflesecurity.com/trufflehog)
4. **Meli, M. et al. (North Carolina State University):** *How Bad Can It Git? Characterizing Secret Leakage in Public GitHub Repositories*, Proceedings of the ISOC Network and Distributed System Security Symposium (NDSS), 2019.
5. **GitHub Docs:** *About secret scanning and push protection for repositories*, GitHub Enterprise Cloud Docs, 2024. [https://docs.github.com/code-security/secret-scanning](https://docs.github.com/code-security/secret-scanning)
