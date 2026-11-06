# Research — Lab Extra 2: El repo que delata

**Grupo:** 02 · **Autor de esta parte:** Torres Damaris — @damaris412

**Declaración de uso de IA:** usamos Claude (Anthropic) para organizar y redactar
este research. Los datos de cada herramienta se tomaron de su documentación
oficial (fuentes al final) y se relacionaron con lo que hicimos en el lab.

**Opción elegida:** A — Herramientas reales (detección y limpieza de secretos).

---

Comparo una herramienta de **detección** (Gitleaks) y una de **limpieza**
(`git filter-repo`), que cubren las dos mitades del problema que vimos en el lab:
*encontrar* lo que quedó en la historia y *sacarlo* de ahí.

## Detección — Gitleaks

**Qué busca:** secretos en código e historia de git (API keys, tokens, claves
privadas, `.env`) mediante reglas de expresiones regulares y detección de
entropía. Puede escanear el árbol actual (`gitleaks detect`), **toda la historia
de commits** (recorre los diffs, igual que nosotros con `git log -p`) y los
diffs de un push.

**Cómo la usaría en un pipeline de CI:** en dos lugares, igual que las
mitigaciones de la P5 del informe:
- como **pre-commit hook** local (`gitleaks protect --staged`), para frenar el
  secreto antes de que entre al historial;
- como **job de CI** (GitHub Actions / GitLab CI) que corre `gitleaks detect` en
  cada push/PR y falla el build si encuentra algo, bloqueando el merge.

**Qué NO resuelve:** es *detección*, no *remediación*. Encuentra el secreto, pero
no lo rota ni lo borra de la historia; y como toda herramienta de patrones, tiene
falsos negativos (un secreto con formato raro puede escaparse) y falsos positivos
(ruido que hay que calibrar con un `.gitleaks.toml`). Sobre todo: encontrar el
secreto **no lo invalida** — hay que rotarlo igual.

## Limpieza — `git filter-repo`

**Qué hace:** reescribe la historia del repositorio para **eliminar** archivos o
reemplazar cadenas en todos los commits (p. ej. borrar `config.py` de toda la
historia, o reemplazar el valor del token por `***`). Es el reemplazo moderno y
recomendado del viejo `git filter-branch` (más rápido y seguro), y cumple el rol
del BFG Repo-Cleaner con más flexibilidad.

**Cómo la usaría:** después de **rotar** los secretos, para dejar el repo limpio
de cara al futuro: `git filter-repo --path config.py --invert-paths` (saca el
archivo de toda la historia) o `--replace-text` (reemplaza valores). Luego
force-push y pedir a todos que re-clonen.

**Qué NO resuelve:** reescribir la historia **no protege lo ya filtrado**. Como
analizamos en la P4, si el repo fue público o tiene forks/clones, el secreto ya
fue visto; `filter-repo` solo evita *futuras* exposiciones del repo canónico.
Además cambia todos los hashes de los commits, lo que rompe los clones existentes
y referencias (PRs, tags) — por eso es la parte *menos* urgente del plan: va
**después** de rotar, nunca en lugar de rotar.

**En resumen:** Gitleaks te dice *qué* se filtró y *dónde*; `filter-repo` lo saca
del historial. Ninguna de las dos reemplaza el paso que de verdad corta el riesgo
—**rotar el secreto**— que es la conclusión que sacamos investigando el caso.

## Pregunta de cierre: ¿por qué el escaneo de GitHub no te salva igual?

GitHub escanea los pushes públicos buscando secretos de proveedores conocidos
(AWS, Stripe, etc.) y les avisa para que los revoquen. Aun así quedan al menos
dos **ventanas de exposición** abiertas:

1. **La ventana push → revocación.** Entre que hacés el push y que el proveedor
   efectivamente revoca la clave pasan minutos, y los bots de atacantes escanean
   en ese mismo rango de tiempo (el uso de una clave AWS filtrada se mide en
   minutos). En esa ventana la credencial es válida y usable: puede que te la
   usen *antes* de que la alerta surta efecto.
2. **Lo que GitHub no cubre.** Solo detecta patrones de proveedores soportados:
   un secreto *custom* (como el `PHANTOM_API_TOKEN` o el `PAGOS_SECRET` de nuestro
   lab, o la `staging_key` del cluster) no dispara ninguna alerta ni revocación
   automática. Y el escaneo es para repos **públicos**: en uno privado con 30
   colaboradores (P3) el secreto puede vivir expuesto internamente sin que nadie
   lo note. Por eso el escaneo de GitHub es una red de contención útil, pero no
   reemplaza rotar el secreto ni los controles propios (pre-commit + CI).

## Fuentes

- Gitleaks — documentación oficial (GitHub del proyecto).
  https://github.com/gitleaks/gitleaks
- `git filter-repo` — documentación oficial.
  https://github.com/newren/git-filter-repo
- GitHub Docs — *About secret scanning* / *Push protection*.
  https://docs.github.com/en/code-security/secret-scanning/about-secret-scanning
- GitHub Docs — *Removing sensitive data from a repository*.
  https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
- OWASP — *Secrets Management Cheat Sheet*.
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
