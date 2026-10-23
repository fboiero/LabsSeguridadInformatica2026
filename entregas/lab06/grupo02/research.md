# Research — Lab 06 · Enumeración de servicios

Material de apoyo del inventario de `informe.md`. Fuentes, técnicas y comandos
usados durante la enumeración de PhantomCorp.

---

## 1. Táctica y encuadre (MITRE ATT&CK)

- **Táctica:** Discovery — `TA0007`.
- **Técnicas aplicadas:**
  - `T1083` File and Directory Discovery → `dirb`/`gobuster` sobre rutas.
  - `T1595.003` Active Scanning: Wordlist Scanning → fuerza bruta de rutas.
  - `T1082` System Information Discovery → fingerprinting con `whatweb`/`nmap -sC`.
  - `T1087` Account Discovery → enumeración vía `/api/users`.

La enumeración es la fase que más determina el vector de explotación posterior:
sobre un servicio ya identificado en recon, busca lo que **no** está publicado.

---

## 2. Herramientas usadas

| Tool | Para qué | Comando base |
|---|---|---|
| `dirb` | Fuerza bruta de directorios/archivos con wordlist | `dirb http://phantomcorp/` |
| `gobuster` | Igual que dirb, más rápido (Go) | `gobuster dir -u http://phantomcorp -w /usr/share/dirb/wordlists/common.txt` |
| `whatweb` | Fingerprinting de CMS/stack/versión | `whatweb -a 3 http://phantomcorp` |
| `nmap` (NSE) | Scripts `http-methods`, `http-enum` | `nmap -sV -sC phantomcorp` |
| `curl` | Confirmar rutas, ver headers, método OPTIONS | `curl -X OPTIONS -i http://phantomcorp/` |
| `jq` | Parsear el JSON de la API | `curl -s .../api/users \| jq` |
| `git-dumper` | Reconstruir un repo desde un `.git` expuesto | `git-dumper http://phantomcorp/.git/ ./dump` |

---

## 3. Lectura de códigos de respuesta HTTP

| Código | Significado para enumerar |
|---|---|
| `200 OK` | La ruta existe y es accesible → hallazgo directo |
| `403 Forbidden` | Existe pero está protegida → igual es información (sé que está) |
| `301/302` | Redirección → suele confirmar que hay algo detrás (login) |
| `404 Not Found` | No existe → descartar |

Regla: en enumeración de directorios, **todo lo que no sea 404 es un hallazgo**.

---

## 4. Por qué el fingerprinting dirige la enumeración

Identificar producto + versión exactos (p. ej. PhantomCMS `X.Y`) permite pasar
de fuerza bruta ciega a **enumeración dirigida**: cada CMS tiene archivos default
conocidos (`/CHANGELOG`, `/README`, `/version.php`, `/wp-login.php` en
WordPress, etc.). Pedir el archivo default correcto confirma la versión y, con
esa versión, se busca el CVE aplicable (metodología del Lab 05).

---

## 5. Referencias

- MITRE ATT&CK — Discovery (TA0007): https://attack.mitre.org/tactics/TA0007/
- OWASP WSTG — Enumerate Applications / Review Webserver Metafiles:
  https://owasp.org/www-project-web-security-testing-guide/
- OWASP — Test HTTP Methods (WSTG-CONF-06):
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
- git-dumper: https://github.com/arthaud/git-dumper
- Ley 26.388 (delitos informáticos, Argentina) — marco de uso responsable.

> Uso responsable: toda la enumeración se ejecutó exclusivamente contra el
> contenedor `phantomcorp` de la cátedra. Enumerar sistemas ajenos sin
> autorización constituye acceso no autorizado (Ley 26.388).
