# Research — Lab Extra 2: El repo que delata (Opción A)

**Grupo:** 14 · **Declaración de uso de IA:** usamos IA para resumir y comparar
las herramientas; las fuentes se verificaron en su documentación oficial.

## Detección: Gitleaks vs. TruffleHog

- **Gitleaks** — busca secretos por *regex* + entropía sobre el árbol y toda la
  historia de git (`gitleaks detect`). En CI: job que corre en cada PR/push y
  falla el build si encuentra un match; también como pre-commit hook. **No
  resuelve:** no rota ni revoca nada, y los falsos positivos/negativos dependen
  de la calidad de las reglas; no limpia la historia.

- **TruffleHog** — además de patrones, **verifica** credenciales llamando al
  proveedor (dice si la key sigue *viva*), y escanea historia, ramas y más de
  700 tipos de secretos. En CI: igual que gitleaks, con el plus de priorizar
  secretos verificados-activos. **No resuelve:** tampoco rota ni reescribe
  historia; la verificación activa puede generar tráfico/ruido.

## Limpieza: git filter-repo vs. BFG Repo-Cleaner

- **git filter-repo** — reescribe la historia completa (reemplaza texto, borra
  archivos/paths). Flexible y recomendado por el proyecto git sobre
  `filter-branch`. **No resuelve:** cambia todos los hashes → obliga a
  recoordinar a todo el equipo y **no** toca las copias ya clonadas/forkeadas.

- **BFG Repo-Cleaner** — más simple y rápido para el caso típico (borrar
  archivos grandes / secretos por patrón). **No resuelve:** menos granular que
  filter-repo y, de nuevo, no revoca el secreto ni alcanza a los forks.

## Pregunta de cierre

El escaneo de GitHub en pushes públicos **no te salva** porque:
1. **Ventana pre-aviso:** entre que pusheás y el proveedor revoca, el secreto
   estuvo público; bots que scrapean en tiempo real pueden haberlo copiado ya.
2. **Cobertura parcial:** solo cubre proveedores soportados y repos públicos en
   GitHub; un secreto propio (API interna, DB) o un repo privado/forkeado no
   dispara revocación automática, y las copias locales/forks conservan la historia.
