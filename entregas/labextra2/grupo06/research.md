# Research — Lab Extra 2: El repo que delata

**Grupo:** 06
**Fecha:** 2026-10-29
**Opción elegida:** A — Herramientas reales (detección y limpieza de secretos en Git)

**Declaración de uso de IA:**

**Herramienta:** ChatGPT y Claude

- **Finalidad:** revisión de redacción y contraste de afirmaciones con documentación oficial.

- **Partes asistidas:** explicación de Gitleaks, alcance del historial y reflog, limpieza con git filter-repo, protecciones de GitHub y referencias.

## 1. Detección: Gitleaks

Gitleaks es una herramienta de código abierto que busca posibles secretos, como contraseñas, tokens y claves de API. Permite analizar archivos de un directorio o cambios del historial de Git. Utiliza reglas configurables, expresiones regulares y, según la regla, criterios como la entropía del valor encontrado. Su configuración admite reglas propias y exclusiones para falsos positivos revisados [1].

**Cómo se usaría en un pipeline de CI:** En una ejecución de CI se puede analizar el historial disponible en el clon con:

```bash
gitleaks git --log-opts="--all" repo-delata
```

Los comandos antiguos `gitleaks detect` y `gitleaks protect` están deprecados desde la versión 8.19.0; la documentación actual organiza el análisis en los modos `git`, `dir` y `stdin` [1].

El alcance depende tanto del comando como del contenido del clon. Un checkout superficial o que no haya obtenido las referencias necesarias no permite revisar toda la historia remota. Por eso, el workflow debe recuperar el historial y las ramas que se pretenden analizar.

También puede integrarse una revisión local antes del commit para detectar secretos en los cambios preparados. Esto complementa el control de CI, pero no lo reemplaza.

**Qué no resuelve:** `--all` incluye los commits alcanzables desde las referencias locales y `HEAD`. No incorpora automáticamente todos los objetos existentes en `.git`. Git ofrece `--reflog` como una opción diferente para incluir commits mencionados por los reflogs [2].

En el escenario descrito para R3, el escaneo podría alcanzar la rama `feature/pasarela-pagos` si su referencia e historial están disponibles localmente. Para R2, si el commit se conserva únicamente en el reflog, `--all` por sí solo no alcanza. Los objetos sin referencias ni entradas de reflog requieren una revisión adicional.

Tampoco puede asegurarse que Gitleaks detecte los tres secretos del laboratorio sin ejecutarlo: el resultado depende de las reglas, las exclusiones y el formato de los valores. La herramienta no elimina ni revoca credenciales.

## 2. Limpieza: `git filter-repo`

La documentación de Git desaconseja utilizar `git filter-branch` por sus problemas de rendimiento y seguridad, y recomienda herramientas alternativas como `git filter-repo` [3].

`git filter-repo` permite reescribir el historial para eliminar archivos o reemplazar contenido. Es una operación de remediación que debe planificarse, porque modifica identificadores de commits y puede afectar ramas, etiquetas y herramientas relacionadas [4].

**Cómo se usaría en una respuesta a incidente:** La primera medida es revocar o rotar la credencial, comprobando que el valor anterior quede invalidado. Después se evalúa si también resulta necesario retirarla del historial. GitHub advierte que la reescritura puede no estar justificada si la revocación ya elimina el riesgo de acceso [5].

Si se decide limpiar, se trabaja sobre un clon fresco con el historial y las referencias necesarios. Los siguientes comandos ilustran dos operaciones alternativas; no representan pruebas ejecutadas en este laboratorio:

```bash
git filter-repo --sensitive-data-removal \
  --path .env.pasarela --invert-paths
```

```bash
git filter-repo --sensitive-data-removal \
  --replace-text ../secretos.txt
```

El primer ejemplo elimina la ruta indicada del historial procesado. Si el archivo tuvo otros nombres o ubicaciones, deben incluirse también. El segundo utiliza un archivo de expresiones de reemplazo, que debe mantenerse fuera del repositorio y protegerse por su contenido sensible [4][5].

**Qué no resuelve:** Reescribir el repositorio local y actualizar el remoto no elimina las copias existentes en clones, forks, referencias de pull requests o vistas almacenadas por la plataforma. Es necesario coordinar la limpieza de otras copias y evitar que un colaborador vuelva a publicar el historial anterior. Volver a clonar es una opción; otra es limpiar cuidadosamente el clon existente [5].

La herramienta tampoco convierte la limpieza en prevención continua. Su función principal es modificar el historial seleccionado, mientras que los controles de CI y los hooks buscan evitar nuevas incorporaciones.

## 3. Pregunta de cierre — por qué el secret scanning de GitHub no alcanza

GitHub Secret Scanning analiza el historial de todas las ramas del repositorio y realiza nuevas revisiones cuando incorpora tipos de secretos. Por eso, una rama nunca fusionada no queda excluida simplemente por estar fuera de `main` [6].

Push Protection cumple otra función: puede bloquear pushes que contienen secretos reconocidos. No retira credenciales ya publicadas ni elimina copias que terceros hayan obtenido antes del bloqueo [7].

Estas protecciones tienen límites. La detección depende de los tipos de secretos y funciones disponibles; una alerta no implica que la credencial ya esté invalidada. Cuando GitHub notifica a un proveedor asociado, este debe tomar las medidas correspondientes. El equipo también debe comprobar la revocación y actualizar los servicios afectados [6].

Además, los reflogs locales y los objetos que solo existen en una copia particular no equivalen al historial disponible en GitHub. No corresponde asumir que el escaneo de la plataforma cubre esos datos.

La respuesta debe combinar prevención, detección y remediación: evitar incorporar secretos, revisar el alcance real de los escaneos y revocar las credenciales expuestas. Borrar un archivo o reescribir commits no sustituye la rotación con invalidación del valor anterior.

## 4. Fuentes

1. Gitleaks. _Repositorio oficial y documentación_.  
   https://github.com/gitleaks/gitleaks

2. Git. _git-log: opciones `--all` y `--reflog`_.  
   https://git-scm.com/docs/git-log

3. Git. _git-filter-branch: advertencias y alternativas_.  
   https://git-scm.com/docs/git-filter-branch

4. Newren, E. _git-filter-repo: repositorio oficial_.  
   https://github.com/newren/git-filter-repo

5. GitHub Docs. _Removing sensitive data from a repository_.  
   https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository

6. GitHub Docs. _Secret scanning_.  
   https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning

7. GitHub Docs. _Push protection_.  
   https://docs.github.com/en/code-security/concepts/secret-security/push-protection
