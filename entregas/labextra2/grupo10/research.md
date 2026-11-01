# Research — Lab Extra 2: El repo que delata

## Detección y limpieza de secretos en Git

### Por qué hacen falta dos tipos de herramienta

Cuando una credencial se agrega a Git, un commit posterior que la borra solo cambia la versión actual del archivo. Los commits anteriores siguen formando parte del historial y pueden estar en ramas, clones y forks. Por eso conviene distinguir dos trabajos: detectar dónde aparece una credencial y, si se filtró, quitarla de las referencias del repositorio. Ninguno de esos pasos invalida por sí solo la credencial: hay que revocarla o rotarla primero.

### Detección: Gitleaks

Gitleaks busca posibles secretos en archivos y en el historial de Git. Sus reglas identifican patrones de proveedores y permiten configurar reglas propias [1]. La CLI actual usa `gitleaks git` para revisar parches del historial; el README explica que el escaneo se apoya en `git log -p`. También incluye un ejemplo de hook pre-commit. En versiones recientes `detect` y `protect` siguen disponibles como comandos ocultos, pero están deprecados desde v8.19.0; por eso conviene fijar la versión y comprobar el comando del hook antes de adoptarlo [1].

Lo usaría en dos momentos. En la computadora de cada integrante instalaría un hook pre-commit para examinar lo preparado antes de crear el commit, usando el ejemplo del proyecto y una versión fijada. En CI ejecutaría `gitleaks git` sobre el repositorio y los cambios de cada pull request; conservaría el historial completo en el checkout para no limitar el análisis a los últimos commits. El hook da una respuesta rápida, mientras que CI brinda un control común para las contribuciones del equipo [1].

Gitleaks es un detector, no una garantía de que todo secreto vaya a encontrarse. Puede no reconocer un formato que no esté cubierto por sus reglas, y una regla amplia puede producir falsos positivos. Además, un hook instalado en la computadora de una persona puede omitirse o no estar instalado en la de otra; el propio proyecto documenta cómo omitir el hook [1]. Si encuentra una clave, el equipo debe confirmar si es real y activa, revocarla y seguir el procedimiento de limpieza. Gitleaks no revoca credenciales ni borra automáticamente todas las copias históricas.

### Limpieza: `git-filter-repo`

`git-filter-repo` sirve para reescribir el historial. Puede eliminar un archivo de todas las referencias o reemplazar texto sensible en los archivos históricos; GitHub documenta ambos usos y pide verificar el resultado después de reescribirlo [2]. Por ejemplo, después de rotar la credencial, se podría trabajar sobre un clon nuevo, usar `--replace-text` para reemplazar el valor filtrado, inspeccionar todas las ramas y etiquetas, y coordinar la actualización del remoto. La reescritura crea commits distintos, por lo que requiere una actualización coordinada y puede afectar ramas, etiquetas y pull requests [2].

La herramienta no es un escáner ni una forma de desactivar la clave. Tampoco puede retirar por sí sola el secreto de los clones y forks que otras personas ya tienen. Su documentación recomienda revocar o rotar primero: una vez invalidada, la credencial deja de servir aunque sobreviva en una copia; después se reescribe y limpia el historial, y se coordinan las copias restantes [3].

### Comparación y conclusión

| Herramienta | Función | Uso en el flujo | Límite principal |
|---|---|---|---|
| Gitleaks | Detecta coincidencias con reglas en cambios o historia | Hook pre-commit compatible con la versión fijada y `gitleaks git` en CI | Puede no reconocer secretos fuera de sus patrones; no los invalida ni limpia la historia |
| `git-filter-repo` | Reescribe commits y referencias para retirar archivos o valores | Limpieza coordinada del historial después de contener el incidente | No revoca el valor expuesto ni elimina copias de clones, forks u otros servicios |

La respuesta operativa es usar prevención y detección antes de una filtración, y tratar cualquier secreto confirmado como comprometido: revocarlo o rotarlo, evaluar el uso que tuvo, limpiar el historial y coordinar a quienes conservan copias. La reescritura reduce la exposición futura en el remoto, pero no sustituye la rotación [2][3].

### Pregunta de cierre: por qué GitHub no alcanza

En repositorios públicos, GitHub activa secret scanning automáticamente y puede generar alertas para patrones compatibles; algunas credenciales también generan avisos a proveedores participantes. Push protection puede bloquear secretos compatibles antes de que lleguen al repositorio, pero la cobertura y disponibilidad dependen del patrón, el tipo de repositorio y la configuración [4][5]. Aun así, quedan ventanas abiertas:

1. **El secreto pudo salir antes del aviso o la revocación.** Si una credencial llega al repositorio público, otras personas o sistemas automatizados pueden copiarla antes de que el equipo responda. La alerta informa; no invalida la clave. Los avisos directos también se limitan a proveedores participantes [4].
2. **La cobertura depende de los patrones y la configuración.** GitHub mantiene una lista de tipos compatibles; Push Protection cubre los tipos que puede reconocer con suficiente confianza y, para repositorios, depende de la configuración y el plan. Un secreto privado o con un formato no contemplado puede pasar inadvertido [4][5].
3. **Las copias externas sobreviven a la limpieza.** Un fork, clon, descarga o registro externo puede conservar el commit anterior después de un force-push. Por eso, hay que contactar a quienes conservan copias y tratar la credencial como comprometida, además de limpiar el remoto [2][3].

## Fuentes

1. Gitleaks. (s. f.). *Gitleaks: Scan git repos (or files) for secrets*. GitHub. https://github.com/gitleaks/gitleaks
2. GitHub. (s. f.). *Removing sensitive data from a repository*. GitHub Docs. https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
3. Newren, C. (s. f.). *git-filter-repo: Sensitive data removals*. GitHub. https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt
4. GitHub. (s. f.). *Supported secret scanning patterns*. GitHub Docs. https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns
5. GitHub. (s. f.). *Push protection*. GitHub Docs. https://docs.github.com/en/code-security/concepts/secret-security/push-protection
