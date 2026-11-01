# Research — Lab Extra 2: El repo que delata

## Detección y limpieza de secretos en Git

### Por qué hacen falta dos tipos de herramienta

Cuando una credencial se agrega a Git, un commit posterior que la borra solo cambia la versión actual del archivo. Los commits anteriores siguen formando parte del historial y pueden estar en ramas, clones y forks. Por eso conviene distinguir dos trabajos: detectar dónde aparece una credencial y, si se filtró, quitarla de las referencias del repositorio. Ninguno de esos pasos invalida por sí solo la credencial: hay que revocarla o rotarla primero.

### Detección: Gitleaks

Gitleaks busca posibles secretos en archivos y en el historial de Git. Sus reglas identifican patrones de proveedores y pueden usar expresiones regulares y entropía; también permite configurar reglas propias [1]. En un repositorio Git, `gitleaks detect` revisa parches del historial (`git log -p`); `gitleaks protect --staged` examina los cambios preparados para el próximo commit [1].

Lo usaría en dos momentos. En la computadora de cada integrante instalaría el hook de pre-commit para que examine lo preparado antes de crear el commit. En CI ejecutaría Gitleaks sobre el repositorio y los cambios de cada pull request; conservaría el historial completo en el checkout para no limitar el análisis a los últimos commits. El hook da una respuesta rápida, mientras que CI brinda un control común para las contribuciones del equipo. El README oficial documenta tanto el uso de `--staged` en pre-commit como el escaneo del repositorio desde la línea de comandos [1].

Gitleaks es un detector, no una garantía de que todo secreto vaya a encontrarse. Puede no reconocer un formato que no esté cubierto por sus reglas, y una regla amplia puede producir falsos positivos. Además, un hook instalado en la computadora de una persona puede omitirse o no estar instalado en la de otra; el propio proyecto documenta cómo omitir el hook [1]. Si encuentra una clave, el equipo debe confirmar si es real y activa, revocarla y seguir el procedimiento de limpieza. Gitleaks no revoca credenciales ni borra automáticamente todas las copias históricas.

### Limpieza: `git-filter-repo`

`git-filter-repo` sirve para reescribir el historial. Puede eliminar un archivo de todas las referencias o reemplazar texto sensible en los archivos históricos; GitHub documenta ambos usos y pide verificar el resultado después de reescribirlo [2]. Por ejemplo, después de rotar la credencial, se podría trabajar sobre un clon nuevo, usar `--replace-text` para reemplazar el valor filtrado, inspeccionar todas las ramas y etiquetas, y coordinar la actualización del remoto. La reescritura crea commits distintos, por lo que requiere una actualización coordinada y puede afectar ramas, etiquetas y pull requests [2].

La herramienta no es un escáner ni una forma de desactivar la clave. Tampoco puede retirar por sí sola el secreto de los clones y forks que otras personas ya tienen. Su documentación recomienda revocar o rotar primero: una vez invalidada, la credencial deja de servir aunque sobreviva en una copia; después se reescribe y limpia el historial, y se coordinan las copias restantes [3].

### Comparación y conclusión

| Herramienta | Función | Uso en el flujo | Límite principal |
|---|---|---|---|
| Gitleaks | Detecta coincidencias con reglas en cambios o historia | Hook `protect --staged` y análisis `detect` en CI | Puede no reconocer secretos fuera de sus patrones; no los invalida ni limpia la historia |
| `git-filter-repo` | Reescribe commits y referencias para retirar archivos o valores | Limpieza coordinada del historial después de contener el incidente | No revoca el valor expuesto ni elimina copias de clones, forks u otros servicios |

La respuesta operativa es usar prevención y detección antes de una filtración, y tratar cualquier secreto confirmado como comprometido: revocarlo o rotarlo, evaluar el uso que tuvo, limpiar el historial y coordinar a quienes conservan copias. La reescritura reduce la exposición futura en el remoto, pero no sustituye la rotación [2][3].

### Pregunta de cierre: por qué GitHub no alcanza

El escaneo de GitHub ayuda a detectar credenciales compatibles con sus patrones y generar alertas; Push Protection puede bloquear pushes que contienen secretos compatibles [4]. Aun así, quedan ventanas abiertas:

1. **El secreto pudo salir antes del aviso o la revocación.** Si el push llega a un repositorio público, otras personas o sistemas automatizados pueden copiarlo antes de que el equipo lea la alerta y el proveedor invalide la clave. La alerta detecta; no hace que una credencial ya expuesta sea inválida [4].
2. **El detector no cubre todos los valores ni todos los ajustes.** GitHub limita la detección a patrones que reconoce; el escaneo genérico requiere habilitación y Push Protection solo bloquea los tipos compatibles. Un secreto privado o con un formato no contemplado puede pasar inadvertido [4].
3. **Las copias externas sobreviven a la limpieza.** Un fork, clon, descarga o registro externo puede conservar el commit anterior después de un force-push. Por eso, hay que contactar a quienes conservan copias y tratar la credencial como comprometida, además de limpiar el remoto [2][3].

## Fuentes

1. Gitleaks. (s. f.). *Gitleaks: Scan git repos (or files) for secrets*. GitHub. https://github.com/gitleaks/gitleaks
2. GitHub. (s. f.). *Removing sensitive data from a repository*. GitHub Docs. https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
3. Newren, C. (s. f.). *git-filter-repo: Sensitive data removals*. GitHub. https://github.com/newren/git-filter-repo/blob/main/Documentation/git-filter-repo.txt
4. GitHub. (s. f.). *About secret scanning alerts*. GitHub Docs. https://docs.github.com/en/code-security/concepts/secret-security/about-alerts
