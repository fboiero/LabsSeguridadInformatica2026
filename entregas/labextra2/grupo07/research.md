# Research — Lab Extra 2: El repo que delata

**Opción A — Herramientas reales.** Aporte de Lorenzo: Gitleaks y GitHub Secret Scanning/Push Protection. La entrega grupal debe completar integración y revisar la extensión total de 1–2 carillas.

## Gitleaks: una barrera desde la máquina del desarrollador

[Gitleaks](https://github.com/gitleaks/gitleaks) es un detector de secretos que analiza repositorios Git, archivos y entrada estándar. Su proyecto ofrece reglas predeterminadas y configuración propia, y documenta la integración como hook pre-commit y como acción de GitHub. El hook permite revisar el contenido que se intenta confirmar y detener el commit local si aparece un patrón sospechoso. En CI se puede ejecutar sobre cambios entrantes o sobre el repositorio/historia para detectar filtraciones que el hook no haya visto.

Su principal valor preventivo es la cercanía al autor: el desarrollador recibe el hallazgo antes del push y puede retirar el secreto del cambio. También es una herramienta que puede mantenerse dentro del propio proyecto, sin depender de que una persona tenga un plan particular del hosting. Los límites importan: detecta patrones y puede producir falsos positivos o no reconocer un secreto nuevo/no estructurado; los hooks locales no están garantizados en cada clon y pueden omitirse, por ejemplo con `--no-verify`. El CI descubre la filtración pero no siempre bloquea el push inicial si se ejecuta después de que el commit ya fue publicado. El repositorio oficial consultado indica que Gitleaks está en estado “feature complete” y que el foco futuro son parches de seguridad; conviene verificar el estado de mantenimiento y soporte antes de adoptarlo en una política nueva.

## GitHub Secret Scanning y Push Protection: control remoto

GitHub documenta que Secret Scanning busca credenciales conocidas en toda la historia Git de todas las ramas y también en otros contenidos alojados, como issues y pull requests. Esa búsqueda es útil para descubrir exposición pasada y abrir alertas; no borra objetos ni invalida por sí misma el secreto. Push Protection agrega una barrera al remoto: cuando detecta un secreto cubierto durante un push, puede detenerlo antes de que llegue al repositorio. Admite patrones de proveedores, algunos patrones genéricos y patrones personalizados según la configuración disponible. Los administradores pueden habilitarla al nivel que corresponda, revisar alertas y controlar bypasses.

Para incorporarla al flujo, habilitarla en la organización/repositorio y comprobar en la configuración qué categorías de secretos están cubiertas; usar las alertas de Secret Scanning para revisar historia y ramas; y documentar quién puede aprobar un bypass. Según la documentación, la protección de repositorios requiere GitHub Secret Protection y no está habilitada por defecto; además, contributors con permiso pueden tener opciones de bypass. Así que “el servidor escanea” no equivale a “todo secreto queda bloqueado”. La cobertura varía por tipo de patrón, configuración y superficie de push.

## Comparación práctica y ventanas de exposición

Gitleaks es útil como control temprano, repetible y configurable en el entorno de desarrollo y CI. La protección remota de GitHub cubre el límite común del push y da alertas centralizadas, pero depende de habilitación, permisos y patrones cubiertos. Usaría ambos: hook local para feedback rápido, CI como segunda verificación y Push Protection como política del servidor. Configuraría el pipeline para bloquear el merge si el escaneo del diff encuentra una credencial, y trataría las excepciones con revisión explícita. Si una credencial real entra a una historia, la respuesta inmediata es revocarla/rotarla y evaluar el alcance; reescribir historia reduce exposición futura, pero no retira copias ya clonadas.

La notificación automática al proveedor tampoco elimina dos ventanas. Primero, la credencial puede ser visible o copiada entre el commit y el push, o llegar a otro remoto, espejo o canal que no se escanea. Segundo, después de publicarla, un bot, fork, clon o caché puede conservarla aunque luego se limpie el historial; una alerta no garantiza que el proveedor la revoque antes de su uso. Además, secretos no cubiertos o bypasses dejan una ventana hasta que alguien detecte y atienda la alerta. Rotar sigue siendo lo que invalida el secreto comprometido.

## Pregunta de cierre

Un escaneo de push reduce el tiempo de exposición, pero no protege los clones antes del push, los destinos remotos sin cobertura ni los forks/cachés que ya obtuvieron el objeto. Aunque la búsqueda posterior encuentre la key y se reescriba el historial, una copia externa puede conservarla; el secreto debe rotarse. Por eso la prevención se construye en capas y la respuesta a la filtración empieza por revocar, no por borrar el commit.

## Fuentes

- Gitleaks, [repositorio y documentación oficial](https://github.com/gitleaks/gitleaks) (consulta: 2026-11-20).
- GitHub Docs, [Secret scanning](https://docs.github.com/en/code-security/concepts/secret-security/secret-scanning) (consulta: 2026-11-20).
- GitHub Docs, [Push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection) (consulta: 2026-11-20).
