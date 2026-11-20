# Anexo — Detalle técnico por integrante

Complemento de `entrega/informe.md` (§9). Los textos se trasladan sin cambios desde el
informe para que el cuerpo respete el límite de 3 a 5 páginas.

### P2 — Autorización, RoE, tokens y red team

Se implementó el parser YAML del Rules of Engagement (RoE), que limita dominios
y CIDR al laboratorio declarado en `harness/profiles.yaml` y verifica aprobación,
ventana con zona horaria, fases y exclusiones. El emisor genera tokens por fase
con TTL tomado de `policy.yaml`, registra emisiones y rechazos, y vincula cada
token al engagement. El Guard incluye comprobaciones de normalización, IPv6,
engagement y resolución DNS opcional. Para emitir tokens se hizo obligatorio el
sink de auditoría; queda pendiente conectar el sink persistente SQLite de P1.
También se incorporaron `RedirectPolicy` y `validate_parameters` como controles
reutilizables por los adaptadores.

Los intentos adversariales A1–A10 están en `tests/test_redteam_guard.py` y las
mutaciones M1–M9 en `entrega/mutaciones.md`, con salidas en
`entrega/evidencia/salidas/`. Para los gates 007 · 3.1 y 3.3 se agregaron pruebas
que rechazan hallazgos incompletos y entregas sin aprobación. No se modificó
`harness/reporting.py`, que corresponde a P5.

En la revisión posterior se agregaron pruebas para la expiración exacta del
token, fases vacías, exclusiones combinadas, contactos inválidos, fases
desconocidas y el hash de aprobación. La evidencia local registra **162 tests
aprobados**, **10/10 evals golden** y `ruff` limpio en los archivos P2 revisados.
Las comprobaciones se ejecutaron con `python -X utf8` por la codificación de la
consola Windows. `progress.py` informa 003 en **13/14**: sigue pendiente la
revisión cruzada humana 1.3. La spec de autorización contiene **23 Scenarios**.

El chequeo focal `mypy --strict --follow-imports=skip` pasó para `roe.py` y
`tokens.py`. Al seguir imports, mypy informa errores en las interfaces de
`contracts.py` y `policy_loader.py`, que no corresponden a esos dos archivos.

**Límites y pendientes:** A4 depende de configurar `Guard(resolver=...)` en
runtime y A5 de que el adaptador HTTP de 004 use `RedirectPolicy`; ambas
integraciones siguen pendientes. También falta una revisión humana de si los
bypass encontrados son reales y si las correcciones son suficientes, además de
la revisión cruzada 003 · 1.3. Los commits de tests y correcciones se conservaron
en la historia local: `98e85f4` → `1b9392e` y `9a76691` → `937a234`. La rama aún
no se publicó en el remoto. La prueba de “emisor único” de `ScopeToken` es
estática: la clase sigue siendo pública y puede construirse desde fuera del
paquete, por lo que no impide en runtime la fabricación de tokens. También falta
una revisión independiente de seguridad del diff.

### P5 — Validación, informe y recorrido

El sandbox crea un contenedor de solo lectura y sin capacidades por verificación, lo
destruye siempre y hace una sola solicitud sin seguir redirecciones; el Sender
rechaza hosts fuera del lab aunque el token los incluya. La aprobación se liga al hash
de los parámetros. El informe deriva cada estado de la bitácora, se identifica por su
hash, rechaza datos sensibles y no se entrega ni exporta si alguna etapa es simulada.
El change 008 conectó el loop B de P4 (ZAP) al recorrido con su propio gate y una
tabla de vectores CVSS firmada. El change 002 se implementó sobre el diseño de P1, con
un único desvío documentado (evento como JSON canónico). Detalle y evidencia: los
`archive.md` de cada change y `entrega/evidencia/salidas/P5-*`.
