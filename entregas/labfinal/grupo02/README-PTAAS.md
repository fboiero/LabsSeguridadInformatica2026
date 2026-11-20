# PTaaS – Grupo 02

## Descripción

Implementación de un núcleo de Pentest as a Service (PTaaS)
con controles de autorización, alcance, ejecución segura,
auditoría y aprobación humana.

## Estructura

- `harness/contracts.py`: contratos, Guard, Harness, ScopeToken,
  adaptadores, bitácora y Kill Switch.
- `harness/engagement.py`: máquina de estados del engagement.
- `harness/loops.py`: loops de reconocimiento, detección y validación.
- `harness/adapters/`: adaptadores Nmap y Nuclei.
- `harness/poc/`: catálogo de pruebas de concepto parametrizadas.
- `harness/policy.yaml`: políticas de seguridad.
- `harness/tools.yaml`: capacidades y herramientas permitidas.
- `harness/schemas.py`: modelos y validación de datos.
- `harness/reporting.py`: generación y control de entrega de informes.
- `tests/`: pruebas automatizadas.

## Requisitos

- Python 3.11 o superior.
- Dependencias declaradas en `requirements.txt`.

Instalación:

    python -m pip install -r entregas/labfinal/grupo02/requirements.txt

## Ejecutar pruebas

Desde la raíz del repositorio:

    DEST="entregas/labfinal/grupo02"
    PYTHONPATH="$DEST" python -m pytest -v "$DEST/tests"

## Controles de seguridad

- Restricción de activos por CIDR y dominios autorizados.
- Validación de ventana temporal y fase del engagement.
- Allowlist de acciones por fase.
- Bloqueo de acciones y adaptadores destructivos.
- Aprobación humana para operaciones que la requieren.
- Kill Switch para abortar ejecuciones.
- Registro de decisiones y encadenamiento de hashes de auditoría.
- Adaptadores con argumentos acotados y ejecución sin shell.

## Validación

La batería actual contiene 52 pruebas automatizadas aprobadas.

Las pruebas de adaptadores utilizan runners controlados; el resultado
de las pruebas no implica que se haya ejecutado un escaneo real.

## Uso responsable

Este sistema debe utilizarse exclusivamente sobre activos con
autorización expresa y dentro de las condiciones definidas en el
Rules of Engagement (RoE).

La aprobación humana y los controles del Harness no sustituyen
la autorización legal ni la revisión del operador.
