# Diseño — revisión documental

Registrar SHA-256 del insumo antes de normalizarlo. Validar el informe en un
contenedor efímero sin red. El borrador no contiene rutas, código ni mensajes de
Bandit. Es reproducible para el mismo insumo; la exportación lo recalcula y
comprueba integridad y conformidad explícita antes de crear un nuevo JSON local.
El hash no autentica al aprobador ni es una firma. No hay CVSS/CWE inventados,
hallazgos confirmados, publicación automática ni compatibilidad DefectDojo.
