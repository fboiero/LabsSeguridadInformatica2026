# Research — Lab Extra: SSRF (CWE-918)

**Grupo:** 14 · **Declaración de uso de IA:** usamos IA para redactar; contrastado
con OWASP SSRF Prevention Cheat Sheet y el post-mortem público de Capital One (2019).

## Un incidente real: Capital One (2019)
Un SSRF contra una app en AWS permitió alcanzar el metadata service
(`169.254.169.254`) y robar credenciales temporales del rol IAM del servidor;
con ellas se accedió a buckets S3 con datos de ~100 millones de personas. Qué
habría cambiado: IMDSv2 (token obligatorio, que bloquea el SSRF básico), egress
restringido y validación de destino en el componente que hacía los fetch.

## Por qué el string-filtering no alcanza
`localhost` y `127.0.0.1` se evaden con: IP decimal (`2130706433`), octal
(`0177.0.0.1`), IPv6 (`[::1]`), dominios que resuelven a loopback, y
**DNS rebinding** (el nombre resuelve a una IP pública en la validación y a una
interna en el fetch). Por eso la defensa correcta valida la **IP resuelta** y
re-valida tras redirecciones, idealmente con allowlist.

## Cierre
SSRF convierte al servidor en un proxy de confianza del atacante: el impacto va
desde escaneo de puertos internos y lectura de servicios segmentados (este lab)
hasta robo de credenciales cloud (Capital One). La mitigación es de destino, no
de superficie textual.
