# Informe forense — Incidente PhantomCorp (phantomcorp-web)


**Grupo:** 14 · **Investigadores:** *(nombre — usuario GitHub)* · **Fecha:**
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión + exfiltración

## 0. Declaración de uso de IA

- **Herramienta:** Claude (modelo Claude Sonnet 5.5, de Anthropic) usado a través de Claude Code (CLI), con acceso al repositorio del grupo.
- **Uso:** asistente a lo largo de todo el informe y del análisis de la evidencia.
- **Dinámica de trabajo:**
  1. Un integrante lee el enunciado y la rúbrica y le pide a la IA que explique conceptualmente cada paso, sin ejecutar nada.
  2. Una vez entendido el paso, se le pide a la IA que lo ejecute: comandos sobre la copia de la evidencia (`caso_copia/`, nunca sobre la original) y, cuando corresponde, código.
  3. La IA vuelca en el informe los comandos corridos y sus resultados reales.
  4. El integrante revisa lo producido antes de avanzar al paso siguiente.
- **Verificación:** los resultados se obtienen de la salida real de los comandos (se copian, no se reescriben) y se contrastan contra la evidencia y sus hashes; los hallazgos se cruzan entre fuentes (logs, disco, memoria).

## 1. Resumen del incidente
*(3-5 líneas, sin jerga: qué pasó, hasta dónde llegó el atacante, qué se llevó.)*

## 2. Cadena de custodia

Se trabajó sobre una **copia** de la evidencia (`caso_copia/`); `labs/lab11-forensia/caso/`
no se modificó.

**Precaución de sistema:** los hashes de `evidencia.sha256` corresponden a los bytes
con saltos de línea LF. En Windows con `core.autocrlf=true` el checkout los convierte
a CRLF y todos los hashes dejarían de coincidir. Por eso la copia se arma con los bytes
tal como están en git y con un `.gitattributes` (`* -text`) que evita la conversión.

**1. Crear la copia de trabajo** (desde la raíz del repo):

```bash
D=entregas/lab11/grupo14/caso_copia
for f in $(git ls-files labs/lab11-forensia/caso); do
  rel=${f#labs/lab11-forensia/caso/}
  mkdir -p "$D/$(dirname "$rel")"
  git show HEAD:"$f" > "$D/$rel"
done
printf '* -text\n' > "$D/.gitattributes"
```

**2. Verificar la integridad de cada archivo contra su hash de captura:**

```bash
cd entregas/lab11/grupo14/caso_copia
sha256sum -c evidencia.sha256        # macOS: shasum -a 256 -c evidencia.sha256
```

Salida:

```
disco/etc/passwd.snippet: OK
disco/listado.txt: OK
disco/var/www/uploads/shell.php.evidencia.txt: OK
logs/access.log: OK
logs/auth.log: FAILED
memoria/bash_history.txt: OK
memoria/lsof.txt: OK
memoria/netstat.txt: OK
memoria/pslist.txt: OK
sha256sum: WARNING: 1 computed checksum did NOT match
```

**3. Comparar el hash esperado con el actual del archivo que falló:**

```bash
grep auth.log evidencia.sha256
sha256sum logs/auth.log
```

| | SHA-256 |
|---|---|
| Registrado en la captura | `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff` |
| Actual | `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab` |

**Resultado:** 8 archivos íntegros y 1 alterado. `logs/auth.log` fue modificado
después de la captura (R5): se lo trata como **no confiable** y su contenido solo se
usa como pista a contrastar con las otras fuentes. Un archivo alterado cuya
modificación no se documenta invalida la evidencia; por eso queda registrado acá.

*(Pendiente: analizar el contenido de `auth.log` y registrar el marcador del R5.)*

## 3. Línea de tiempo del ataque

| Hora (UTC) | Evento | Evidencia (archivo:línea) |
|---|---|---|
| 02:14 | Escaneo/enumeración desde 185.220.101.42 | access.log |
| | ... | |

## 4. Indicadores de compromiso (IOCs)

| Tipo | Valor | Dónde apareció |
|---|---|---|
| IP atacante | | |
| IP/puerto C2 | | |
| Archivo malicioso | | |
| Usuario backdoor | | |
| Persistencia | | |

## 5. Alcance del daño
*(¿Qué datos se exfiltraron? ¿Dejó persistencia? ¿El atacante sigue con acceso?)*

## 6. Contención y erradicación (recomendaciones)
*(Qué haría el equipo de respuesta AHORA: cerrar el vector, matar procesos, rotar
credenciales, remover persistencia, bloquear IOCs.)*

## 7. Preguntas de análisis (P1–P5)

### P1
### P2
### P3
### P4
### P5

## 8. Captura de `./ctf status 11`
*(pegá acá la salida, o adjuntá `status.png` en esta carpeta.)*
