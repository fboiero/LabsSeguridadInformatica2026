# Loop agéntico y sandbox defensivo

El enunciado docente indica **DVWA o Juice Shop**. Este perfil usa tarjetas
sintéticas etiquetadas para cualquiera de los dos, no una conexión al laboratorio.
No ejecuta el adaptador activo anterior ni acredita que el curso acepte esta
sustitución. No implementa el `Sender` del kit.

El agente recibe el inventario y elige si pedir otra tarjeta, finalizar o escalar.
Una nueva tarjeta cambia el estado que recibe en la siguiente vuelta; una
referencia repetida detiene el loop, una inválida se rechaza y el coordinador
impone hasta tres rondas. Toda salida queda pendiente de revisión humana.
El modelo no tiene herramientas y solo recibe etiquetas cerradas. Sin `--live`
se usa un fixture explícito; con `--live` se solicita Sol y no hay fallback.

```powershell
.\.venv\Scripts\python.exe -B -m runtime.review_loop review --lab dvwa --live --output runs/dvwa-review.json
.\.venv\Scripts\python.exe -B -m runtime.review_loop validate runs/dvwa-review.json --output runs/dvwa-pending.json
```

El segundo comando no inicia Docker si no se indica aprobación. Tras revisar
el caso, una persona puede pasar su digest `approval_sha256` con
`--approve-sha256` y un destino nuevo. El digest vincula los bytes canónicos del
caso y su identificador único; no prueba identidad del aprobador. La única
comprobación del catálogo es `document_consistency_v1`, no un PoC.

El contenedor usa imagen fijada, sin red, sin montajes, sin privilegios y con
filesystem de solo lectura. El worker constata que solo existe loopback y no hay
rutas externas IPv4. Docker usa `--rm` y el coordinador comprueba que el nombre
del contenedor ya no aparece en `docker ps -a`; si no se puede comprobar, no
emite un recibo de éxito. El JSON de recibo no acredita explo­tabilidad.
