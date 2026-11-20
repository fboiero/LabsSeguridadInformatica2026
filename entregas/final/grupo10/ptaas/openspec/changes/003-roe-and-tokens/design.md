# Diseño 003 — Autorización de la demo inerte

El RoE YAML se toma de un archivo local acotado, no del modelo. UTC explícito,
dominios exactos `.lab.test` o redes RFC1918 canónicas, sin comodines, alias YAML
ni valores duplicados. El consentimiento para la demo inerte se obtiene fuera
del archivo. El TTL máximo está en código y nunca excede el fin del RoE.

El emisor conserva en memoria un token por fase. El Guard comprueba identidad
del objeto contra el emisor además de alcance, fase y vigencia. Esto separa los
datos del modelo de la autorización; no es autenticación entre procesos ni
resiste código Python hostil en el mismo proceso. Reiniciar invalida la sesión.
La emisión es para una sola fase; renovar reemplaza la autorización anterior.
El checkpoint expone solo `fixture.observe`, un contador sin E/S de red. El
modo sin emisor se conserva solo por compatibilidad con los tests del núcleo;
ambas CLI sintéticas activan la comprobación del emisor.
