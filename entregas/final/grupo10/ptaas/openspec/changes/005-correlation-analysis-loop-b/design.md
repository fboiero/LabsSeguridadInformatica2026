# Diseño

NVD y EPSS son snapshots locales: una ausencia produce `None`, nunca un dato
inventado. Los templates permitidos están en `templates/allowlist` y el scanner
rechaza cualquier otro ID o target. El loop B conserva el conjunto de IDs
observados y termina por resolución, falta de progreso o presupuesto.
