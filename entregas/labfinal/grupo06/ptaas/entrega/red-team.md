# Red team del guard — A1 a A10

Alcance: solo el laboratorio del kit y las estructuras deterministas del
harness. No se ejecutó ninguna prueba contra un sistema real ni fuera de
`lab/`. Cada intento es un test en `tests/test_redteam_guard.py`.

- Commit con los tests en rojo: `98e85f4` (`red team · A1-A10: tests adversariales en rojo`).
- Commit con las correcciones: `1b9392e` (`003 · 2.2-2.5: parser de RoE, emisor de tokens y controles A1-A10 del guard`).
- Ambos commits vuelven a ser alcanzables desde la rama local; todavía no se hizo
  push. Se preservaron los hashes originales.
- Ese segundo commit también corrige dos errores de fixture del primer intento
  (dominio del token en A1 y literal IPv6 inválido en A3); se detectaron al
  correr los tests, no ajustando el test para que pasara el código.

### Calidad de la evidencia roja

La primera corrida agrupada (`red-003-007-tests.txt`) terminó con dos errores de
recolección por módulos/símbolos todavía inexistentes (`harness.roe` y
`RedirectPolicy`); por sí sola no demuestra fallos de comportamiento de A1–A10.
La suite A1–A10 sí quedó en el commit de tests `98e85f4`, antes de la corrección
`1b9392e`, y las mutaciones M1–M9 documentan controles concretos que hacen fallar
tests al romperlos. Para los defectos adicionales de RoE descubiertos en la
revisión, el par funcional es `9a76691` (tests rojos) → `937a234` (correcciones):
se reprodujeron 6 fallos de comportamiento y, por separado, 1 fallo de auditoría
en un worktree aislado. Ver `p2-review-tests-red.txt`.

| # | Intento | ¿Bypass real? | Test | Corrección |
|---|---|---|---|---|
| A1 | Hostname con mayúsculas, punto final o espacios | No: antes fallaba cerrado (rechazaba un destino autorizado); no era un bypass. El primer test además usó un dominio incompatible con su token | `test_a1_hostname_se_normaliza_antes_de_decidir` | Se normaliza con `strip().lower().rstrip(".")` en el Guard y `validate_target` |
| A2 | Sufijo engañoso (`evil-lab.example.test`) | No: ya estaba cubierto | `test_a2_sufijo_enganoso_se_bloquea` (4 casos) | Sin cambio de código; se extendió el test |
| A3 | IPv6 e IPv4 mapeadas a IPv6 | No: la forma mapeada se rechazaba al compararse con CIDR IPv4 (fallo cerrado), no abría el alcance | `test_a3_*` | `_as_ip` normaliza IPv4 mapeada; IPv6 nativa se compara con su CIDR |
| A4 | Hostname autorizado que resuelve fuera de alcance | Riesgo si no se configura un resolver: `resolver=None` sigue siendo el valor por defecto | `test_a4_*` (3 casos) | Con `Guard(resolver=...)`, revalida todas las IPs y falla cerrado; el runtime debe inyectarlo |
| A5 | Redirección HTTP a otro host | No evaluable end-to-end aún: no hay adaptador HTTP; solo existe la política | `test_a5_*` | `RedirectPolicy` valida host/esquema/credenciales; queda pendiente integrarla en el adaptador HTTP de 004 |
| A6 | Token reutilizado en otra fase o engagement | Fase siempre bloqueada; engagement solo se liga si se configura `engagement_id` en el Guard | `test_a6_*` (2 casos) | `Guard(engagement_id=...)` bloquea tokens ajenos y registra `BLOCKED`; configuración obligatoria en el runtime |
| A7 | Ventana con zonas horarias distintas | No era un bypass del Guard existente; era una capacidad faltante del parser de RoE | `test_a7_*` (2 casos) | El parser compara instantes en UTC y rechaza ventanas invertidas |
| A8 | CIDR demasiado amplio (`/8`, `0.0.0.0/0`) | No era un bypass del Guard existente; era una capacidad faltante del parser de RoE | `test_a8_cidr_amplio_o_publico_se_rechaza` (5 casos) | `roe._red` exige prefijo mínimo /24 (v4) o /64 (v6) y subred de `targets.lab_only_cidrs` |
| A9 | Argumentos inyectados por target o `parameters` | Parcial: se valida `target` y existe un validador de parámetros, pero no hay call sites que lo usen en adaptadores | `test_a9_*` (11 casos) | `validate_parameters` rechaza valores peligrosos; integrarlo antes de construir argv queda a cargo de los adaptadores consumidores |
| A10 | Escritura concurrente en la bitácora | **Sí bajo interleaving**: sin lock, dos hilos pueden tomar el mismo `prev` | `test_a10_escritura_concurrente_conserva_la_cadena` | `AuditLog.record_decision` serializa lectura de `prev` + append con un lock |

## Evidencia de los bypass

- M1, M3, M4, M5, M7 y M8 de `entrega/mutaciones.md` muestran tests fallando al
  desactivar controles de alcance, CIDR, engagement, DNS, parámetros y bitácora.
- Los A1–A10 quedaron en commits separados de pruebas/correcciones, pero la
  primera corrida agrupada falló durante la recolección (véase la nota anterior);
  no se debe presentar esa salida como diez fallos funcionales independientes.
- A4 y A5 no se pueden probar contra el laboratorio todavía porque el adaptador
  HTTP es del change 004. Se probaron con resolver y política inyectados, que es
  el punto de control que el adaptador deberá usar.
- A10 se probó con 10 hilos × 25 registros. El test de estrés no siempre falla
  por scheduling; la mutación M8 (sin lock + pausa de 1 ms) reproduce la
  bifurcación de forma determinista.

## Intentos adicionales sobre el catálogo de validación (P5, change 006)

| # | Intento | ¿Bypass real? | Test | Corrección |
|---|---|---|---|---|
| B1 | Cambiar el host de la verificación por `path` (`//example.com/`, `http://example.com/`) | **Sí en el kit original**: `run_parametrized` solo controlaba largo y saltos de línea, así que un `path` así podía apuntar la solicitud a otro host | `test_path_que_cambia_el_objetivo_se_rechaza` | `_check_target_params`: `path` debe empezar con una sola `/`, sin esquema, host, query ni fragmento |
| B2 | Recorrido de rutas por `path` (`/../../etc/passwd`) | Sí en el kit original | `test_path_que_cambia_el_objetivo_se_rechaza` | Se rechazan los segmentos `..` |
| B3 | Inyectar parámetros de query por `param_name` (`q&admin=1`, `q=1`, `q#x`) | Sí en el kit original | `test_param_name_con_caracteres_especiales_se_rechaza` | `param_name` debe ser un identificador simple |
| B4 | Registrar una entrada del catálogo aprobada por un agente (`approved_by: security-reviewer`) | Sí en el kit original: solo se exigía que el campo no estuviera vacío | `test_entrada_aprobada_por_un_agente_se_rechaza` | `validate_entries` rechaza los nombres de `AGENT_APPROVERS` |

- Commit con los tests en rojo: `cfdd3a0` (`006 · 2.1: tests que fallan — sandbox, loop C, CLI y parámetros del catálogo`).
- Commit con las correcciones: `77bc330` (`006 · 2.3: límites del sandbox en profiles.yaml y controles de parámetros y aprobadores del catálogo`).
- Mutaciones M10 a M12 en `entrega/mutaciones.md`.
- B4 es una barrera por nombre: no impide que alguien escriba un nombre de
  persona falso. La aprobación real sigue dependiendo del proceso de revisión
  del change.

## Lo que no se hizo

- No se atacó ningún host fuera del laboratorio.
- No se generaron exploits ni se amplió el catálogo de PoCs.
- No se aprobó ningún gate HITL.
- La decisión de si cada bypass es "real" y si la corrección alcanza queda
  pendiente de revisión humana (P2 + otro integrante), según la sección 9 del
  plan.
