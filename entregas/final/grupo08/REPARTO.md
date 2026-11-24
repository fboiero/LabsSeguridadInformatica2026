# Reparto del Práctico Final — Grupo 08

El engagement tiene **4 hitos encadenados (R1→R4)** y un **informe** con 6 secciones.
Lo dividimos en **5 partes**. Cada integrante toma una, y por cada una:

1. ejecuta/entiende un tramo de la cadena de ataque,
2. redacta la parte del informe que le corresponde, y
3. hace **su propio commit** a nombre real (sin co-author de Claude).

> La cadena es encadenada: conviene correr el entorno juntos (`./ctf lab final`,
> `make shell`) y repartir la **captura de evidencia + redacción**. Nadie cierra su
> sección sin la evidencia reproducible de su hito.

**Asignación:** la Parte 1 (R1) ya la hizo **Marco**. El resto queda **por definir**
entre los integrantes.

---

## Mapa rúbrica → partes

| Componente rúbrica | Pts | Parte(s) |
|---|---:|---|
| 4 hitos (flags R1–R4)              | 20 | Todas (1 hito c/u + ensamble) |
| Resumen ejecutivo                  | 15 | Parte 5 |
| Hallazgos técnicos (CVSS+evidencia)| 30 | Cada parte aporta su H-0x |
| Remediaciones                      | 20 | Cada parte aporta la de su H-0x |
| Narrativa y conclusión             | 10 | Parte 4 |
| Proceso — Git y colaboración       |  5 | 1 commit por integrante |

---

## Parte 1 — Recon + Enumeración (R1) · **hecha por Marco**
- **Hito:** R1 — encontrar el portal interno no linkeado.
- **Informe:** §0 Declaración de IA · §2 Alcance y metodología · **H-01**.
- **Estado:** completa, con evidencia en `evidencia/r1-*.txt`.

## Parte 2 — Explotación / Foothold (R2)
- **Hito:** R2 — entrar al portal sin credenciales válidas.
- **Informe:** **H-02** de la vulnerabilidad que da el foothold (SQLi en el login)
  con CVSS justificado + evidencia + impacto + remediación **de raíz** (consultas
  parametrizadas, no "validar del lado del cliente").
- **Evidencia:** PoC del foothold + flag R2.

## Parte 3 — Post-explotación / Secreto (R3)
- **Hito:** R3 — del acceso, conseguir un secreto que habilite más.
- **Informe:** **H-03** del hallazgo que expone el secreto (token/credencial en el
  backup de config) con CVSS + evidencia + impacto + remediación (no exponer backups,
  tokens no predecibles, secretos fuera del código).
- **Evidencia:** cómo se obtuvo el secreto + flag R3.

## Parte 4 — Impacto + Narrativa + Conclusión (R4)
- **Hito:** R4 — llegar a los "crown jewels": los datos de clientes.
- **Informe:** **H-04** del impacto final con CVSS + evidencia + impacto de negocio +
  remediación · §3 Narrativa del ataque (R1→R4 en prosa) · §5 Conclusión.
- **Evidencia:** demostración del impacto + flag R4.

## Parte 5 — Resumen ejecutivo + Ensamble + Anexo
- **Informe:** §1 Resumen ejecutivo (sin jerga, media carilla + tabla de severidades
  con el conteo real) · §6 Anexo (bitácora, capturas, salida de `./ctf status final`).
- **Ensamble:** ordenar hallazgos por severidad (críticos primero), numeración
  coherente H-01…H-04, revisión de estilo y consistencia.
- **Evidencia:** captura de `./ctf status final` con los 4 hitos.

---

## Checklist previo al PR
- [ ] 4 flags capturadas y `./ctf status final` 4/4 (captura en `evidencia/`).
- [ ] Cada hallazgo con CVSS **justificado** y evidencia que **reproduce**.
- [ ] Remediaciones que previenen de raíz (no mitigaciones cosméticas).
- [ ] §0 Declaración de IA completa (no declararla = causal de rechazo).
- [ ] Nada auditado fuera del host `phantomcorp` (Ley 26.388).
- [ ] 1 commit por integrante, a nombre real (sin co-author de Claude).
- [ ] PR desde el fork → `upstream/main`, rama `labfinal-grupo08`.
