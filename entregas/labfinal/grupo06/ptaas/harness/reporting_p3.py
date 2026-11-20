"""007 2.3/2.4: validación CVSS/EPSS y presentación PTES sin modificar reporting de P5.

Métricas: https://www.first.org/cvss/v4.0/specification-document (sección 7).
La API devuelve el mismo contenedor que reporting.render_report y conserva deliver.
"""
from __future__ import annotations

import html
import math
from typing import Any

from harness.reporting import Finding, MissingField, render_report as base_report

BASE = {'AV': 'NALP', 'AC': 'LH', 'AT': 'NP', 'PR': 'NLH', 'UI': 'NPA',
        'VC': 'HLN', 'VI': 'HLN', 'VA': 'HLN', 'SC': 'HLN', 'SI': 'HLN', 'SA': 'HLN'}
METRICS = {**{k: set(v) for k, v in BASE.items()},
           **{'M' + k: set(v + 'X' + ('S' if k in {'SI', 'SA'} else '')) for k, v in BASE.items()},
           'E': set('XAPU'), 'CR': set('XHML'), 'IR': set('XHML'), 'AR': set('XHML'),
           'S': set('XNP'), 'AU': set('XNY'), 'R': set('XAUI'), 'V': set('XDC'),
           'RE': set('XLMH'), 'U': {'X', 'Clear', 'Green', 'Amber', 'Red'}}


def validate_cvss4(vector: str) -> str:
    if not isinstance(vector, str) or not vector.startswith('CVSS:4.0/'):
        raise MissingField('CVSS: se requiere versión 4.0')
    seen = set()
    for component in vector.split('/')[1:]:
        parts = component.split(':')
        if len(parts) != 2:
            raise MissingField('CVSS: segmento inválido')
        key, value = parts
        if key in seen or key not in METRICS or value not in METRICS[key]:
            raise MissingField('CVSS: métrica duplicada, desconocida o valor inválido')
        seen.add(key)
    if not set(BASE).issubset(seen):
        raise MissingField('CVSS: falta métrica base')
    return vector


def _epss(value: float | None) -> str:
    if value is None:
        return 'unknown'
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise MissingField('EPSS: probabilidad debe estar entre 0 y 1')
    return f'{value * 100:g}%'


def _text(value: Any) -> str:
    # Los campos del objetivo se presentan como texto, nunca como HTML o enlaces activos.
    text = html.escape(str(value), quote=True).replace('\n', ' ').replace('\r', ' ')
    for char in ('\\', '`', '*', '_', '[', ']', '#'):
        text = text.replace(char, '\\' + char)
    return text


def render_report(engagement_id: str, findings: list[Finding], *,
                  scope: dict[str, Any] | None = None) -> dict[str, Any]:
    for finding in findings:
        validate_cvss4(finding.cvss_v4_vector)
        _epss(finding.epss)
        if finding.validation_status not in {'validated', 'not_validated'}:
            raise MissingField('estado de validación inválido')
    # Preservar los requisitos CWE/remediación y el contenedor del componente P5.
    # La regex heredada exige orden canónico: validar una copia con las bases ordenadas.
    from dataclasses import replace
    canonical = []
    for finding in findings:
        values = dict(part.split(':') for part in finding.cvss_v4_vector.split('/')[1:])
        ordered = 'CVSS:4.0/' + '/'.join(k + ':' + values[k] for k in BASE)
        ordered += ''.join('/' + k + ':' + v for k, v in values.items() if k not in BASE)
        canonical.append(replace(finding, cvss_v4_vector=ordered))
    report = base_report(engagement_id, canonical)
    scope = scope or {}
    validated = sum(f.validation_status == 'validated' for f in findings)
    lines = [f'# Informe de pentest — {_text(engagement_id)}', '', '## Resumen ejecutivo',
             f'Se documentan {len(findings)} hallazgos: {validated} validados en sandbox y '
             f'{len(findings) - validated} no validados, según los registros suministrados.',
             'Este inventario no demuestra ausencia de vulnerabilidades fuera de la evidencia aportada.',
             '', '## Alcance y RoE']
    for key, label in [('assets', 'Activos'), ('window', 'Ventana'), ('exclusions', 'Exclusiones'), ('roe_ref', 'Referencia RoE')]:
        lines.append(f'- {label}: {_text(scope.get(key, "unknown"))}')
    lines += ['', '## Metodología', 'Estructura de presentación PTES §7. La cobertura ejecutada es la de las referencias aportadas; '
              'la estructura no acredita por sí sola ejecución completa de PTES, NIST u OWASP.',
              '', '## Hallazgos priorizados', 'Orden: EPSS conocido descendente; unknown al final. No se infiere puntaje CVSS.']
    ordered_findings = sorted(findings, key=lambda f: (f.epss is None, -(f.epss or 0), f.id))
    for f in ordered_findings:
        status = 'validado en sandbox' if f.validation_status == 'validated' else 'no validado'
        lines += [f'### {_text(f.id)} — {_text(f.title)}', f'- Activo: {_text(f.asset)}',
                  f'- {_text(f.cwe)} · {f.cvss_v4_vector} · EPSS: {_epss(f.epss)}',
                  '- Puntaje CVSS: unknown (no aportado por el contrato Finding)',
                  f'- Estado: {status}', f'- Remediación: {_text(f.remediation)}',
                  '- Evidencia: ' + (', '.join(_text(r) for r in f.evidence_refs) or 'unknown'), '']
    lines += ['## Anexos', '- Inventario de activos: ' + (', '.join(sorted({_text(f.asset) for f in findings})) or 'unknown'),
              '- Referencias de bitácora: ' + (', '.join(sorted({_text(r) for f in findings for r in f.evidence_refs})) or 'unknown')]
    report['markdown'] = '\n'.join(lines)
    return report
