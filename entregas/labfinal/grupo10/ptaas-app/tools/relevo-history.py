"""Abre el historial local de Relevo sin iniciar el panel operativo."""

import argparse
import re
import sqlite3
import webbrowser
from contextlib import closing
from html import escape
from pathlib import Path
from tempfile import NamedTemporaryFile

ROOT = Path(__file__).resolve().parents[1]
LOCAL_DB = ROOT / "runs" / "relevo.sqlite"
PREVIOUS_DB = ROOT.parents[2] / "final" / "grupo10" / "ptaas" / "runs" / "relevo.sqlite"
NODES = (
    ("Coordinador", "center", "◎", "50%", "48%"),
    ("Inventario", "inventory", "▣", "20%", "21%"),
    ("Correlación", "correlation", "⌕", "80%", "21%"),
    ("Validación", "validation", "◇", "17%", "62%"),
    ("Redacción", "reporting", "✎", "83%", "62%"),
    ("Vos", "human", "☻", "50%", "77%"),
)


def board(role: str) -> str:
    parts = ['<div class="field" aria-label="Mapa de participantes">']
    for name, position, icon, left, top in NODES:
        active = " active" if name == role else ""
        parts.append(
            f'<div class="node {position}{active}"><div class="avatar">{icon}</div>'
            f'<span>{name}</span></div>'
        )
        if active:
            parts.append(f'<div class="ball" style="left:{left};top:{top}" aria-hidden="true">⚽</div>')
    return "".join([*parts, "</div>"])


def render_history(path: Path) -> str:
    template = (ROOT / "ui" / "relevo.html").read_text(encoding="utf-8")
    styles = re.findall(r"<style>.*?</style>", template, re.DOTALL)
    page = [
        '<!doctype html><html lang="es"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<title>Relevo · Sala de agentes (historial)</title>',
        *styles,
        '<style>details{margin:1rem 0}summary{cursor:pointer;padding:.5rem}'
        '.layout{margin-top:.5rem}.event p,.draft{white-space:pre-wrap;overflow-wrap:anywhere}'
        '@media(max-width:950px){.layout{grid-template-columns:1fr}}</style>',
        '</head><body><header><h1>◉ RELEVO <small>/ Sala de agentes</small></h1>'
        '<span class="tag">● Solo lectura</span></header><main>',
        '<p class="notice">Últimas 50 sesiones guardadas. Abrí una sesión para ver la pizarra, '
        'la línea de tiempo y el borrador, si existe.</p>',
    ]
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        sessions = db.execute(
            "SELECT s.id, s.case_id, s.state, t.role, COALESCE(NULLIF(c.summary, ''), w.draft, '') "
            "FROM sessions s LEFT JOIN live_turns t ON t.session_id = s.id "
            "LEFT JOIN coverage_reviews c ON c.session_id = s.id "
            "LEFT JOIN review_work w ON w.session_id = s.id ORDER BY s.id DESC LIMIT 50"
        ).fetchall()
        if not sessions:
            page.append("<p>No hay sesiones guardadas.</p>")
        for index, (session_id, case_id, state, role, draft) in enumerate(sessions):
            case = "Juice Shop" if case_id == "juice" else case_id
            label = escape(f"#{session_id} · {case} · {state}")
            role = "Vos" if state == "PENDING_HITL" else role or "Coordinador"
            opened = " open" if index == 0 else ""
            page.append(f'<details name="session"{opened}><summary>{label}</summary>')
            page.append('<div class="layout"><section class="card"><h2>Pizarra de turnos</h2>')
            page.append(f'<div class="status">{escape(state)} · {escape(role)}</div>')
            page.append(board(role))
            if draft:
                page.append(f'<h3>Borrador guardado</h3><p class="notice draft">{escape(draft)}</p>')
            page.append('</section><aside><section class="card"><h2>Línea de tiempo</h2><div class="timeline">')
            for actor, kind, message in db.execute(
                "SELECT actor, kind, message FROM events WHERE session_id = ? ORDER BY id",
                (session_id,),
            ):
                page.append(
                    f'<div class="event"><strong>{escape(f"{actor} · {kind}")}</strong>'
                    f'<p>{escape(message)}</p></div>'
                )
            page.append("</div></section></aside></div></details>")
    page.append("</main></body></html>")
    return "\n".join(page)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=LOCAL_DB if LOCAL_DB.is_file() else PREVIOUS_DB)
    args = parser.parse_args()
    if not args.db.is_file():
        parser.error(f"No se encontró la base: {args.db}. Indicá la ruta con --db.")
    try:
        html = render_history(args.db)
    except sqlite3.Error as exc:
        parser.exit(1, f"No se pudo leer el historial: {exc}\n")
    with NamedTemporaryFile(
        mode="w", encoding="utf-8", prefix="relevo-historial-", suffix=".html", delete=False
    ) as report:
        report.write(html)
    path = Path(report.name)
    print(f"Visor generado: {path}", flush=True)
    if not webbrowser.open(path.as_uri()):
        print("Abrí el archivo anterior en tu navegador.")


if __name__ == "__main__":
    main()
