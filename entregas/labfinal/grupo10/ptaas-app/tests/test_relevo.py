import json
import sqlite3

import pytest

from runtime.relevo import Store, sandbox_state_file


@pytest.mark.parametrize('phase', ['support', 'document'])
def test_correlation_optional_context_survives_restart_without_queries(tmp_path, monkeypatch, phase):
    path = tmp_path / 'context.db'
    store = Store(path)
    session = store.start_live('juice', auto=True)['id']
    with sqlite3.connect(path) as db:
        db.execute("INSERT INTO coverage_reviews(session_id,snapshot,observation) VALUES(?,?,?)",
                   (session, '[]', 'CSP ausente; impacto no verificado'))
        db.execute("UPDATE live_turns SET role='Correlación' WHERE session_id=?", (session,))
        db.execute('UPDATE sessions SET state=? WHERE id=?',
                   ('DOCUMENT_REVIEW' if phase == 'document' else 'ACTIVE', session))
    monkeypatch.setattr('runtime.relevo.run_header_review', lambda *a: pytest.fail('no debe repetir consultas'))

    class Model:
        name = 'fixture'
        def __init__(self):
            self.requests = []
        def generate(self, prompt):
            request = json.loads(prompt)
            self.requests.append(request)
            if 'contexto_humano_no_verificado' not in request:
                return json.dumps({'texto': 'CSP ausente, impacto incierto.',
                                   'pregunta_humana': '¿Hay evidencia adicional de impacto?'})
            return json.dumps({'texto': 'Se mantiene como observación, sin impacto confirmado.',
                               'pregunta_humana': '¿Otra pregunta?'})

    model = Model()
    paused = store.advance(session, model)
    assert paused['state'] == 'AWAITING_CONTEXT' and paused['context_question']
    store = Store(path)
    assert store.get(session)['context_question'] == paused['context_question']
    resumed = store.correlation_answer(session, '')
    assert resumed['state'] == ('DOCUMENT_REVIEW' if phase == 'document' else 'ACTIVE')
    with pytest.raises(ValueError):
        store.correlation_answer(session, 'respuesta duplicada')
    result = store.advance(session, model)
    assert result['state'] == ('DOCUMENT_REVIEW' if phase == 'document' else 'ACTIVE')
    assert result['role'] == 'Redacción'
    assert model.requests[-1]['contexto_humano_no_verificado']['respuesta'] == 'No tengo contexto adicional.'
    assert any('sin impacto confirmado' in event['message'] for event in result['events'])


def test_correlation_can_continue_without_question(tmp_path):
    store = Store(tmp_path / 'no-question.db')
    session = store.start_live('juice')['id']
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO coverage_reviews(session_id,snapshot,observation) VALUES(?,?,?)", (session, '[]', ''))
        db.execute("UPDATE sessions SET state='DOCUMENT_REVIEW' WHERE id=?", (session,))
    class Model:
        def generate(self, prompt):
            return '{"texto":"Observación sin impacto confirmado."}'
    result = store.advance(session, Model())
    assert result['state'] == 'DOCUMENT_REVIEW' and result['role'] == 'Redacción'
    assert not result['context_question']


@pytest.mark.parametrize('outcome', ['approve', 'reject'])
def test_coverage_handoff(tmp_path, monkeypatch, outcome):
    path = tmp_path / 'coverage.db'
    store = Store(path)
    session = store.start_live('juice')['id']
    roles = []
    calls = []

    class Model:
        name = 'fixture'

        def generate(self, prompt):
            msg = json.loads(prompt)
            roles.append(msg['agent'])
            if msg['agent'] == 'asset_discovery':
                return '{"pregunta":"¿Hay CSP?"}'
            if msg['agent'] == 'validation':
                return json.dumps({'accion': next(iter(msg['catalogo_disponible'])), 'motivo': 'Siguiente control'})
            assert msg['cobertura']
            return '{"texto":"Revisar configuración."}'

    def check(check_id, receipt, *args):
        calls.append(check_id)
        return 'HTTP 200 · Content-Security-Policy: ausente'

    monkeypatch.setattr('runtime.relevo.run_header_review', check)
    model = Model()
    store.advance(session, model)
    gate = store.advance(session, model)
    first_check = gate['check']
    review = store.decide_check(session, gate['check'], outcome)
    while review['state'] == 'ACTIVE':
        gate = store.advance(session, model)
        review = store.decide_check(session, gate['check'], 'finish')
    assert review['state'] == 'DOCUMENT_REVIEW'
    assert sum(r['estado'] == 'Con resultado' for r in review['coverage']) == int(outcome == 'approve')
    store.advance(session, model)
    done = Store(path).advance(session, model)
    assert done['state'] == 'COMPLETED' and done['draft']
    assert roles[-2:] == ['correlation', 'reporting']
    assert calls == ([first_check] if outcome == 'approve' else [])
    with pytest.raises(ValueError):
        store.advance(session, model)


def test_session_sandbox_path_is_stable(tmp_path):
    store = Store(tmp_path / 'sandbox.db')
    session = store.start_live('juice')['id']
    assert sandbox_state_file(store.path, session).name == f'relevo-sandbox-{session}.json'


def test_invalid_next_proposal_explains_why_it_blocked(tmp_path):
    class InvalidModel:
        name = 'test'

        def generate(self, prompt):
            return '{"pregunta":"¿Qué sigue?"}' if 'asset_discovery' in prompt else '{"accion":"POC-HDR-001","motivo":"repetida"}'

    store = Store(tmp_path / 'invalid.db')
    session = store.start_live('juice')['id']
    store.advance(session, InvalidModel())
    gate = store.advance(session, InvalidModel())
    store.decide_check(session, gate['check'], 'reject')
    continued = store.advance(session, InvalidModel())
    assert continued['state'] == 'ACTIVE'
    assert any(event['actor'] == 'Correlación' for event in continued['events'])


def test_review_pauses_and_survives_restart(tmp_path):
    path = tmp_path / "relevo.sqlite"
    review = Store(path).start("juice")
    assert review["state"] == "PENDING_HITL" and review["decision"] is None
    store = Store(path)
    assert store.history()[0]["id"] == review["id"]
    assert store.respond(review["id"], "later")["state"] == "PENDING_HITL"
    result = store.respond(review["id"], "reject")
    assert result["state"] == "REVIEWED" and result["decision"] == "reject"
    with pytest.raises(ValueError):
        store.respond(review["id"], "include")


def test_changed_evidence_blocks_review(tmp_path, monkeypatch):
    store = Store(tmp_path / "relevo.sqlite")
    review = store.start("juice")
    monkeypatch.setattr("runtime.relevo.fingerprint", lambda _: "changed")
    with pytest.raises(ValueError, match="cambió"):
        store.respond(review["id"], "include")
    assert store.get(review["id"])["state"] == "PENDING_HITL"


def test_unknown_case_is_rejected(tmp_path):
    store = Store(tmp_path / "relevo.sqlite")
    with pytest.raises(ValueError):
        store.start("arbitrary")
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT count(*) FROM sessions").fetchone()[0] == 0


def test_live_agent_handoffs_and_human_pause(tmp_path):
    class Provider:
        name = "test"

        def __init__(self):
            self.answers = iter(['{"destino":"Correlación","motivo":"Revisar", "resultado":"Recibo leído"}',
                                 '{"destino":"Validación","motivo":"Cotejar", "resultado":"Revisar CSP"}',
                                 '{"destino":"Vos","motivo":"Decidir", "resultado":"El recibo indica CSP ausente"}',
                                 '{"destino":"Vos","motivo":"Entregar", "resultado":"El recibo indica CSP ausente en /"}'])

        def generate(self, prompt):
            return next(self.answers)

    store = Store(tmp_path / "relevo.sqlite")
    session = store.start_document("juice")
    provider = Provider()
    first = store.advance(session["id"], provider)
    assert first["state"] == "ACTIVE"
    assert any("Inventario a Correlación" in e["message"] for e in first["events"])
    assert store.advance(session["id"], provider)["role"] == "Validación"
    second = store.advance(session["id"], provider)
    assert second["state"] == "PENDING_HITL" and second["proposal"]
    assert store.respond(session["id"], "include")["state"] == "ACTIVE"
    result = store.advance(session["id"], provider)
    assert result["state"] == "COMPLETED" and result["draft"]


def test_correction_reopens_review_and_clears_proposal(tmp_path):
    class Provider:
        name = "test"

        def generate(self, prompt):
            return '{"destino":"Vos","motivo":"Revisar", "resultado":"Frase propuesta"}'

    store = Store(tmp_path / "relevo.sqlite")
    session = store.start_document("juice")
    store.advance(session["id"], Provider())
    paused = store.advance(session["id"], Provider())
    assert paused["state"] == "PENDING_HITL"
    corrected = store.respond(session["id"], "correct", "Aclarar que es un recibo")
    assert corrected["state"] == "ACTIVE" and corrected["role"] == "Correlación"
    assert corrected["proposal"] == ""
    assert any("Aclarar que es un recibo" in e["message"] for e in corrected["events"])


@pytest.mark.parametrize('accept', [True, False])
def test_new_session_gate(tmp_path, monkeypatch, accept):
    import json

    store = Store(tmp_path / 'panel.db')
    monkeypatch.setattr('runtime.relevo.fingerprint', lambda _: pytest.fail('leyó un recibo'))
    calls = []

    def check(check_id, receipt, *args):
        calls.append(check_id)
        return 'HTTP 200 · cabecera presente'

    monkeypatch.setattr('runtime.relevo.run_header_review', check)

    class Model:
        name = 'test'

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿La respuesta incluye CSP?'})
            if req['agent'] == 'validation':
                assert '¿La respuesta incluye CSP?' in req['contexto']
                return json.dumps({'accion': next(iter(req['catalogo_disponible'])), 'motivo': 'Revisar la política'})
            return json.dumps({'texto': 'Interpretación conservadora del recibo.'})

    session = store.start_live('juice')['id']
    store.advance(session, Model())
    gate = store.advance(session, Model())
    assert gate['state'] == 'AWAITING_CHECK' and not calls
    with pytest.raises(ValueError):
        store.respond(session, 'include')
    store.decide_check(session, gate['check'], 'approve' if accept else 'reject')
    assert calls == ([gate['check']] if accept else [])
    with pytest.raises(ValueError):
        store.decide_check(session, gate['check'], 'approve')
    seen = {gate['check']}
    step = store.get(session)
    while step['state'] != 'DOCUMENT_REVIEW':
        if step['state'] == 'ACTIVE':
            step = store.advance(session, Model())
        elif step['state'] == 'AWAITING_CHECK':
            assert step['check'] not in seen
            seen.add(step['check'])
            step = store.decide_check(session, step['check'], 'approve')
        else:
            raise AssertionError(step['state'])
    assert len(seen) == 15 and step['state'] == 'DOCUMENT_REVIEW'
    assert len(calls) == 14 + int(accept)
    assert sum(r['estado'] == 'Con resultado' for r in step['coverage']) == len(calls)


def test_agent_can_propose_new_path(tmp_path, monkeypatch):
    seen = {}

    def check(check_id, receipt, *args):
        seen['check'] = check_id
        seen['path'] = args[1]
        return 'HTTP 200 · métricas públicas'

    monkeypatch.setattr('runtime.relevo.run_header_review', check)

    class Model:
        name = 'test'

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Hay métricas expuestas?'})
            return json.dumps({'accion': 'POC-METRICS-001', 'motivo': 'Revisar métricas', 'ruta': '/metrics/custom'})

    store = Store(tmp_path / 'dynamic.db')
    session = store.start_live('juice')['id']
    store.advance(session, Model())
    gate = store.advance(session, Model())
    assert gate['check'] == 'POC-METRICS-001' and gate['path'] == '/metrics/custom'
    store.decide_check(session, gate['check'], 'approve')
    assert seen == {'check': 'POC-METRICS-001', 'path': '/metrics/custom'}


def test_agent_cannot_escape_authorized_scope(tmp_path):
    class Model:
        name = 'test'

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Hay métricas expuestas?'})
            return json.dumps({'accion': 'POC-METRICS-001', 'motivo': 'x', 'ruta': '//evil.test/metrics'})

    store = Store(tmp_path / 'escape.db')
    session = store.start_live('juice')['id']
    store.advance(session, Model())
    blocked = store.advance(session, Model())
    assert blocked['state'] == 'RETRY_TURN'
    assert 'path_invalid' in blocked['events'][-1]['message']


def test_auto_catalog_runs_without_per_check_gate(tmp_path, monkeypatch):
    calls = []

    def check(check_id, receipt, *args):
        calls.append((check_id, args[1]))
        return 'HTTP 200 · CSP ausente'

    monkeypatch.setattr('runtime.relevo.run_header_review', check)

    class Model:
        name = 'test'

        def __init__(self):
            self.validation_calls = 0

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Hay CSP?'})
            self.validation_calls += 1
            if self.validation_calls == 1:
                return json.dumps({'accion': 'POC-CSP-001', 'motivo': 'Revisar CSP'})
            return json.dumps({'concluir': True, 'motivo': 'La pregunta quedó respondida.'})

    store = Store(tmp_path / 'auto.db')
    session = store.start_live('juice', auto=True)['id']
    store.advance(session, Model())
    step = store.advance(session, Model())
    assert calls == [('POC-CSP-001', '/')]
    assert step['state'] == 'ACTIVE'
    assert any('Aprobación de sesión (catálogo)' in e['message'] for e in step['events'])
    correlation = store.advance(session, Model())
    assert correlation['state'] == 'ACTIVE' and correlation['role'] == 'Redacción'
    done = store.advance(session, Model())
    assert done['state'] == 'ACTIVE' and done['role'] == 'Inventario'
    assert any('siguiente objetivo' in e['message'] for e in done['events'])


def test_validation_receives_previous_results(tmp_path, monkeypatch):
    prompts = []

    def check(check_id, receipt, *args):
        return 'HTTP 200 · CSP ausente'

    monkeypatch.setattr('runtime.relevo.run_header_review', check)

    class Model:
        name = 'test'

        def __init__(self):
            self.validation_calls = 0

        def generate(self, prompt):
            req = json.loads(prompt)
            prompts.append(req)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Hay CSP?'})
            self.validation_calls += 1
            if self.validation_calls == 1:
                return json.dumps({'accion': 'POC-CSP-001', 'motivo': 'Revisar CSP'})
            return json.dumps({'concluir': True, 'motivo': 'Suficiente'})

    store = Store(tmp_path / 'context.db')
    session = store.start_live('juice', auto=True)['id']
    for _ in range(7):
        store.advance(session, Model())
    validation = [p for p in prompts if p['agent'] == 'validation']
    assert validation and any(
        row['id'] == 'POC-CSP-001' and 'CSP ausente' in row['observacion']
        for prompt in validation for row in prompt['resultados_previos'])


def test_correlation_accepts_tolerant_response(tmp_path):
    class Model:
        name = 'test'

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Hay CSP?'})
            if req['agent'] == 'validation':
                return json.dumps({'concluir': True, 'motivo': 'Suficiente'})
            if req['agent'] == 'correlation':
                return '```json\n{"resumen":"La cobertura muestra CSP ausente."}\n```'
            return json.dumps({'texto': 'Borrador de cierre.'})

    store = Store(tmp_path / 'corr.db')
    session = store.start_live('juice', auto=True)['id']
    store.advance(session, Model())
    store.advance(session, Model())
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE sessions SET state='DOCUMENT_REVIEW' WHERE id=?", (session,))
    correlated = store.advance(session, Model())
    assert correlated['state'] == 'DOCUMENT_REVIEW' and correlated['role'] == 'Redacción'
    final = store.advance(session, Model())
    assert final['state'] == 'COMPLETED' and final['draft'] == 'Borrador de cierre.'


def test_correlation_failure_records_reason(tmp_path):
    class Model:
        name = 'test'

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Hay CSP?'})
            if req['agent'] == 'validation':
                return json.dumps({'concluir': True, 'motivo': 'Suficiente'})
            return ''

    store = Store(tmp_path / 'corr-fail.db')
    session = store.start_live('juice', auto=True)['id']
    store.advance(session, Model())
    store.advance(session, Model())
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE sessions SET state='DOCUMENT_REVIEW' WHERE id=?", (session,))
    blocked = store.advance(session, Model())
    assert blocked['state'] == 'RETRY_REVIEW'
    assert 'Falló la revisión documental' in blocked['events'][-1]['message']
    assert 'texto_invalido' in blocked['events'][-1]['message']


def test_retry_review_preserves_coverage(tmp_path):
    store = Store(tmp_path / 'retry.db')
    with sqlite3.connect(store.path) as db:
        cursor = db.execute("INSERT INTO sessions(case_id,fingerprint,state,created) VALUES('juice','', 'RETRY_REVIEW', 0)")
        session = int(cursor.lastrowid)
        db.execute("INSERT INTO live_turns(session_id,role) VALUES(?, 'Correlación')", (session,))
        db.execute("INSERT INTO coverage_reviews(session_id,snapshot,observation) VALUES(?,?,?)",
                   (session, '[{"id":"POC-CSP-001","estado":"Con resultado"}]', 'CSP ausente'))
    resumed = store.retry(session)
    assert resumed['state'] == 'DOCUMENT_REVIEW'
    assert resumed['coverage'][0]['estado'] == 'Con resultado'
    assert 'no se repiten consultas' in resumed['events'][-1]['message']

def test_active_check_is_blocked_without_session_authorization(tmp_path):
    store = Store(tmp_path / 'active-blocked.db')
    session = store.start_live('juice', auto=True)['id']
    with pytest.raises(ValueError):
        store.decide_check(session, 'PROPOSAL-AUTH-SQLI-001', 'approve')
    with sqlite3.connect(store.path) as db:
        db.execute("INSERT INTO coverage_reviews(session_id,snapshot,observation) VALUES(?,?,?)", (session, '[]', ''))
        db.execute("UPDATE fresh_reviews SET action='PROPOSAL-AUTH-SQLI-001', path='/rest/user/login' WHERE session_id=?", (session,))
        db.execute("UPDATE sessions SET state='AWAITING_CHECK' WHERE id=?", (session,))
    with pytest.raises(ValueError):
        store.decide_check(session, 'PROPOSAL-AUTH-SQLI-001', 'approve')


def test_active_check_needs_per_attempt_gate_even_in_auto_mode(tmp_path, monkeypatch):
    calls = []

    def review(check, receipt, *args):
        calls.append((check, args[-1] if args else None))
        return 'POST /rest/user/login · HTTP 200 · sesión emitida · pendiente de docente'

    monkeypatch.setattr('runtime.relevo.run_header_review', review)

    class Model:
        name = 'test'

        def __init__(self):
            self.validation_calls = 0

        def generate(self, prompt):
            req = json.loads(prompt)
            if req['agent'] == 'asset_discovery':
                return json.dumps({'pregunta': '¿Se puede omitir el login?'})
            self.validation_calls += 1
            return json.dumps({'accion': 'PROPOSAL-AUTH-SQLI-001', 'motivo': 'Probar el login del laboratorio'})

    store = Store(tmp_path / 'active-auto.db')
    session = store.start_live('juice', auto=True, active=True)['id']
    store.advance(session, Model())
    gate = store.advance(session, Model())
    assert gate['state'] == 'AWAITING_CHECK' and gate['check'] == 'PROPOSAL-AUTH-SQLI-001'
    assert calls == []
    done = store.decide_check(session, gate['check'], 'approve')
    assert calls == [('PROPOSAL-AUTH-SQLI-001', True)]
    assert any('activa: requiere aprobación por intento' in e['message'] for e in done['events'])
    assert any('pendiente de docente' in e['message'] for e in done['events'])
    assert any('autorización de sesión' == e['kind'] for e in done['events'])

def test_queue_active_requires_authorization_and_uses_fixed_path(tmp_path):
    store = Store(tmp_path / 'queue.db')
    blocked = store.start_live('juice')['id']
    with pytest.raises(ValueError):
        store.queue_active(blocked)

    session = store.start_live('juice', active=True)['id']
    queued = store.queue_active(session)
    assert queued['state'] == 'AWAITING_CHECK'
    assert queued['check'] in {'PROPOSAL-AUTH-SQLI-001', 'PROPOSAL-SQLI-SEARCH-001'}
    assert any('aprobación por intento' in e['message'] for e in queued['events'])
