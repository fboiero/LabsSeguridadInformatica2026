"""Reglas de parada de los loops agénticos (deterministas; el LLM propone, el harness decide)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LoopDecision:
    decision: str      # "continue" | "stop"
    reason: str


def decide_recon(iteration: int, new_assets: int, max_iterations: int) -> LoopDecision:
    """Loop A: parar si el grafo se estabilizó o se alcanzó el tope."""
    if iteration >= max_iterations:
        return LoopDecision("stop", "tope de iteraciones alcanzado")
    if new_assets == 0:
        return LoopDecision("stop", "grafo estabilizado")
    return LoopDecision("continue", f"{new_assets} activos nuevos")


def decide_detection(history_new_evidence: list[int], max_iterations: int,
                     resolved: bool = False) -> LoopDecision:
    """Loop B: parar si se resolvió, tras 2 iteraciones sin evidencia nueva o al tope."""
    if resolved:
        return LoopDecision("stop", "hallazgo resuelto")
    if len(history_new_evidence) >= max_iterations:
        return LoopDecision("stop", "tope de iteraciones alcanzado")
    if len(history_new_evidence) >= 2 and all(n == 0 for n in history_new_evidence[-2:]):
        return LoopDecision("stop", "sin ganancia de información")
    return LoopDecision("continue", "hay evidencia nueva o iteraciones disponibles")


def decide_validation(attempts: int, evidence_sufficient: bool, max_attempts: int) -> LoopDecision:
    """Loop C: parar con evidencia suficiente o intentos agotados."""
    if evidence_sufficient:
        return LoopDecision("stop", "evidencia suficiente")
    if attempts >= max_attempts:
        return LoopDecision("stop", "intentos agotados")
    return LoopDecision("continue", "evidencia insuficiente")


def run_recon(harness, token, seeds, graph, *, checkpoint=None, correlate=None):
    """Loop A determinista. `correlate` propone hosts, nunca invoca herramientas.

    Las aprobaciones pertenecen al Guard del llamador; esta función no las emite.
    Un checkpoint contabiliza una vuelta antes de actuar para no reiniciar el tope
    tras una interrupción. No cambia el estado del engagement de P1.
    """
    from harness.asset_graph import normalize_asset
    from harness.adapters.common import validate_target
    from harness.contracts import Action, Guard, KillSwitchEngaged, Phase, Result, ScopeViolation
    from harness.policy_loader import load_policy

    if graph.engagement_id != token.engagement_id:
        raise ValueError('grafo de otro engagement')
    max_iterations = load_policy()['limits']['max_loop_iterations']['recon']
    if type(max_iterations) is not int or max_iterations < 1:
        raise ValueError('tope RECON inválido')
    max_iterations = min(max_iterations, 5)

    def persist():
        if checkpoint is not None:
            graph.save(checkpoint)

    def record(name, target, result):
        entry = harness.audit.record('recon', Action(name, Phase.RECON), target, token, result)
        if isinstance(entry, dict) and entry.get('hash'):
            graph.evidence_refs.append(entry['hash'])

    def finish(status, reason):
        graph.status, graph.stop_reason = status, reason
        result = {'ABORTED': Result.ABORTED, 'PENDING_HITL': Result.PENDING_HITL,
                  'BLOCKED': Result.BLOCKED, 'ERROR': Result.BLOCKED}.get(status, Result.OK)
        record('recon.loop.' + reason, str(graph.iteration), result)
        persist()
        return graph

    def scope_host(host):
        host = validate_target(host)
        if not Guard._in_scope(host, token):
            if host not in graph.excluded:
                graph.excluded.append(host)
            record('recon.out_of_scope', host, Result.BLOCKED)
            return None
        return host

    def invoke(name, target):
        action = Action(name, Phase.RECON, requires_human_approval=name == 'httpx.probe')
        try:
            result = harness.invoke('recon', action, target, token)
        except KillSwitchEngaged:
            finish('ABORTED', 'kill switch')
            return None
        except ScopeViolation:
            finish('BLOCKED', 'autorización rechazada')
            return None
        if result.get('status') == 'PENDING_HITL':
            finish('PENDING_HITL', 'aprobación humana requerida')
            return None
        if name == 'subfinder.enum' and result.get('status') == 'UNAVAILABLE' and result.get('reason') == 'no_local_sources':
            record('recon.passive_unavailable', target, Result.BLOCKED)
            return {'status': 'UNAVAILABLE', 'assets': []}
        if result.get('status') == 'ERROR':
            record('recon.error.' + result.get('error', 'unknown'), target, Result.BLOCKED)
            if result.get('error') == 'schema':
                graph.schema_failures += 1
                if graph.schema_failures >= 2:
                    finish('PENDING_HITL', 'dos salidas inválidas')
                    return None
                return {'retry': True}
            finish('ERROR', 'error de herramienta')
            return None
        try:
            if result.get('status') != 'OK' or not isinstance(result.get('assets'), list):
                raise ValueError('schema inválido')
            result['assets'] = [normalize_asset(value) for value in result['assets']]
        except (ValueError, TypeError):
            graph.schema_failures += 1
            record('recon.error.schema', target, Result.BLOCKED)
            if graph.schema_failures >= 2:
                finish('PENDING_HITL', 'dos salidas inválidas')
                return None
            return {'retry': True}
        for redirect in result.get('blocked_redirects', []):
            # Solo el host, no rutas/query que pueden contener datos sensibles.
            from urllib.parse import urlsplit
            try:
                host = urlsplit(redirect).hostname or 'invalid'
            except ValueError:
                host = 'invalid'
            record('recon.redirect_blocked', host, Result.BLOCKED)
        return result

    if graph.status in {'ABORTED', 'STOPPED', 'PENDING_HITL'}:
        return graph
    if graph.iteration >= max_iterations:
        return finish('STOPPED', 'tope de iteraciones alcanzado')
    # Validar completamente las semillas antes de actuar.
    seeds = list(dict.fromkeys(validate_target(seed) for seed in (graph.frontier or seeds)))
    graph.frontier = seeds
    while graph.iteration < max_iterations:
        graph.iteration += 1
        graph.status, graph.stop_reason = 'RUNNING', ''
        persist()
        record('recon.iteration', str(graph.iteration), Result.OK)
        batch, retry = [], False
        for seed in seeds:
            host = scope_host(seed)
            if host is None:
                continue
            result = invoke('subfinder.enum', host)
            if result is None:
                return graph
            if result.get('retry'):
                retry = True
                break
            batch.extend(result['assets'])
            batch.append({'type': 'host', 'address': host, 'source_tool': 'scope.seed', 'technologies': []})
        if retry:
            persist()
            continue
        new_assets = 0
        active = []
        for item in batch:
            host = scope_host(item['address'])
            if host is not None:
                new_assets += int(graph.add(item))
                if host not in active:
                    active.append(host)
        for host in active:
            result = invoke('httpx.probe', host)
            if result is None:
                return graph
            if result.get('retry'):
                retry = True
                break
            for item in result['assets']:
                if scope_host(item['address']) is not None:
                    new_assets += int(graph.add(item))
        if retry:
            persist()
            continue
        graph.schema_failures = 0
        proposals = list(correlate(graph)) if correlate is not None else []
        # Validar propuestas sin ejecutar ni promover a hallazgos de vulnerabilidad.
        next_seeds = []
        for proposal in proposals:
            host = scope_host(proposal)
            if host is not None and host not in next_seeds:
                next_seeds.append(host)
        decision = decide_recon(graph.iteration, new_assets, max_iterations)
        if decision.decision == 'stop':
            return finish('STOPPED', decision.reason)
        if next_seeds:
            seeds = next_seeds
            graph.frontier = seeds
        persist()
    return finish('STOPPED', 'tope de iteraciones alcanzado')
