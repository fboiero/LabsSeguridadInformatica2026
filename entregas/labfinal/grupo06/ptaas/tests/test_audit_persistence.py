"""Change 002 · contrato de la bitácora: cadena, datos sensibles y ausencia de borrado."""
import pytest

from harness.audit import GENESIS, Entry, EventoSensible, InMemoryAuditStore, verificar_cadena


def _llenar(store: InMemoryAuditStore, n: int = 3) -> None:
    for i in range(n):
        store.append({"engagement": "eng-1", "action": f"a{i}", "target": "10.0.0.5",
                      "result": "OK"})


def test_primer_registro_usa_genesis_y_cadena_integra():
    store = InMemoryAuditStore()
    _llenar(store)
    primero = store.entries()[0]
    assert primero.prev == GENESIS
    assert store.verify().ok


def test_alterar_un_campo_intermedio_hace_fallar_la_verificacion():
    store = InMemoryAuditStore()
    _llenar(store)
    lista = store.entries()
    viejo = lista[1]
    lista[1] = Entry(viejo.seq, viejo.prev, viejo.hash, {**viejo.data, "target": "10.9.9.9"})
    resultado = verificar_cadena(lista)
    assert not resultado.ok
    assert resultado.indice == 1


def test_borrar_un_registro_intermedio_hace_fallar_la_verificacion():
    store = InMemoryAuditStore()
    _llenar(store, 4)
    lista = store.entries()
    del lista[1]
    assert not verificar_cadena(lista).ok


def test_evento_con_credencial_se_rechaza_y_no_deja_registro():
    store = InMemoryAuditStore()
    with pytest.raises(EventoSensible):
        store.append({"engagement": "eng-1", "action": "login", "password": "x"})
    assert store.entries() == []


def test_el_contrato_no_expone_operaciones_de_modificacion_ni_borrado():
    for prohibida in ("update", "delete", "remove", "set", "clear"):
        assert not hasattr(InMemoryAuditStore, prohibida)


# ==== Change 002 · persistencia SQLite (P5, sobre el diseño y el delta de P1) =========
#
# Delta: openspec/changes/002-audit-persistence/specs/audit-log/spec.md
# Diseño: openspec/changes/002-audit-persistence/design.md
# Para alterar o borrar filas "por fuera de la API", los tests abren el archivo con
# sqlite3 y quitan los triggers: es lo que haría alguien con acceso al disco, y es
# justamente lo que la cadena tiene que detectar.

import importlib
import json
import sqlite3
import threading


def api(module):
    return importlib.import_module("harness." + module)


def evento(i, eng="eng-1"):
    return {"engagement": eng, "agent": "recon", "action": f"httpx.probe#{i}",
            "target": "dvwa.lab.test", "phase": "recon", "result": "OK"}


def abrir(path, eng="eng-1"):
    return api("audit").SQLiteAuditStore(path, eng)


def escribir(path, n=3, eng="eng-1"):
    store = abrir(path, eng)
    for i in range(n):
        store.append(evento(i, eng))
    store.close()


def sql_directo(path, *sentencias):
    """Modifica el archivo saltándose la API y los triggers (atacante con acceso al disco)."""
    con = sqlite3.connect(path)
    con.execute("DROP TRIGGER IF EXISTS registros_no_update")
    con.execute("DROP TRIGGER IF EXISTS registros_no_delete")
    for s in sentencias:
        con.execute(s)
    con.commit()
    con.close()


def test_registros_recuperados_tras_reinicio(tmp_path):
    db = tmp_path / "eng-1.db"
    escribir(db, 3)
    store = abrir(db)                      # "reinicio": instancia y conexión nuevas
    entradas = store.entries()
    assert [e.data["action"] for e in entradas] == ["httpx.probe#0", "httpx.probe#1",
                                                   "httpx.probe#2"]
    assert entradas[0].prev == GENESIS
    assert store.verify().ok


def test_archivo_de_otro_engagement_rechaza_el_evento(tmp_path):
    audit = api("audit")
    db = tmp_path / "eng-a.db"
    escribir(db, 2, eng="eng-a")
    store = abrir(db, "eng-a")
    with pytest.raises(audit.EngagementMismatch):
        store.append(evento(9, "eng-b"))
    assert len(store.entries()) == 2


def test_abrir_un_archivo_de_otro_engagement_falla(tmp_path):
    audit = api("audit")
    db = tmp_path / "eng-a.db"
    escribir(db, 1, eng="eng-a")
    with pytest.raises(audit.EngagementMismatch):
        abrir(db, "eng-b")


def test_cadena_corrupta_al_abrir_no_acepta_registros(tmp_path):
    audit = api("audit")
    db = tmp_path / "eng-1.db"
    escribir(db, 3)
    sql_directo(db, "UPDATE registros SET data = replace(data, 'dvwa', 'otro') WHERE seq = 2")
    store = abrir(db)
    resultado = store.verify()
    assert not resultado.ok and resultado.indice == 1
    with pytest.raises(audit.AuditCorrupt):
        store.append(evento(3))
    assert len(store.entries()) == 3


def test_cli_verify_con_fila_borrada_falla_e_informa_el_indice(tmp_path, capsys):
    db = tmp_path / "eng-1.db"
    escribir(db, 4)
    sql_directo(db, "DELETE FROM registros WHERE seq = 2")
    rc = api("audit").main(["verify", str(db)])
    salida = json.loads(capsys.readouterr().out)
    assert rc != 0
    assert salida["ok"] is False and salida["indice"] == 1


def test_cli_verify_archivo_integro(tmp_path, capsys):
    db = tmp_path / "eng-1.db"
    escribir(db, 3)
    rc = api("audit").main(["verify", str(db)])
    salida = json.loads(capsys.readouterr().out)
    assert rc == 0 and salida["ok"] is True
    assert salida["count"] == 3 and len(salida["head"]) == 64


def test_cli_verify_detecta_alteracion(tmp_path, capsys):
    db = tmp_path / "eng-1.db"
    escribir(db, 3)
    sql_directo(db, "UPDATE registros SET data = replace(data, 'OK', 'BLOCKED') WHERE seq = 3")
    assert api("audit").main(["verify", str(db)]) != 0


def test_update_directo_es_rechazado_por_la_base(tmp_path):
    db = tmp_path / "eng-1.db"
    escribir(db, 2)
    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("UPDATE registros SET data = '{}' WHERE seq = 1")
    con.close()
    assert abrir(db).verify().ok


def test_delete_directo_es_rechazado_por_la_base(tmp_path):
    db = tmp_path / "eng-1.db"
    escribir(db, 2)
    con = sqlite3.connect(db)
    with pytest.raises(sqlite3.DatabaseError):
        con.execute("DELETE FROM registros WHERE seq = 1")
    con.close()
    assert len(abrir(db).entries()) == 2


def test_la_api_sqlite_no_ofrece_borrado(tmp_path):
    store_cls = api("audit").SQLiteAuditStore
    for prohibida in ("update", "delete", "remove", "set", "clear", "truncate"):
        assert not hasattr(store_cls, prohibida)


def test_escrituras_concurrentes_no_bifurcan_la_cadena(tmp_path):
    db = tmp_path / "eng-1.db"
    abrir(db).close()
    errores = []

    def escritor(nombre):
        try:
            store = abrir(db)              # conexión propia, como otro proceso
            for i in range(40):
                store.append({**evento(i), "agent": nombre})
            store.close()
        except Exception as exc:  # noqa: BLE001
            errores.append(exc)

    hilos = [threading.Thread(target=escritor, args=(f"w{k}",)) for k in range(3)]
    for h in hilos:
        h.start()
    for h in hilos:
        h.join()
    assert errores == []
    entradas = abrir(db).entries()
    assert len(entradas) == 120
    assert len({e.prev for e in entradas}) == 120          # ningún prev repetido
    assert [e.seq for e in entradas] == list(range(1, 121))
    assert abrir(db).verify().ok


def test_ancla_detecta_borrado_del_ultimo_registro(tmp_path):
    db = tmp_path / "eng-1.db"
    escribir(db, 3)
    count, head = abrir(db).anchor()
    sql_directo(db, "DELETE FROM registros WHERE seq = 3")
    store = abrir(db)
    assert store.verify().ok                              # la cadena restante es válida
    assert not store.verify_anchor(count, head).ok        # pero el ancla no coincide


def test_cli_verify_con_ancla(tmp_path):
    db = tmp_path / "eng-1.db"
    escribir(db, 3)
    count, head = abrir(db).anchor()
    sql_directo(db, "DELETE FROM registros WHERE seq = 3")
    rc = api("audit").main(["verify", str(db), "--anchor-count", str(count),
                            "--anchor-head", head])
    assert rc != 0


def test_evento_con_password_se_rechaza_en_sqlite(tmp_path):
    db = tmp_path / "eng-1.db"
    store = abrir(db)
    with pytest.raises(EventoSensible, match="password"):
        store.append({**evento(0), "password": "x"})
    assert store.entries() == []


def test_harness_registra_en_la_bitacora_persistente(tmp_path):
    """2.5: Harness usa la bitácora persistente sin cambiar su contrato público."""
    import time

    from harness.contracts import (
        Action,
        Guard,
        Harness,
        KillSwitch,
        Phase,
        ScopeToken,
        ScopeViolation,
    )
    from harness.policy_loader import phase_allowlist

    db = tmp_path / "eng-1.db"
    log = api("audit").PersistentAuditLog(db, "eng-1")
    harness = Harness(Guard(phase_allowlist()), log, {}, KillSwitch())
    token = ScopeToken("eng-1", ("10.99.0.0/24",), ("dvwa.lab.test",), time.time() - 5,
                       time.time() + 60, Phase.RECON)
    with pytest.raises(ScopeViolation):
        harness.invoke("recon", Action("httpx.probe", Phase.RECON), "example.com", token)
    assert log.entries[-1]["result"] == "BLOCKED"          # contrato de AuditLog intacto
    log.close()
    persistido = abrir(db).entries()
    assert persistido[-1].data["result"] == "BLOCKED"
    assert persistido[-1].data["target"] == "example.com"
    assert abrir(db).verify().ok
