#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
pruebas_esqueleto.py — pruebas del LOOP de agente_esqueleto.py, SIN RED.

No tocan phantomcorp ni lanzan subprocess: inyectan un cliente-doble y
reemplazan ejecutar_tool por una función controlada. Cubren las cuatro
situaciones que pide el reparto:

  1. accion "final"            -> imprime y corta; no ejecuta tools.
  2. tool + REALIMENTACION     -> el doble solo propone el POST al vault si
                                  recibio el token por `resultados`. Prueba que
                                  el loop devuelve {id, output} del paso anterior
                                  (TODO 3). Es lo que el mock NO demuestra.
  3. tool desconocida / error  -> ejecutar_tool devuelve un string de error; el
                                  loop no se cae y lo realimenta igual.
  4. agotamiento del limite    -> cliente que nunca termina -> corta en MAX_PASOS.

Uso:  python3 pruebas_esqueleto.py     (sin dependencias, biblioteca estandar)
"""
import io
import sys
import os
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import agente_esqueleto as ag  # noqa: E402

TOKEN = "T-9f3k-vault"
FLAG_VAULT = "FLAG{agente_esqueleto_completo}"

_fallos = []
def check(cond, msg):
    estado = "ok  " if cond else "FALLA"
    print(f"  [{estado}] {msg}")
    if not cond:
        _fallos.append(msg)

def correr_main_con(cliente_factory, ejecutar_tool_fake):
    """Corre ag.main() con un cliente-doble y un ejecutar_tool controlado.
    Devuelve (stdout, flags_detectadas)."""
    orig_crear, orig_exec = ag.crear_cliente, ag.ejecutar_tool
    ag.crear_cliente = lambda system, tools: cliente_factory()
    ag.ejecutar_tool = ejecutar_tool_fake
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            ag.main()
    finally:
        ag.crear_cliente, ag.ejecutar_tool = orig_crear, orig_exec
    return buf.getvalue()


# ---------- 1. accion final ----------
class ClienteFinal:
    def paso(self, resultados=None):
        return {"tipo": "final", "texto": "auditoria terminada"}

def test_final():
    print("1) accion 'final' corta el loop sin ejecutar tools")
    llamadas = []
    out = correr_main_con(ClienteFinal, lambda n, a: llamadas.append(n) or "")
    check("auditoria terminada" in out, "imprime el texto de cierre del LLM")
    check(len(llamadas) == 0, "no ejecuta ninguna tool")


# ---------- 2. tool + realimentacion (encadenamiento real) ----------
class ClienteEncadena:
    """Primero pide el token. En el SEGUNDO paso inspecciona `resultados`: solo
    propone el POST al vault si el token llego por la realimentacion."""
    def __init__(self):
        self.fase = 0
        self.vio_token_por_resultados = False
        self.id_correlacionado = False
    def paso(self, resultados=None):
        if self.fase == 0:
            self.fase = 1
            return {"tipo": "tool", "nombre": "http_get",
                    "argumentos": {"url": "http://phantomcorp/api/token"}, "id": "t-1"}
        if self.fase == 1:
            self.fase = 2
            # TODO 3 bajo prueba: el loop tuvo que devolvernos [{id,output}].
            if resultados and resultados[0].get("id") == "t-1":
                self.id_correlacionado = True
            if resultados and TOKEN in resultados[0].get("output", ""):
                self.vio_token_por_resultados = True
                return {"tipo": "tool", "nombre": "http_post",
                        "argumentos": {"url": "http://phantomcorp/api/vault",
                                       "data": {"token": TOKEN}}, "id": "t-2"}
            return {"tipo": "final", "texto": "no recibi token: realimentacion rota"}
        return {"tipo": "final", "texto": "listo"}

def test_encadenamiento():
    print("2) realimentacion: el POST al vault depende de haber recibido el token")
    cli = ClienteEncadena()
    def exec_fake(nombre, args):
        if args.get("url", "").endswith("/api/token"):
            return '{"token": "%s"}' % TOKEN
        if args.get("url", "").endswith("/api/vault"):
            return '{"ok": true, "flag": "%s"}' % (FLAG_VAULT
                   if args.get("data", {}).get("token") == TOKEN else "")
        return ""
    out = correr_main_con(lambda: cli, exec_fake)
    check(cli.id_correlacionado, "el resultado vuelve atado al id de la accion (id correcto)")
    check(cli.vio_token_por_resultados, "el cliente recibio el token por `resultados`")
    check(FLAG_VAULT in out, "se encadeno token -> vault y apareci el flag capstone")


# ---------- 3. tool desconocida / error no rompe el loop ----------
class ClienteErrorLuegoFinal:
    def __init__(self): self.fase = 0
    def paso(self, resultados=None):
        if self.fase == 0:
            self.fase = 1
            return {"tipo": "tool", "nombre": "no_existe",
                    "argumentos": {"x": 1}, "id": "e-1"}
        # se asegura de haber recibido el string de error realimentado
        self.recibio_error = bool(resultados and "desconocida" in resultados[0]["output"])
        return {"tipo": "final", "texto": "sigo viva pese al error"}

def test_error():
    print("3) un error de tool se realimenta y el loop sigue sin romperse")
    cli = ClienteErrorLuegoFinal()
    # usamos el ejecutar_tool REAL: para 'no_existe' devuelve string, no excepcion
    out = correr_main_con(lambda: cli, ag.ejecutar_tool)
    check(getattr(cli, "recibio_error", False), "el string de error llego por `resultados`")
    check("sigo viva pese al error" in out, "el loop continuo hasta el 'final'")


# ---------- 4. agotamiento del limite de pasos ----------
class ClienteInfinito:
    def __init__(self): self.n = 0
    def paso(self, resultados=None):
        self.n += 1
        return {"tipo": "tool", "nombre": "http_get",
                "argumentos": {"url": "http://phantomcorp/"}, "id": f"i-{self.n}"}

def test_limite():
    print("4) un cliente que nunca termina corta en MAX_PASOS (guardrail)")
    llamadas = []
    cli = ClienteInfinito()
    out = correr_main_con(lambda: cli, lambda nom, a: llamadas.append(1) or "sin flag")
    check(len(llamadas) == ag.MAX_PASOS, f"se ejecutaron exactamente {ag.MAX_PASOS} tools")
    check("límite" in out or "limite" in out, "informa el corte por limite de pasos")


if __name__ == "__main__":
    print(f"=== pruebas del loop de agente_esqueleto.py (MAX_PASOS={ag.MAX_PASOS}) ===\n")
    test_final(); print()
    test_encadenamiento(); print()
    test_error(); print()
    test_limite(); print()
    if _fallos:
        print(f"\nRESULTADO: {len(_fallos)} fallo(s).")
        sys.exit(1)
    print("\nRESULTADO: todas las pruebas pasaron.")
    sys.exit(0)
