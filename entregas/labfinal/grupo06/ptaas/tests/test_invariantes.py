"""Invariante I1 — único camino (matriz de invariantes, `entrega/matriz-invariantes.md`).

Fuera de `harness/adapters/` ningún módulo del harness ni de `tools/` puede ejecutar
directamente un binario de herramienta de seguridad, ni usar `os.system`. Las
herramientas se ejecutan solo como `runner` de un `ToolAdapter`, que se invoca por
`Harness.invoke`. El hook de Claude Code (`.claude/hooks/`) frena lo mismo en la
sesión de desarrollo; este test lo hace cumplir sobre el código.

Se analiza el código fuente (AST): una llamada a `subprocess.run/Popen/call/
check_call/check_output` cuyo primer argumento es una lista que empieza con el nombre
de una herramienta de seguridad es una ejecución directa.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECURITY_TOOLS = {"nmap", "masscan", "naabu", "nuclei", "nikto", "wapiti", "sqlmap", "hydra",
                  "msfconsole", "zap-cli", "zap-baseline.py", "zap.sh", "amass", "subfinder",
                  "httpx"}
SUBPROCESS_CALLS = {"run", "Popen", "call", "check_call", "check_output"}


def scanned_files():
    for base in ("harness", "tools"):
        for path in sorted((ROOT / base).rglob("*.py")):
            if "adapters" not in path.relative_to(ROOT).parts:
                yield path


def direct_executions(source: str) -> list[str]:
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        owner = node.func.value
        name = owner.id if isinstance(owner, ast.Name) else None
        if name == "os" and node.func.attr == "system":
            found.append(f"os.system (línea {node.lineno})")
        if name == "subprocess" and node.func.attr in SUBPROCESS_CALLS and node.args:
            first = node.args[0]
            if (isinstance(first, ast.List) and first.elts
                    and isinstance(first.elts[0], ast.Constant)
                    and first.elts[0].value in SECURITY_TOOLS):
                found.append(f"{first.elts[0].value} (línea {node.lineno})")
    return found


def test_i1_ninguna_herramienta_de_seguridad_se_ejecuta_fuera_de_un_adaptador():
    violaciones = {str(p.relative_to(ROOT)): v for p in scanned_files()
                   if (v := direct_executions(p.read_text(encoding="utf-8")))}
    assert violaciones == {}


def test_i1_el_detector_reconoce_una_ejecucion_directa():
    # Control del propio test: si el detector no ve esto, el test anterior no prueba nada.
    codigo = "import subprocess, os\nsubprocess.run(['nmap', '-sV', 'x'])\nos.system('ls')\n"
    assert len(direct_executions(codigo)) == 2


def test_i1_docker_como_runner_no_es_ejecucion_directa():
    # El sandbox y los puentes lanzan `docker`; la herramienta corre como runner del
    # adaptador. No es una violación de I1.
    assert direct_executions("import subprocess\nsubprocess.run(['docker', 'ps'])\n") == []
