import ast
import re
from pathlib import Path


def test_local_scenarios_point_to_test_functions():
    root = Path(__file__).resolve().parents[1]
    specs = root / "openspec"
    scenarios = {(path.parent.name, name.strip()) for path in (specs / "changes").glob("*/specs/*/spec.md")
                 for name in re.findall(r"^### Scenario:\s*(.+)$", path.read_text(encoding="utf-8"), re.MULTILINE)}
    seen = set()
    for line in (specs / "specs/scenario-tests.tsv").read_text(encoding="utf-8").splitlines():
        capability, title, reference = line.split("|")
        key = (capability, title)
        assert key not in seen
        seen.add(key)
        file, name = reference.split("::")
        assert file.startswith("tests/") and name.startswith("test_")
        tree = ast.parse((root / file).read_text(encoding="utf-8"))
        assert any(isinstance(node, ast.FunctionDef) and node.name == name for node in tree.body), reference
    assert seen == scenarios
