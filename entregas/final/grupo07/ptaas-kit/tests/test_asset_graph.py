import json

import pytest

from harness.asset_graph import AssetGraph, GraphVersionError
from harness.schemas import Asset


def test_grafo_guarda_y_recupera_assets_fuentes_y_alcance(tmp_path):
    graph = AssetGraph()
    first = Asset("ignored", "host", "DVWA.LAB.TEST", "httpx.probe", ("PHP 8",))
    second = Asset("ignored-again", "host", "dvwa.lab.test", "nmap.service_scan", ("nginx",))
    graph.add(first, in_scope=True, discovered_from="dvwa.lab.test")
    graph.add(second, in_scope=True, discovered_from="dvwa.lab.test")
    graph.add(Asset("outside", "host", "other.example.org", "subfinder.enum"),
              in_scope=False, discovered_from="dvwa.lab.test")

    path = tmp_path / "assets.json"
    graph.save(path)
    loaded = AssetGraph.load(path)

    assert len(loaded.nodes) == 2
    node = loaded.get_by_address("dvwa.lab.test")
    assert node is not None
    assert node.asset.id.startswith("asset-")
    assert node.in_scope is True
    assert node.sources == ("httpx.probe", "nmap.service_scan")
    assert node.asset.technologies == ("PHP 8", "nginx")
    assert loaded.get_by_address("other.example.org").in_scope is False


def test_grafo_rechaza_version_desconocida_sin_modificar_archivo(tmp_path):
    path = tmp_path / "assets.json"
    original = json.dumps({"schema_version": 99, "nodes": []})
    path.write_text(original, encoding="utf-8")

    with pytest.raises(GraphVersionError):
        AssetGraph.load(path)

    assert path.read_text(encoding="utf-8") == original
