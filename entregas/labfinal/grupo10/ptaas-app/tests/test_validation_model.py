import json
from pathlib import Path
from typing import Any

from runtime.providers import ROLE_MODELS, OpenCodeProvider


def test_validation_has_dedicated_luna_model() -> None:
    assert ROLE_MODELS["validation"] == "gpt-5.6-luna"
    assert ROLE_MODELS["validation"] != ROLE_MODELS["analysis"]


def test_validation_request_is_accepted_by_provider(monkeypatch: Any) -> None:
    class Completed:
        returncode = 0
        stdout = '{"data":{"text":"{}"}}'

    seen = {}

    def run(argv: list[str], **kwargs: Any) -> Completed:
        seen["payload"] = json.loads(argv[-1])
        return Completed()

    monkeypatch.setattr("runtime.providers.subprocess.run", run)
    provider = OpenCodeProvider(executable=Path("opencode.exe"))
    assert provider.generate(json.dumps({"agent": "validation"})) == "{}"
    assert seen["payload"]["model"] == {"providerID": "openai", "id": "gpt-5.6-luna"}
