"""Validate a reviewed availability receipt in a networkless Docker worker."""
import argparse
import hashlib
import json
import re
import subprocess
from hmac import compare_digest
from pathlib import Path
from uuid import uuid4

from . import abc_receipt
from .review_loop import _IMAGE


def validate(path: Path, approved_sha256: str | None) -> dict[str, str | bool]:
    if approved_sha256 is None or not re.fullmatch(r"[0-9a-fA-F]{64}", approved_sha256):
        raise ValueError("reviewer_approval_required")
    with path.open("rb") as stream:
        raw = stream.read(abc_receipt.MAX_BYTES + 1)
    digest = hashlib.sha256(raw).hexdigest()
    if len(raw) > abc_receipt.MAX_BYTES or not compare_digest(digest, approved_sha256.lower()):
        raise ValueError("approval_hash_mismatch")

    name = "ptaas-abc-check-" + uuid4().hex
    source = Path(abc_receipt.__file__).read_text(encoding="utf-8")
    args = ["docker", "run", "--rm", "--pull", "never", "--name", name, "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65534:65534", "--pids-limit", "32",
            "--memory", "128m", "-i", _IMAGE, "python", "-I", "-B", "-c", source, digest]
    try:
        worker = subprocess.run(args, input=raw, capture_output=True, timeout=25, check=False)
    finally:
        listing = subprocess.run(["docker", "ps", "-aq", "--filter", f"name=^/{name}$"],
                                 capture_output=True, timeout=10, check=False)
        if listing.returncode != 0 or listing.stdout.strip():
            raise ValueError("sandbox_removal_unverified")
    if worker.returncode:
        raise ValueError("receipt_check_failed")
    result = json.loads(worker.stdout)
    if not isinstance(result, dict) or result.get("state") != "DOCUMENT_CHECKED" or (
        result.get("network_isolated") is not True or result.get("receipt_sha256") != digest
    ):
        raise ValueError("invalid_worker_result")
    return {**result, "container_removed": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--approve-sha256")
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.receipt, args.approve_sha256)))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"validation_blocked: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
