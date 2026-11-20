"""Senders fixture, restringido y contenedor efímero sobre red interna verificada."""

from __future__ import annotations

import ipaddress
import json
import subprocess
import uuid
from pathlib import Path
from typing import Any

from harness.http_transport import FixtureSender, RestrictedSender
from harness.poc.catalog import ResponseRecord
from harness.roe import load_lab_targets

__all__ = ["DockerSender", "FixtureSender", "RestrictedSender"]


class DockerSender:
    mode = "sandbox"

    def __init__(self, domains: tuple[str, ...], cidrs: tuple[str, ...], network: str):
        self.domains = domains
        self.cidrs = cidrs
        self.network = network
        self.name = "ptaas-validation-" + uuid.uuid4().hex
        self.closed = False
        self.calls = 0

    def __call__(self, poc_id: str, params: dict[str, Any]) -> ResponseRecord:
        if self.closed or self.calls >= 2:
            raise ValueError("Sender cerrado o límite de solicitudes")
        # No se conecta a una red arbitraria: la inspección exige internal y subnet autorizada.
        info = subprocess.run(
            ["docker", "network", "inspect", self.network],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        net = json.loads(info.stdout)[0]
        subnets = [
            ipaddress.ip_network(x["Subnet"]) for x in net["IPAM"]["Config"] if "Subnet" in x
        ]
        if (
            not net.get("Internal")
            or not subnets
            or not all(
                any(
                    isinstance(n, ipaddress.IPv4Network) and n.subnet_of(ipaddress.IPv4Network(c))
                    for c in load_lab_targets()["cidrs"]
                )
                for n in subnets
            )
        ):
            raise ValueError("red Docker no interna o fuera del alcance del token")
        self.calls += 1
        root = Path(__file__).resolve().parent.parent
        command = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--name",
            self.name,
            "--network",
            self.network,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            "64",
            "--memory",
            "64m",
            "--cpus",
            "0.5",
            "--user",
            "65534:65534",
            "--mount",
            f"type=bind,source={root},target=/app,readonly",
            "-w",
            "/app",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "python:3.12-slim",
            "python",
            "-m",
            "harness.http_transport",
        ]
        try:
            result = subprocess.run(
                command,
                input=json.dumps(
                    {
                        "domains": self.domains,
                        "cidrs": self.cidrs,
                        "poc_id": poc_id,
                        "params": params,
                    }
                ),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if result.returncode:
                raise ValueError("worker sandbox rechazó la solicitud o falló")
            data = json.loads(result.stdout)
            return ResponseRecord(**{**data, "set_cookies": tuple(data["set_cookies"])})
        finally:
            # Solo el contenedor efímero con UUID creado por esta instancia.
            subprocess.run(
                ["docker", "rm", "-f", self.name], capture_output=True, timeout=10, check=False
            )

    def close(self) -> None:
        self.closed = True
