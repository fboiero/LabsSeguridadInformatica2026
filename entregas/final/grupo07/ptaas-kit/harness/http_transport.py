from __future__ import annotations

import http.client
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit


@dataclass(frozen=True)
class ResponseRecord:
    status: int
    headers: dict[str, str]
    body: str
    set_cookies: tuple[str, ...] = ()
    canary: str | None = None


class FixtureSender:
    mode = "fixture"

    def __init__(self) -> None:
        self.closed = False
        self.calls = 0

    def __call__(self, poc_id: str, params: dict[str, Any]) -> ResponseRecord:
        if self.closed or self.calls >= 2:
            raise ValueError("Sender cerrado o límite de solicitudes")
        self.calls += 1
        return ResponseRecord(200, {"Content-Type": "text/html"}, "Fixture sintética sin CSP")

    def close(self) -> None:
        self.closed = True


class RestrictedSender:
    mode = "restricted_http_no_container"

    def __init__(
        self,
        domains: tuple[str, ...],
        cidrs: tuple[str, ...],
        timeout: float = 3,
        max_bytes: int = 65536,
        max_requests: int = 2,
    ) -> None:
        self.domains = domains
        self.cidrs = cidrs
        if not 0 < timeout <= 3 or not 0 < max_bytes <= 65536 or not 0 < max_requests <= 2:
            raise ValueError("límites fuera del máximo permitido")
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.max_requests = max_requests
        self.closed = False
        self.calls = 0

    def __call__(self, poc_id: str, params: dict[str, Any]) -> ResponseRecord:
        if self.closed or self.calls >= self.max_requests:
            raise ValueError("Sender cerrado o límite de solicitudes")
        u = urlsplit(params["base_url"])
        path = params["path"]
        host = u.hostname or ""
        if (
            u.scheme != "http"
            or u.username
            or u.password
            or u.query
            or u.fragment
            or u.path not in ("", "/")
            or u.port not in (None, 80, 3000)
            or host not in self.domains
            or host not in ("dvwa.lab.test", "juiceshop.lab.test")
            or not path.startswith("/")
            or path.startswith("//")
            or "\\" in path
            or any(ord(c) < 32 for c in path)
        ):
            raise ValueError("URL fuera del laboratorio o ruta inválida")
        addresses = {
            x[4][0] for x in socket.getaddrinfo(host, u.port or 80, type=socket.SOCK_STREAM)
        }
        if not addresses or not all(
            any(ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in self.cidrs)
            for ip in addresses
        ):
            raise ValueError("DNS fuera del CIDR autorizado")
        # IP fijada tras la validación; no segundo lookup, proxies ni redirecciones.
        ip = str(min(addresses))
        self.calls += 1
        connection = http.client.HTTPConnection(ip, u.port or 80, timeout=self.timeout)
        if "canary" in params:
            path += ("&" if "?" in path else "?") + urlencode(
                {params["param_name"]: params["canary"]}
            )
        try:
            connection.request("GET", path, headers={"Host": host, "Connection": "close"})
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise ValueError("redirecciones bloqueadas")
            deadline = time.monotonic() + self.timeout
            chunks = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("tiempo total de respuesta agotado")
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, self.max_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > self.max_bytes:
                    raise ValueError("respuesta excede límite")
            body = b"".join(chunks)
            if len(body) > self.max_bytes:
                raise ValueError("respuesta excede límite")
            headers = dict(response.getheaders())
            cookies = tuple(v for k, v in response.getheaders() if k.lower() == "set-cookie")
            return ResponseRecord(
                response.status,
                headers,
                body.decode("utf-8", errors="replace"),
                cookies,
                params.get("canary"),
            )
        finally:
            connection.close()

    def close(self) -> None:
        self.closed = True


if __name__ == "__main__":
    import json
    import sys
    from dataclasses import asdict

    data = json.load(sys.stdin)
    sender = RestrictedSender(tuple(data["domains"]), tuple(data["cidrs"]))
    try:
        print(json.dumps(asdict(sender(data["poc_id"], data["params"]))))
    finally:
        sender.close()
