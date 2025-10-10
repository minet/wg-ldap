from __future__ import annotations

import logging
import json
import base64
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from pathlib import Path
from typing import Optional

from .config import load_config, AppConfig

log = logging.getLogger(__name__)


def pubkey(config: AppConfig) -> str:
    if hasattr(pubkey, "_cached"):
        return pubkey._cached  # type: ignore
    import nacl.signing
    import nacl.encoding
    with open(config.wireguard.private_key_path, 'r') as f:
        priv = f.read().strip()
    priv = base64.b64decode(priv.encode())
    setattr(pubkey, "_cached", nacl.signing.SigningKey(priv).verify_key.encode(encoder=nacl.encoding.Base64Encoder).decode())
    return pubkey._cached  # type: ignore


def routes(config: AppConfig) -> str:
    """Generate a comma-separated list of CIDRs for the AllowedIPs field."""
    if hasattr(routes, "_cached"):
        return routes._cached  # type: ignore
    # Collect all unique CIDRs from per_group_routes
    all_cidrs = set()
    for group_cidrs in config.per_group_routes.values():
        all_cidrs.update(group_cidrs)
    setattr(routes, "_cached", ",".join(sorted(all_cidrs)))  # type: ignore
    return routes._cached  # type: ignore

class LookupHandler(BaseHTTPRequestHandler):
    config: Optional[AppConfig] = None

    def _serve_index(self) -> None:
        assert self.config is not None
        # index.html is rigth next to this script
        index_path = Path(__file__).parent / "index.html"
        if not index_path.exists():
            self.send_error(500, "Index file missing")
            return
        try:
            content = index_path.read_text(encoding="utf-8")
        except Exception as e:
            log.exception("Failed to read index file: %s", e)
            self.send_error(500, "Failed to read index file")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        content = content.replace("{{WG_LDAP_SERVER_HOST}}", str(self.config.web.external_vpn_ip)) \
                         .replace("{{WG_LDAP_SERVER_PORT}}", str(self.config.wireguard.port)) \
                         .replace("{{WG_LDAP_PUBKEY}}", pubkey(self.config)) \
                         .replace("{{WG_LDAP_ROUTES}}", routes(self.config))
        self.wfile.write(content.encode("utf-8"))
        return
    

    def do_GET(self) -> None:
        assert self.config is not None
        # path expected: /valid_username
        path = unquote(self.path)
        if not path.startswith("/"):
            self.send_error(400, "Bad request")
            return
        username = path.lstrip("/")
        if not username:
            self._serve_index()
            return
        state_path = Path(self.config.state_file)
        if not state_path.exists():
            self.send_error(500, "State file missing")
            return
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
        except Exception as e:
            log.exception("Failed to read state file: %s", e)
            self.send_error(500, "Failed to read state file")
            return
        ip = data.get(username)
        if ip is None:
            self.send_error(404, "Not found")
            return
        # return only the IP
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(ip.encode("utf-8"))


def serve(config_path: str = "/etc/wg-ldap/config.toml", host: str | None = None, port: int | None = None) -> None:
    cfg = load_config(Path(config_path))
    # Use config.web values when host/port not explicitly provided
    host = host if host is not None else cfg.web.host
    port = port if port is not None else cfg.web.port
    # Attach config to handler class so instances can access it
    LookupHandler.config = cfg
    server = ThreadingHTTPServer((host, port), LookupHandler)
    log.info("Starting lookup server on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down server")
        server.shutdown()


if __name__ == "__main__":
    serve()
