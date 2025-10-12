from __future__ import annotations

import argparse
import base64
import codecs
import logging
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from .config import load_config, AppConfig

log = logging.getLogger(__name__)


def pubkey(cfg: AppConfig) -> str:
    if hasattr(pubkey, "_cached"):
        return pubkey._cached  # type: ignore
    
    
    with open(cfg.wireguard.private_key_path, 'r') as f:
        priv_b64 = f.read().strip()
    
    # Decode the base64 private key
    priv_bytes = base64.b64decode(priv_b64)
    
    # Load the private key
    private_key = X25519PrivateKey.from_private_bytes(priv_bytes)
    
    # Derive public key
    pubkey_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, 
        format=serialization.PublicFormat.Raw
    )
    
    # Encode to base64
    pub = codecs.encode(pubkey_bytes, 'base64').decode('utf8').strip()
    
    setattr(pubkey, "_cached", pub)
    return pubkey._cached  # type: ignore


def routes(cfg: AppConfig) -> str:
    """Generate a comma-separated list of CIDRs for the AllowedIPs field."""
    if hasattr(routes, "_cached"):
        return routes._cached  # type: ignore
    # Collect all unique CIDRs from per_group_routes
    all_cidrs = set()
    for group_cidrs in cfg.per_group_routes.values():
        all_cidrs.update(group_cidrs)
    all_cidrs.add(cfg.vpn_network().with_prefixlen)
    setattr(routes, "_cached", ",".join(sorted(all_cidrs)))  # type: ignore
    return routes._cached  # type: ignore

class LookupHandler(BaseHTTPRequestHandler):
    cfg: Optional[AppConfig] = None

    def _serve_index(self) -> None:
        assert self.cfg is not None
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

        wireguard_ip = self.cfg.wireguard.address.split('/')[0]
        content = content.replace("{{WG_LDAP_SERVER_HOST}}", str(self.cfg.web.external_vpn_ip)) \
                         .replace("{{WG_LDAP_SERVER_PORT}}", str(self.cfg.wireguard.port)) \
                         .replace("{{WG_LDAP_PUBKEY}}", pubkey(self.cfg)) \
                         .replace("{{WG_LDAP_ROUTES}}", routes(self.cfg)) \
                         .replace("{{WG_LDAP_DNS}}", wireguard_ip) \
                         .replace("{{WG_LDAP_SEARCH_DOMAIN}}", self.cfg.web.dns_search_domain)
        self.wfile.write(content.encode("utf-8"))
        return
    

    def do_GET(self) -> None:
        assert self.cfg is not None
        # path expected: /valid_username
        path = unquote(self.path)
        if not path.startswith("/"):
            self.send_error(400, "Bad request")
            return
        username = path.lstrip("/")
        if not username:
            self._serve_index()
            return
        state_path = Path(self.cfg.web.state_file)
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


def serve() -> None:
    
    parser = argparse.ArgumentParser(description="Start the WireGuard LDAP lookup server")
    parser.add_argument("--config", type=str, help="Path to config file", default="/etc/wg-ldap/config.toml")
    parser.add_argument("--host", type=str, help="Host to bind to")
    parser.add_argument("--port", type=int, help="Port to bind to")
    
    args = parser.parse_args()

    cfg = load_config(Path(args.config))

    # Use config.web values as defaults when host/port not explicitly provided
    host = args.host if args.host is not None else cfg.web.host
    port = args.port if args.port is not None else cfg.web.port
    
    # Attach config to handler class so instances can access it
    LookupHandler.cfg = cfg
    server = ThreadingHTTPServer((host, port), LookupHandler)
    log.info("Starting lookup server on %s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down server")
        server.shutdown()


if __name__ == "__main__":
    serve()
