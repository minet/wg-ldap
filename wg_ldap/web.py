from __future__ import annotations

import logging
import json
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote
from pathlib import Path
from typing import Optional

from .config import load_config, AppConfig

log = logging.getLogger(__name__)


class LookupHandler(BaseHTTPRequestHandler):
    config: Optional[AppConfig] = None
    def do_GET(self) -> None:
        assert self.config is not None
        # path expected: /valid_username
        path = unquote(self.path)
        if not path.startswith("/"):
            self.send_error(400, "Bad request")
            return
        username = path.lstrip("/")
        if not username:
            self.send_error(404, "Not found")
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
