"""Local PulseFlow server: real API handlers, no mock data or public file listing.

Run ``python server.py`` and open http://127.0.0.1:8787.
Install requirements.txt and configure the same database variables as production.
The explicitly isolated UI test fixture is tests/serve_test.py, never this server.
"""
from __future__ import annotations

import importlib
import json
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)
# An allowlist prevents accidental publication of source code, .env, .git or backups.
PUBLIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/core.mjs": ("core.mjs", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
}
API_MODULES = {
    "/api/auth": "api.auth",
    "/api/whatsapp": "api.whatsapp",
    "/api/send-whatsapp": "api.send-whatsapp",
}


class SecurityHeaders:
    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", CSP)
        super().end_headers()

    def log_message(self, message: str, *args) -> None:
        # Do not log query strings, credentials, contact data or webhook payloads.
        return


@lru_cache(maxsize=3)
def api_handler(module_name: str):
    module = importlib.import_module(module_name)
    return type("LocalAPIHandler", (SecurityHeaders, module.handler), {})


class Handler(SecurityHeaders, BaseHTTPRequestHandler):
    server_version = "PulseFlowLocal"
    sys_version = ""

    def json_reply(self, status: int, data: dict) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def local_host(self) -> bool:
        try:
            hostname = urlsplit("http://" + self.headers.get("Host", "")).hostname
        except ValueError:
            return False
        return hostname in {"localhost", "127.0.0.1", "::1"}

    def dispatch(self) -> None:
        if not self.local_host():
            return self.json_reply(403, {"ok": False, "error": "servidor disponível apenas em localhost"})
        path = unquote(urlsplit(self.path).path)
        if path in API_MODULES:
            if self.command not in {"GET", "POST"}:
                return self.json_reply(405, {"ok": False, "error": "método não permitido"})
            try:
                handler_class = api_handler(API_MODULES[path])
            except (ImportError, RuntimeError):
                return self.json_reply(503, {"ok": False, "error": "dependências do backend ausentes; instale requirements.txt e configure o banco"})
            # Reuse this parsed request, while resolving helpers on the real API class.
            delegate = handler_class.__new__(handler_class)
            delegate.__dict__ = self.__dict__
            getattr(delegate, "do_" + self.command)()
            return
        if self.command not in {"GET", "HEAD"}:
            return self.json_reply(405, {"ok": False, "error": "método não permitido"})
        public = PUBLIC_FILES.get(path)
        if not public or not (ROOT / public[0]).is_file():
            return self.json_reply(404, {"ok": False, "error": "página não encontrada"})
        raw = (ROOT / public[0]).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", public[1])
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_PATCH = dispatch
    do_DELETE = dispatch
    do_OPTIONS = dispatch


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8787), Handler)
    print("PulseFlow local: http://127.0.0.1:8787 (APIs reais; banco configurado necessário)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
