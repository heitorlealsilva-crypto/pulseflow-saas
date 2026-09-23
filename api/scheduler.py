"""GitHub Actions OIDC entry point for the durable PulseFlow scheduler.

This endpoint deliberately accepts only POST requests authenticated with a
short-lived GitHub OIDC token.  The existing ``/api/worker`` endpoint remains
available to Vercel Cron as a once-a-day fallback using ``CRON_SECRET``.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from api.auth import connect
from api.github_oidc import authorized
from api.worker import run_batch


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Do not let request headers or tokens reach provider logs.
        return

    def reply(self, status: int, value: dict) -> None:
        raw = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        return self.reply(405, {"ok": False, "error": "método não permitido"})

    def do_POST(self):
        if not authorized(self.headers):
            return self.reply(401, {"ok": False, "error": "agendador não autorizado"})
        try:
            with connect() as db:
                return self.reply(200, run_batch(db))
        except Exception:
            # Database, tenant and contact details must never be exposed here.
            return self.reply(503, {"ok": False, "error": "agendador temporariamente indisponível"})
