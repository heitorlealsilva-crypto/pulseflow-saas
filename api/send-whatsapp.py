"""Retired single-tenant sender. All sends must use the authenticated tenant API."""
import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def retired(self):
        raw = json.dumps({"ok": False, "sent": False, "code": "endpoint_retired",
                          "error": "Use a integração WhatsApp da sua conta no PulseFlow."}).encode()
        self.send_response(410)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = retired
    do_POST = retired
