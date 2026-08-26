"""Envio real pela WhatsApp Cloud API com bloqueios do PulseFlow."""
from __future__ import annotations

import hmac
import json
import os
from http.server import BaseHTTPRequestHandler
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def ready() -> dict:
    return {
        "accessToken": bool(os.getenv("META_ACCESS_TOKEN")),
        "phoneNumberId": bool(os.getenv("META_PHONE_NUMBER_ID")),
        "graphVersion": bool(os.getenv("META_GRAPH_VERSION")),
        "internalKey": bool(os.getenv("PULSEFLOW_INTERNAL_API_KEY")),
    }


class handler(BaseHTTPRequestHandler):
    def reply(self, status: int, value: dict) -> None:
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        requirements = ready()
        self.reply(200, {"ok": True, "service": "pulseflow-whatsapp-send", "configured": all(requirements.values()), "requirements": requirements})

    def do_POST(self) -> None:
        internal_key = os.getenv("PULSEFLOW_INTERNAL_API_KEY", "")
        supplied_key = self.headers.get("X-PulseFlow-Key", "")
        if not internal_key:
            return self.reply(503, {"sent": False, "error": "chave interna não configurada"})
        if not hmac.compare_digest(supplied_key, internal_key):
            return self.reply(401, {"sent": False, "error": "não autorizado"})
        requirements = ready()
        if not all(requirements.values()):
            return self.reply(503, {"sent": False, "error": "credenciais da Meta incompletas", "requirements": requirements})
        length = int(self.headers.get("Content-Length", "0"))
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return self.reply(400, {"sent": False, "error": "JSON inválido"})
        if not payload.get("consentConfirmed"):
            return self.reply(409, {"sent": False, "error": "consentimento do contato não confirmado"})
        if not payload.get("callCompleted"):
            return self.reply(409, {"sent": False, "error": "registre a ligação antes da mensagem"})
        if not payload.get("to") or not payload.get("text"):
            return self.reply(400, {"sent": False, "error": "to e text são obrigatórios"})
        version = os.environ["META_GRAPH_VERSION"].strip("/")
        phone_id = os.environ["META_PHONE_NUMBER_ID"]
        url = f"https://graph.facebook.com/{version}/{phone_id}/messages"
        body = json.dumps({"messaging_product": "whatsapp", "recipient_type": "individual", "to": payload["to"], "type": "text", "text": {"preview_url": False, "body": payload["text"]}}).encode("utf-8")
        request = Request(url, data=body, method="POST", headers={"Authorization": f"Bearer {os.environ['META_ACCESS_TOKEN']}", "Content-Type": "application/json"})
        try:
            with urlopen(request, timeout=12) as response:
                result = json.loads(response.read() or b"{}")
                return self.reply(200, {"sent": True, "provider": "meta-cloud-api", "result": result})
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:1000]
            return self.reply(error.code, {"sent": False, "error": "Meta recusou o envio", "detail": detail})
        except (URLError, TimeoutError) as error:
            return self.reply(502, {"sent": False, "error": "falha ao conectar com a Meta", "detail": str(error)})

