"""Webhook oficial do WhatsApp Business Platform para Vercel Functions.

Credenciais nunca são recebidas pelo navegador. Configure-as como variáveis de
ambiente na Vercel. Eventos normalizados podem ser encaminhados para um backend
durável por PULSEFLOW_EVENT_SINK_URL.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from urllib.error import URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def env_ready() -> dict:
    required = {
        "verifyToken": "META_VERIFY_TOKEN",
        "appSecret": "META_APP_SECRET",
        "accessToken": "META_ACCESS_TOKEN",
        "phoneNumberId": "META_PHONE_NUMBER_ID",
        "wabaId": "META_WABA_ID",
        "graphVersion": "META_GRAPH_VERSION",
    }
    return {name: bool(os.getenv(key)) for name, key in required.items()}


def normalize(payload: dict) -> list[dict]:
    events: list[dict] = []
    for entry in payload.get("entry", []):
        for change in entry.get("changes", []):
            field = change.get("field", "unknown")
            value = change.get("value", {})
            metadata = value.get("metadata", {})
            contacts = {item.get("wa_id"): item.get("profile", {}).get("name") for item in value.get("contacts", [])}
            for message in value.get("messages", []):
                sender = message.get("from", "")
                message_type = message.get("type", "unknown")
                text = message.get("text", {}).get("body", "") if message_type == "text" else ""
                events.append({
                    "type": "whatsapp.message.received",
                    "at": utcnow(),
                    "messageId": message.get("id"),
                    "from": sender,
                    "contactName": contacts.get(sender),
                    "messageType": message_type,
                    "text": text,
                    "phoneNumberId": metadata.get("phone_number_id"),
                    "groupId": message.get("group_id") or value.get("group_id"),
                    "source": "group" if message.get("group_id") or value.get("group_id") else "direct",
                })
            if field.startswith("group_"):
                events.append({"type": f"whatsapp.{field}", "at": utcnow(), "payload": value})
    return events


def forward(events: list[dict]) -> tuple[bool, str | None]:
    sink = os.getenv("PULSEFLOW_EVENT_SINK_URL")
    if not sink or not events:
        return False, None
    body = json.dumps({"provider": "whatsapp", "events": events}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    sink_key = os.getenv("PULSEFLOW_EVENT_SINK_KEY")
    if sink_key:
        headers["Authorization"] = f"Bearer {sink_key}"
    try:
        with urlopen(Request(sink, data=body, headers=headers, method="POST"), timeout=8) as response:
            return 200 <= response.status < 300, None
    except (URLError, TimeoutError) as error:
        return False, str(error)


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
        query = parse_qs(urlparse(self.path).query)
        mode = query.get("hub.mode", [""])[0]
        token = query.get("hub.verify_token", [""])[0]
        challenge = query.get("hub.challenge", [""])[0]
        if mode == "subscribe":
            expected = os.getenv("META_VERIFY_TOKEN", "")
            if expected and hmac.compare_digest(token, expected):
                raw = challenge.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
                return
            return self.reply(403, {"ok": False, "error": "verify_token inválido"})
        ready = env_ready()
        self.reply(200, {
            "ok": True,
            "service": "pulseflow-whatsapp-webhook",
            "configured": all(ready.values()),
            "requirements": ready,
            "eventSinkConfigured": bool(os.getenv("PULSEFLOW_EVENT_SINK_URL")),
            "groupMode": "restricted_official_groups_api",
            "time": utcnow(),
        })

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        secret = os.getenv("META_APP_SECRET", "")
        signature = self.headers.get("X-Hub-Signature-256", "")
        demo_allowed = os.getenv("PULSEFLOW_DEMO_WEBHOOK", "").lower() == "true"
        expected = "sha256=" + hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest() if secret else ""
        if not demo_allowed and (not expected or not hmac.compare_digest(signature, expected)):
            return self.reply(401, {"received": False, "error": "assinatura do webhook inválida"})
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self.reply(400, {"received": False, "error": "JSON inválido"})
        events = normalize(payload)
        forwarded, error = forward(events)
        self.reply(200, {
            "received": True,
            "normalizedEvents": len(events),
            "forwarded": forwarded,
            "forwardError": error,
        })

