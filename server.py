"""PulseFlow local API — stdlib only.

Run: python server.py
Open: http://127.0.0.1:8787

This service is deliberately provider-neutral. Replace the simulated outbound
adapter with an official WhatsApp Business provider before using in production.
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).parent
DATA_FILE = ROOT / "pulseflow-data.json"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def seed() -> dict:
    return {
        "leads": [],
        "integrations": {"whatsapp": False, "voip": False, "calendar": False, "crm": False},
        "events": [],
    }


def load() -> dict:
    if not DATA_FILE.exists():
        return seed()
    try:
        return json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return seed()


def save(data: dict) -> None:
    temp = DATA_FILE.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temp, DATA_FILE)


def event(data: dict, kind: str, payload: dict) -> None:
    data["events"].append({"id": secrets.token_hex(6), "type": kind, "at": utcnow(), "payload": payload})


class Handler(SimpleHTTPRequestHandler):
    def end_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Webhook-Secret")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.end_headers()

    def body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.fail("JSON inválido", HTTPStatus.BAD_REQUEST)
            return {}

    def reply(self, value: dict | list, status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def fail(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST) -> None:
        self.reply({"error": message}, status)

    def route(self) -> list[str]:
        return [x for x in urlparse(self.path).path.split("/") if x]

    def do_GET(self) -> None:
        parts = self.route()
        if parts == ["api", "health"]:
            return self.reply({"ok": True, "service": "pulseflow-api", "time": utcnow()})
        if parts == ["api", "leads"]:
            return self.reply(load()["leads"])
        if parts == ["api", "events"]:
            return self.reply(load()["events"][-100:])
        if parts == ["api", "integrations"]:
            return self.reply(load()["integrations"])
        return super().do_GET()

    def do_POST(self) -> None:
        parts, payload = self.route(), self.body()
        if parts == ["api", "leads"]:
            required = ["name", "phone"]
            if any(not payload.get(field) for field in required):
                return self.fail("name e phone são obrigatórios")
            data = load()
            lead = {
                "id": secrets.token_hex(8), "name": payload["name"], "phone": payload["phone"],
                "origin": payload.get("origin", "Não informado"), "interest": payload.get("interest", "Média"),
                "stage": payload.get("stage", "new"), "notes": payload.get("notes", ""),
                "callDone": False, "automationPaused": False, "createdAt": utcnow(), "messages": [],
            }
            data["leads"].append(lead)
            event(data, "lead.created", {"leadId": lead["id"]})
            save(data)
            return self.reply(lead, HTTPStatus.CREATED)
        if len(parts) == 4 and parts[:2] == ["api", "leads"] and parts[3] == "messages":
            data, lead_id = load(), parts[2]
            lead = next((x for x in data["leads"] if x["id"] == lead_id), None)
            if not lead:
                return self.fail("Lead não encontrado", HTTPStatus.NOT_FOUND)
            if not payload.get("text"):
                return self.fail("text é obrigatório")
            if payload.get("direction", "out") == "out" and not lead.get("callDone"):
                return self.fail("Uma ligação deve ser registrada antes da primeira mensagem", HTTPStatus.CONFLICT)
            msg = {"id": secrets.token_hex(6), "text": payload["text"], "direction": payload.get("direction", "out"), "at": utcnow()}
            lead["messages"].append(msg)
            if msg["direction"] == "in":
                lead["automationPaused"] = True
                event(data, "lead.replied", {"leadId": lead_id, "notifySeller": True, "automationPaused": True})
            else:
                event(data, "message.sent", {"leadId": lead_id, "provider": payload.get("provider", "simulated")})
            save(data)
            return self.reply(msg, HTTPStatus.CREATED)
        if parts == ["api", "webhooks", "whatsapp"]:
            # Expected: {"leadId":"...","text":"...","from":"+55..."}
            data = load()
            lead = next((x for x in data["leads"] if x["id"] == payload.get("leadId")), None)
            if not lead:
                return self.fail("Lead do webhook não encontrado", HTTPStatus.NOT_FOUND)
            lead["messages"].append({"id": secrets.token_hex(6), "text": payload.get("text", ""), "direction": "in", "at": utcnow()})
            lead["automationPaused"] = True
            event(data, "lead.replied", {"leadId": lead["id"], "notifySeller": True, "automationPaused": True})
            save(data)
            return self.reply({"received": True, "automationPaused": True, "notifySeller": True})
        if parts == ["api", "webhooks", "voip"]:
            data = load()
            lead = next((x for x in data["leads"] if x["id"] == payload.get("leadId")), None)
            if not lead:
                return self.fail("Lead do webhook não encontrado", HTTPStatus.NOT_FOUND)
            lead["callDone"] = payload.get("status") in {"completed", "answered"}
            event(data, "call.completed", {"leadId": lead["id"], "status": payload.get("status")})
            save(data)
            return self.reply({"received": True, "callDone": lead["callDone"]})
        if len(parts) == 3 and parts[:2] == ["api", "integrations"]:
            data = load()
            provider = parts[2]
            if provider not in data["integrations"]:
                return self.fail("Integração desconhecida", HTTPStatus.NOT_FOUND)
            # Do not persist actual credentials here. Use a secret manager in production.
            data["integrations"][provider] = bool(payload.get("enabled", True))
            event(data, "integration.updated", {"provider": provider, "enabled": data["integrations"][provider]})
            save(data)
            return self.reply({"provider": provider, "connected": data["integrations"][provider]})
        return self.fail("Rota não encontrada", HTTPStatus.NOT_FOUND)

    def do_PATCH(self) -> None:
        parts, payload = self.route(), self.body()
        if len(parts) == 3 and parts[:2] == ["api", "leads"]:
            data = load()
            lead = next((x for x in data["leads"] if x["id"] == parts[2]), None)
            if not lead:
                return self.fail("Lead não encontrado", HTTPStatus.NOT_FOUND)
            allowed = {"stage", "interest", "origin", "notes", "discardReason", "recoveryAt", "callDone"}
            lead.update({k: v for k, v in payload.items() if k in allowed})
            event(data, "lead.updated", {"leadId": lead["id"], "fields": list(set(payload) & allowed)})
            save(data)
            return self.reply(lead)
        return self.fail("Rota não encontrada", HTTPStatus.NOT_FOUND)


if __name__ == "__main__":
    os.chdir(ROOT)
    server = ThreadingHTTPServer(("127.0.0.1", 8787), Handler)
    print("PulseFlow running at http://127.0.0.1:8787")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nPulseFlow stopped")
