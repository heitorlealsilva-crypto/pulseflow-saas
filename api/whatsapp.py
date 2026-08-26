"""Integração oficial multiempresa com WhatsApp Cloud API."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import urllib.error
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlparse

import psycopg
from cryptography.fernet import Fernet, InvalidToken
from psycopg.rows import dict_row


def connect():
    return psycopg.connect(os.getenv("DATABASE_URL") or os.getenv("STORAGE_URL"), row_factory=dict_row)


def cipher() -> Fernet:
    raw = os.getenv("PULSEFLOW_ENCRYPTION_KEY", "")
    if not raw:
        raise RuntimeError("chave de criptografia não configurada")
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest())
    return Fernet(key)


def ensure_schema(db) -> None:
    statements = ["""
        CREATE TABLE IF NOT EXISTS whatsapp_connections (
            organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            phone_number_id TEXT NOT NULL, waba_id TEXT NOT NULL DEFAULT '', business_number TEXT NOT NULL DEFAULT '',
            access_token_enc TEXT NOT NULL, app_secret_enc TEXT NOT NULL, verify_token_hash TEXT NOT NULL,
            graph_version TEXT NOT NULL DEFAULT 'v23.0', status TEXT NOT NULL DEFAULT 'active',
            connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """, """
        CREATE TABLE IF NOT EXISTS whatsapp_messages (
            id BIGSERIAL PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            wa_message_id TEXT NOT NULL, contact_phone TEXT NOT NULL, contact_name TEXT NOT NULL DEFAULT '',
            direction TEXT NOT NULL, message_type TEXT NOT NULL DEFAULT 'text', body TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'received', occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            raw JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(organization_id, wa_message_id)
        )
    """, "CREATE INDEX IF NOT EXISTS wa_messages_org_phone_idx ON whatsapp_messages(organization_id, contact_phone, occurred_at DESC)"]
    for statement in statements:
        db.execute(statement)
    db.commit()


def session_user(db, header: str) -> dict | None:
    jar = cookies.SimpleCookie(header or "")
    morsel = jar.get("pulseflow_session")
    if not morsel:
        return None
    token_hash = hashlib.sha256(morsel.value.encode()).hexdigest()
    return db.execute("""
        SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
        LEFT JOIN organizations o ON o.id=u.organization_id
        WHERE s.token_hash=%s AND s.expires_at>NOW() AND u.status='active'
        AND (u.role='super_admin' OR o.status='active')
    """, (token_hash,)).fetchone()


def allowed_org(user: dict, requested: str) -> str | None:
    own = str(user.get("organization_id") or "")
    if user["role"] == "super_admin":
        return requested or None
    return own if not requested or requested == own else None


class handler(BaseHTTPRequestHandler):
    def reply(self, status: int, value, content_type: str = "application/json; charset=utf-8") -> None:
        raw = (json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def query(self) -> dict:
        return {key: values[0] for key, values in parse_qs(urlparse(self.path).query).items()}

    def body(self) -> dict:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 2_000_000)
            self.raw_body = self.rfile.read(length) or b"{}"
            return json.loads(self.raw_body)
        except (ValueError, json.JSONDecodeError):
            return {}

    def do_GET(self) -> None:
        query = self.query()
        try:
            with connect() as db:
                ensure_schema(db)
                if "hub.challenge" in query:
                    organization_id = query.get("organization_id", "")
                    row = db.execute("SELECT verify_token_hash FROM whatsapp_connections WHERE organization_id=%s AND status='active'", (organization_id,)).fetchone()
                    candidate = hashlib.sha256(query.get("hub.verify_token", "").encode()).hexdigest()
                    if query.get("hub.mode") == "subscribe" and row and hmac.compare_digest(row["verify_token_hash"], candidate):
                        return self.reply(200, query["hub.challenge"], "text/plain; charset=utf-8")
                    return self.reply(403, "verificação recusada", "text/plain; charset=utf-8")
                user = session_user(db, self.headers.get("Cookie", ""))
                if not user:
                    return self.reply(401, {"ok": False, "error": "não autenticado"})
                organization_id = allowed_org(user, query.get("organization_id", ""))
                if not organization_id:
                    return self.reply(403, {"ok": False, "error": "conta não autorizada"})
                if query.get("action") == "connection":
                    row = db.execute("SELECT organization_id,phone_number_id,waba_id,business_number,graph_version,status,connected_at,updated_at FROM whatsapp_connections WHERE organization_id=%s", (organization_id,)).fetchone()
                    return self.reply(200, {"ok": True, "connected": bool(row), "connection": row, "encryption_ready": bool(os.getenv("PULSEFLOW_ENCRYPTION_KEY"))})
                if query.get("action") == "messages":
                    rows = db.execute("SELECT wa_message_id,contact_phone,contact_name,direction,message_type,body,status,occurred_at FROM whatsapp_messages WHERE organization_id=%s ORDER BY occurred_at DESC LIMIT 500", (organization_id,)).fetchall()
                    return self.reply(200, {"ok": True, "messages": rows})
                return self.reply(404, {"ok": False, "error": "ação não encontrada"})
        except Exception:
            return self.reply(503, {"ok": False, "error": "integração indisponível"})

    def do_POST(self) -> None:
        query, payload = self.query(), self.body()
        try:
            with connect() as db:
                ensure_schema(db)
                if query.get("action") == "webhook":
                    return self.handle_webhook(db, query.get("organization_id", ""), payload)
                user = session_user(db, self.headers.get("Cookie", ""))
                if not user:
                    return self.reply(401, {"ok": False, "error": "não autenticado"})
                organization_id = allowed_org(user, str(payload.get("organization_id", "")))
                if not organization_id:
                    return self.reply(403, {"ok": False, "error": "conta não autorizada"})
                if query.get("action") == "connect":
                    required = ("phone_number_id", "access_token", "app_secret", "verify_token")
                    if any(not str(payload.get(item, "")).strip() for item in required):
                        return self.reply(400, {"ok": False, "error": "preencha os dados obrigatórios da Meta"})
                    encrypted_token = cipher().encrypt(str(payload["access_token"]).encode()).decode()
                    encrypted_secret = cipher().encrypt(str(payload["app_secret"]).encode()).decode()
                    verify_hash = hashlib.sha256(str(payload["verify_token"]).encode()).hexdigest()
                    db.execute("""
                        INSERT INTO whatsapp_connections(organization_id,phone_number_id,waba_id,business_number,access_token_enc,app_secret_enc,verify_token_hash,graph_version,status,updated_at)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'active',NOW())
                        ON CONFLICT(organization_id) DO UPDATE SET phone_number_id=EXCLUDED.phone_number_id,waba_id=EXCLUDED.waba_id,business_number=EXCLUDED.business_number,access_token_enc=EXCLUDED.access_token_enc,app_secret_enc=EXCLUDED.app_secret_enc,verify_token_hash=EXCLUDED.verify_token_hash,graph_version=EXCLUDED.graph_version,status='active',updated_at=NOW()
                    """, (organization_id, str(payload["phone_number_id"]).strip(), str(payload.get("waba_id", "")).strip(), str(payload.get("business_number", "")).strip(), encrypted_token, encrypted_secret, verify_hash, str(payload.get("graph_version", "v23.0")).strip()))
                    db.commit()
                    webhook_url = f"https://pulseflow-saas-alpha.vercel.app/api/whatsapp?action=webhook&organization_id={quote(organization_id)}"
                    return self.reply(200, {"ok": True, "webhook_url": webhook_url})
                if query.get("action") == "send":
                    return self.send_message(db, organization_id, payload)
                return self.reply(404, {"ok": False, "error": "ação não encontrada"})
        except InvalidToken:
            return self.reply(503, {"ok": False, "error": "credencial não pôde ser lida"})
        except Exception:
            return self.reply(503, {"ok": False, "error": "integração indisponível"})

    def handle_webhook(self, db, organization_id: str, payload: dict) -> None:
        row = db.execute("SELECT app_secret_enc FROM whatsapp_connections WHERE organization_id=%s AND status='active'", (organization_id,)).fetchone()
        if not row:
            return self.reply(404, {"ok": False})
        app_secret = cipher().decrypt(row["app_secret_enc"].encode())
        signature = self.headers.get("X-Hub-Signature-256", "")
        raw = getattr(self, "raw_body", b"")
        if signature and not hmac.compare_digest(signature, "sha256=" + hmac.new(app_secret, raw, hashlib.sha256).hexdigest()):
            return self.reply(401, {"ok": False})
        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                contacts = {item.get("wa_id", ""): item.get("profile", {}).get("name", "") for item in value.get("contacts", [])}
                for message in value.get("messages", []):
                    phone = message.get("from", "")
                    body = message.get("text", {}).get("body", "")
                    timestamp = message.get("timestamp")
                    db.execute("""
                        INSERT INTO whatsapp_messages(organization_id,wa_message_id,contact_phone,contact_name,direction,message_type,body,status,occurred_at,raw)
                        VALUES(%s,%s,%s,%s,'in',%s,%s,'received',COALESCE(to_timestamp(%s),NOW()),%s::jsonb)
                        ON CONFLICT(organization_id,wa_message_id) DO NOTHING
                    """, (organization_id, message.get("id") or secrets.token_urlsafe(18), phone, contacts.get(phone, ""), message.get("type", "unknown"), body, timestamp, json.dumps(message)))
                for status in value.get("statuses", []):
                    db.execute("UPDATE whatsapp_messages SET status=%s WHERE organization_id=%s AND wa_message_id=%s", (status.get("status", "sent"), organization_id, status.get("id", "")))
        db.commit()
        return self.reply(200, {"ok": True})

    def send_message(self, db, organization_id: str, payload: dict) -> None:
        row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s AND status='active'", (organization_id,)).fetchone()
        if not row:
            return self.reply(409, {"ok": False, "error": "WhatsApp oficial não conectado"})
        destination, body = str(payload.get("to", "")).strip(), str(payload.get("text", "")).strip()
        if not destination or not body:
            return self.reply(400, {"ok": False, "error": "destinatário e mensagem são obrigatórios"})
        token = cipher().decrypt(row["access_token_enc"].encode()).decode()
        url = f"https://graph.facebook.com/{row['graph_version']}/{row['phone_number_id']}/messages"
        request_body = json.dumps({"messaging_product": "whatsapp", "recipient_type": "individual", "to": destination, "type": "text", "text": {"preview_url": False, "body": body}}).encode()
        request = urllib.request.Request(url, data=request_body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                result = json.loads(response.read())
        except urllib.error.HTTPError as error:
            return self.reply(502, {"ok": False, "error": "a Meta recusou o envio", "status": error.code})
        message_id = (result.get("messages") or [{}])[0].get("id") or secrets.token_urlsafe(18)
        db.execute("INSERT INTO whatsapp_messages(organization_id,wa_message_id,contact_phone,direction,message_type,body,status,raw) VALUES(%s,%s,%s,'out','text',%s,'sent',%s::jsonb) ON CONFLICT(organization_id,wa_message_id) DO NOTHING", (organization_id, message_id, destination, body, json.dumps(result)))
        db.commit()
        return self.reply(200, {"ok": True, "message_id": message_id})
