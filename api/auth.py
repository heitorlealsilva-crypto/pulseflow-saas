"""Autenticação multiempresa e administração global do MVP PulseFlow."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import psycopg
from psycopg.rows import dict_row


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def database_url() -> str:
    return os.getenv("STORAGE_URL") or os.getenv("DATABASE_URL") or ""


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def password_valid(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt_hex, expected = encoded.split("$", 3)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def connect():
    url = database_url()
    if not url:
        raise RuntimeError("banco não configurado")
    return psycopg.connect(url, row_factory=dict_row)


def ensure_schema(db) -> None:
    statements = ["""
        CREATE TABLE IF NOT EXISTS organizations (
            id UUID PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'Base',
            niche TEXT NOT NULL DEFAULT '', whatsapp TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """, """
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY, organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'owner', status TEXT NOT NULL DEFAULT 'active',
            last_login_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """, """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """, "CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS users_org_idx ON users(organization_id)", """
        CREATE TABLE IF NOT EXISTS tenant_workspaces (
            organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            state JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """, """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGSERIAL PRIMARY KEY, actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
            action TEXT NOT NULL, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """, "CREATE INDEX IF NOT EXISTS audit_org_idx ON audit_logs(organization_id, created_at DESC)"]
    for statement in statements:
        db.execute(statement)
    admin_email = os.getenv("PULSEFLOW_ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("PULSEFLOW_ADMIN_PASSWORD", "")
    if admin_email and admin_password:
        exists = db.execute("SELECT 1 FROM users WHERE email=%s", (admin_email,)).fetchone()
        if not exists:
            db.execute(
                "INSERT INTO users(id,organization_id,name,email,password_hash,role) VALUES(%s,NULL,%s,%s,%s,'super_admin')",
                (uuid.uuid4(), "Administrador PulseFlow", admin_email, password_hash(admin_password)),
            )
    db.commit()


def public_user(row: dict) -> dict:
    return {key: row.get(key) for key in ("id", "name", "email", "role", "status", "organization_id")}


class handler(BaseHTTPRequestHandler):
    def reply(self, status: int, value: dict, cookie: str | None = None) -> None:
        raw = json.dumps(value, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self) -> dict:
        try:
            return json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        except json.JSONDecodeError:
            return {}

    def action(self) -> str:
        return parse_qs(urlparse(self.path).query).get("action", [""])[0]

    def session_token(self) -> str:
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return jar.get("pulseflow_session").value if jar.get("pulseflow_session") else ""

    def current_user(self, db) -> dict | None:
        token = self.session_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        return db.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN organizations o ON o.id=u.organization_id WHERE s.token_hash=%s AND s.expires_at>NOW() AND u.status='active' AND (u.role='super_admin' OR o.status='active')",
            (token_hash,),
        ).fetchone()

    def requested_organization(self) -> str:
        return parse_qs(urlparse(self.path).query).get("organization_id", [""])[0]

    def allowed_organization(self, user: dict, requested: str) -> str | None:
        own = str(user.get("organization_id") or "")
        if user["role"] == "super_admin":
            return requested or None
        return own if not requested or requested == own else None

    def audit(self, db, user: dict, organization_id: str, action: str, metadata: dict | None = None) -> None:
        db.execute(
            "INSERT INTO audit_logs(actor_user_id,organization_id,action,metadata) VALUES(%s,%s,%s,%s::jsonb)",
            (user["id"], organization_id, action, json.dumps(metadata or {})),
        )

    def do_GET(self) -> None:
        try:
            with connect() as db:
                ensure_schema(db)
                user = self.current_user(db)
                if self.action() == "health":
                    return self.reply(200, {"ok": True, "database": True, "adminConfigured": bool(os.getenv("PULSEFLOW_ADMIN_EMAIL") and os.getenv("PULSEFLOW_ADMIN_PASSWORD"))})
                if not user:
                    return self.reply(401, {"ok": False, "error": "não autenticado"})
                if self.action() == "me":
                    return self.reply(200, {"ok": True, "user": public_user(user)})
                if self.action() == "admin":
                    if user["role"] != "super_admin":
                        return self.reply(403, {"ok": False, "error": "acesso restrito"})
                    accounts = db.execute("SELECT o.*,COUNT(u.id)::int AS users_count FROM organizations o LEFT JOIN users u ON u.organization_id=o.id GROUP BY o.id ORDER BY o.created_at DESC").fetchall()
                    users = db.execute("SELECT u.id,u.name,u.email,u.role,u.status,u.last_login_at,u.created_at,u.organization_id,o.name AS organization_name FROM users u LEFT JOIN organizations o ON o.id=u.organization_id ORDER BY u.created_at DESC").fetchall()
                    audits = db.execute("SELECT a.action,a.created_at,o.name AS organization_name,u.name AS actor_name FROM audit_logs a LEFT JOIN organizations o ON o.id=a.organization_id LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 30").fetchall()
                    return self.reply(200, {"ok": True, "accounts": accounts, "users": users, "audits": audits, "summary": {"accounts": len(accounts), "users": len(users), "active": sum(1 for item in users if item["status"] == "active")}})
                if self.action() == "workspace":
                    organization_id = self.allowed_organization(user, self.requested_organization())
                    if not organization_id:
                        return self.reply(403, {"ok": False, "error": "conta não autorizada"})
                    account = db.execute("SELECT id,name,plan,status FROM organizations WHERE id=%s", (organization_id,)).fetchone()
                    if not account:
                        return self.reply(404, {"ok": False, "error": "conta não encontrada"})
                    row = db.execute("SELECT state,updated_at FROM tenant_workspaces WHERE organization_id=%s", (organization_id,)).fetchone()
                    if user["role"] == "super_admin":
                        self.audit(db, user, organization_id, "support.workspace.opened")
                        db.commit()
                    return self.reply(200, {"ok": True, "account": account, "workspace": row["state"] if row else None, "updated_at": row["updated_at"] if row else None})
                return self.reply(404, {"ok": False, "error": "ação não encontrada"})
        except Exception:
            return self.reply(503, {"ok": False, "error": "serviço indisponível"})

    def do_POST(self) -> None:
        payload = self.body()
        try:
            with connect() as db:
                ensure_schema(db)
                action = self.action()
                if action == "register":
                    required = ("name", "email", "password", "company")
                    if any(not str(payload.get(item, "")).strip() for item in required):
                        return self.reply(400, {"ok": False, "error": "preencha nome, empresa, e-mail e senha"})
                    email = str(payload["email"]).strip().lower()
                    if len(str(payload["password"])) < 8:
                        return self.reply(400, {"ok": False, "error": "a senha precisa ter pelo menos 8 caracteres"})
                    if db.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
                        return self.reply(409, {"ok": False, "error": "e-mail já cadastrado"})
                    org_id, user_id = uuid.uuid4(), uuid.uuid4()
                    db.execute("INSERT INTO organizations(id,name,niche,whatsapp) VALUES(%s,%s,%s,%s)", (org_id, str(payload["company"]).strip(), str(payload.get("niche", "")).strip(), str(payload.get("whatsapp", "")).strip()))
                    db.execute("INSERT INTO users(id,organization_id,name,email,password_hash,role) VALUES(%s,%s,%s,%s,%s,'owner')", (user_id, org_id, str(payload["name"]).strip(), email, password_hash(str(payload["password"]))))
                    db.commit()
                    return self._create_session(db, user_id)
                if action == "login":
                    email = str(payload.get("email", "")).strip().lower()
                    user = db.execute("SELECT u.* FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.email=%s AND u.status='active' AND (u.role='super_admin' OR o.status='active')", (email,)).fetchone()
                    if not user or not password_valid(str(payload.get("password", "")), user["password_hash"]):
                        return self.reply(401, {"ok": False, "error": "e-mail ou senha inválidos"})
                    db.execute("UPDATE users SET last_login_at=NOW() WHERE id=%s", (user["id"],))
                    db.commit()
                    return self._create_session(db, user["id"])
                if action == "workspace":
                    user = self.current_user(db)
                    if not user:
                        return self.reply(401, {"ok": False, "error": "não autenticado"})
                    organization_id = self.allowed_organization(user, str(payload.get("organization_id", "")))
                    workspace = payload.get("state")
                    if not organization_id or not isinstance(workspace, dict):
                        return self.reply(403, {"ok": False, "error": "conta não autorizada"})
                    encoded = json.dumps(workspace, ensure_ascii=False)
                    if len(encoded.encode()) > 2_000_000:
                        return self.reply(413, {"ok": False, "error": "dados da conta excedem o limite"})
                    db.execute("INSERT INTO tenant_workspaces(organization_id,state,updated_at) VALUES(%s,%s::jsonb,NOW()) ON CONFLICT(organization_id) DO UPDATE SET state=EXCLUDED.state,updated_at=NOW()", (organization_id, encoded))
                    if user["role"] == "super_admin":
                        self.audit(db, user, organization_id, "support.workspace.updated")
                    db.commit()
                    return self.reply(200, {"ok": True})
                if action == "admin-account":
                    user = self.current_user(db)
                    if not user or user["role"] != "super_admin":
                        return self.reply(403, {"ok": False, "error": "acesso restrito"})
                    organization_id = str(payload.get("organization_id", ""))
                    status = str(payload.get("status", ""))
                    if status not in ("active", "suspended"):
                        return self.reply(400, {"ok": False, "error": "status inválido"})
                    updated = db.execute("UPDATE organizations SET status=%s WHERE id=%s RETURNING id", (status, organization_id)).fetchone()
                    if not updated:
                        return self.reply(404, {"ok": False, "error": "conta não encontrada"})
                    self.audit(db, user, organization_id, f"admin.account.{status}")
                    db.commit()
                    return self.reply(200, {"ok": True, "status": status})
                if action == "logout":
                    token = self.session_token()
                    if token:
                        db.execute("DELETE FROM sessions WHERE token_hash=%s", (hashlib.sha256(token.encode()).hexdigest(),))
                        db.commit()
                    return self.reply(200, {"ok": True}, "pulseflow_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
                return self.reply(404, {"ok": False, "error": "ação não encontrada"})
        except Exception:
            return self.reply(503, {"ok": False, "error": "serviço indisponível"})

    def _create_session(self, db, user_id) -> None:
        token = secrets.token_urlsafe(32)
        expires = utcnow() + timedelta(days=30)
        db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(%s,%s,%s)", (hashlib.sha256(token.encode()).hexdigest(), user_id, expires))
        user = db.execute("SELECT * FROM users WHERE id=%s", (user_id,)).fetchone()
        db.commit()
        cookie = f"pulseflow_session={token}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
        self.reply(200, {"ok": True, "user": public_user(user)}, cookie)
