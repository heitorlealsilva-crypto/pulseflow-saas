"""Autenticação, isolamento por empresa e administração do PulseFlow."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import psycopg
from psycopg.rows import dict_row

MAX_BODY_BYTES = 2_000_000
LEGAL_VERSION = "2026-09-20"
PERMISSIONS = ("workspace_read", "workspace_write", "manage_settings", "whatsapp_read", "whatsapp_send", "whatsapp_manage")
WORKSPACE_TYPES = {
    "leads": list, "columns": list, "postSaleColumns": list, "cadence": list,
    "automations": list, "automationRuns": list,
    "reminders": list, "notifications": list, "manualApprovals": list,
    "postSaleCustomers": list, "whatsappImported": list,
    "whatsapp": dict, "businessProfile": dict, "ai": dict, "settings": dict,
    "integrations": dict, "templates": dict, "pipelineBoard": str,
    "schemaVersion": int, "manualCadenceVersion": int,
}
SETTINGS_FIELDS = {"columns", "postSaleColumns", "cadence", "automations", "whatsapp", "businessProfile", "settings", "integrations", "templates"}
AI_RUNTIME_FIELDS = {"memories", "feedback", "lastLearnedAt"}
SECRET_FIELDS = {"password", "passwordhash", "token", "accesstoken", "refreshtoken", "appsecret", "verifytoken", "apikey", "secret", "authorization", "cookie", "session", "credentials", "accesstokenenc", "appsecretenc"}
_SCHEMA_READY_FOR = None


class RequestError(ValueError):
    def __init__(self, message, status=400, **details):
        super().__init__(message)
        self.status, self.details = status, details


def utcnow():
    return datetime.now(timezone.utc)


def database_url():
    return os.getenv("DATABASE_URL") or os.getenv("STORAGE_URL") or ""


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def password_valid(password, encoded):
    try:
        algorithm, rounds, salt_hex, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= int(rounds) <= 1_000_000:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError, AttributeError):
        return False


def connect():
    if not database_url():
        raise RuntimeError("banco não configurado")
    return psycopg.connect(database_url(), row_factory=dict_row, connect_timeout=10)


def ensure_schema(db):
    global _SCHEMA_READY_FOR
    if database_url() and _SCHEMA_READY_FOR == database_url():
        return
    db.execute("SELECT pg_advisory_xact_lock(817405201)")
    statements = ["""
        CREATE TABLE IF NOT EXISTS organizations (
            id UUID PRIMARY KEY, name TEXT NOT NULL, plan TEXT NOT NULL DEFAULT 'Base',
            niche TEXT NOT NULL DEFAULT '', whatsapp TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active', permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())
    """, "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb", """
        CREATE TABLE IF NOT EXISTS users (
            id UUID PRIMARY KEY, organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
            name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'owner', status TEXT NOT NULL DEFAULT 'active',
            legal_version TEXT, legal_accepted_at TIMESTAMPTZ,
            last_login_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())
    """, "ALTER TABLE users ADD COLUMN IF NOT EXISTS legal_version TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS legal_accepted_at TIMESTAMPTZ", """
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())
    """, "CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS users_org_idx ON users(organization_id)", """
        CREATE TABLE IF NOT EXISTS team_invites (
            id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            invited_by UUID REFERENCES users(id) ON DELETE SET NULL, name TEXT NOT NULL, email TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL, accepted_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())
    """, "CREATE INDEX IF NOT EXISTS team_invites_org_idx ON team_invites(organization_id, expires_at DESC)", """
        CREATE TABLE IF NOT EXISTS tenant_workspaces (
            organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            state JSONB NOT NULL DEFAULT '{}'::jsonb, revision BIGINT NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())
    """, "ALTER TABLE tenant_workspaces ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0", """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGSERIAL PRIMARY KEY, actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
            organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
            action TEXT NOT NULL, metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())
    """, "CREATE INDEX IF NOT EXISTS audit_org_idx ON audit_logs(organization_id, created_at DESC)", """
        CREATE TABLE IF NOT EXISTS auth_rate_limits (
            bucket_hash TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 1,
            resets_at TIMESTAMPTZ NOT NULL)
    """, "CREATE INDEX IF NOT EXISTS auth_rate_limits_expiry_idx ON auth_rate_limits(resets_at)"]
    for statement in statements:
        db.execute(statement)
    admin_email = os.getenv("PULSEFLOW_ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("PULSEFLOW_ADMIN_PASSWORD", "")
    if admin_email and len(admin_password) >= 12:
        exists = db.execute("SELECT 1 FROM users WHERE email=%s", (admin_email,)).fetchone()
        if not exists:
            # Never promote an existing customer through an environment variable.
            db.execute("""INSERT INTO users(id,organization_id,name,email,password_hash,role)
                          VALUES(%s,NULL,%s,%s,%s,'super_admin') ON CONFLICT(email) DO NOTHING""",
                       (uuid.uuid4(), "Administrador PulseFlow", admin_email, password_hash(admin_password)))
    db.commit()
    _SCHEMA_READY_FOR = database_url() or None


def public_user(row):
    return {key: row.get(key) for key in ("id", "name", "email", "role", "status", "organization_id")}


def public_account(row):
    if not row:
        return None
    account = {key: row.get(key) for key in ("id", "name", "plan", "status")}
    configured = row.get("permissions") or {}
    account["permissions"] = {key: configured.get(key, True) is True for key in PERMISSIONS}
    return account


def require_permission(user, account, permission):
    if user["role"] == "super_admin":
        return
    if account["status"] != "active" or not account["permissions"][permission]:
        raise RequestError("acesso não autorizado para esta conta", 403)


def organization_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise RequestError("identificador de conta inválido")


def _clean_value(value, depth=0):
    if depth > 16:
        raise RequestError("dados excedem a profundidade permitida")
    if isinstance(value, dict):
        if len(value) > 1000:
            raise RequestError("objeto excede o limite de campos")
        return {key: _clean_value(child, depth + 1) for key, child in value.items()
                if len(key) <= 100 and re.sub(r"[^a-z]", "", key.lower()) not in SECRET_FIELDS}
    if isinstance(value, list):
        if len(value) > 20000:
            raise RequestError("lista excede o limite de itens")
        return [_clean_value(child, depth + 1) for child in value]
    if isinstance(value, str) and len(value) > 100000:
        raise RequestError("texto excede o limite de tamanho")
    return value


def clean_workspace(workspace):
    if not isinstance(workspace, dict):
        raise RequestError("dados da conta inválidos")
    result = {}
    for key, value in workspace.items():
        expected = WORKSPACE_TYPES.get(key)
        if expected is None:
            continue
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise RequestError(f"formato inválido no campo {key}")
        result[key] = _clean_value(value)
    return result


def normalized_origin(value):
    parsed = urlparse(value or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        return None
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        return None
    try:
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Never include cookies or query strings in application logs.
        return

    def reply(self, status, value, cookie=None):
        raw = json.dumps(value, ensure_ascii=False, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise RequestError("tamanho de requisição inválido")
        if length < 0:
            raise RequestError("tamanho de requisição inválido")
        if length > MAX_BODY_BYTES:
            raise RequestError("dados da conta excedem o limite", 413)
        if self.headers.get("Transfer-Encoding"):
            raise RequestError("formato de requisição não suportado")
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise RequestError("envie dados no formato JSON", 415)
        try:
            def reject_constant(_):
                raise ValueError("JSON inválido")
            result = json.loads(self.rfile.read(length) or b"{}", parse_constant=reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise RequestError("JSON inválido")
        if not isinstance(result, dict):
            raise RequestError("JSON deve ser um objeto")
        return result

    def check_origin(self):
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise RequestError("origem da requisição não autorizada", 403)
        origin = normalized_origin(self.headers.get("Origin") or self.headers.get("Referer"))
        host = self.headers.get("Host", "")
        expected = normalized_origin("https://" + host)
        local = normalized_origin("http://" + host)
        configured = normalized_origin(os.getenv("PULSEFLOW_APP_URL", ""))
        if not origin or origin not in {expected, local, configured}:
            raise RequestError("origem da requisição não autorizada", 403)

    def action(self):
        return parse_qs(urlparse(self.path).query).get("action", [""])[0]

    def session_token(self):
        try:
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return jar.get("pulseflow_session").value if jar.get("pulseflow_session") else ""
        except cookies.CookieError:
            return ""

    def current_user(self, db):
        token = self.session_token()
        if not token or len(token) > 256:
            return None
        return db.execute("""
            SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
            LEFT JOIN organizations o ON o.id=u.organization_id
            WHERE s.token_hash=%s AND s.expires_at>NOW() AND u.status='active'
            AND (u.role='super_admin' OR o.status='active')
        """, (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()

    def requested_organization(self):
        return parse_qs(urlparse(self.path).query).get("organization_id", [""])[0]

    def allowed_organization(self, user, requested):
        own = str(user.get("organization_id") or "")
        if user["role"] == "super_admin":
            return organization_uuid(requested) if requested else None
        return own if own and (not requested or requested == own) else None

    def account(self, db, organization_id, locked=False):
        row = db.execute("SELECT id,name,plan,status,permissions FROM organizations WHERE id=%s" + (" FOR UPDATE" if locked else ""), (organization_id,)).fetchone()
        if not row:
            raise RequestError("conta não encontrada", 404)
        return public_account(row)

    def audit(self, db, user, organization_id, action, metadata=None):
        db.execute("INSERT INTO audit_logs(actor_user_id,organization_id,action,metadata) VALUES(%s,%s,%s,%s::jsonb)",
                   (user["id"], organization_id, action, json.dumps(metadata or {})))

    def client_ip(self):
        address = self.client_address[0]
        if os.getenv("VERCEL"):
            address = self.headers.get("X-Vercel-Forwarded-For", address).split(",", 1)[0].strip()
        try:
            return str(ipaddress.ip_address(address))
        except ValueError:
            return "unknown"

    def rate_limit(self, db, action, email=""):
        buckets = [(f"{action}:ip:{self.client_ip()}", 60 if action == "login" else 10)]
        if action == "login":
            buckets.append((f"login:email:{email}", 8))
        denied = False
        seconds = 900 if action == "login" else 3600
        for raw_key, maximum in buckets:
            row = db.execute("""
                INSERT INTO auth_rate_limits(bucket_hash,attempts,resets_at)
                VALUES(%s,1,NOW() + (%s * INTERVAL '1 second'))
                ON CONFLICT(bucket_hash) DO UPDATE SET
                    attempts=CASE WHEN auth_rate_limits.resets_at<=NOW() THEN 1 ELSE auth_rate_limits.attempts+1 END,
                    resets_at=CASE WHEN auth_rate_limits.resets_at<=NOW() THEN EXCLUDED.resets_at ELSE auth_rate_limits.resets_at END
                RETURNING attempts
            """, (hashlib.sha256(raw_key.encode()).hexdigest(), seconds)).fetchone()
            denied = denied or row["attempts"] > maximum
        db.execute("DELETE FROM auth_rate_limits WHERE resets_at < NOW() - INTERVAL '1 day'")
        db.commit()
        if denied:
            raise RequestError("muitas tentativas; aguarde antes de tentar novamente", 429)

    def do_GET(self):
        try:
            with connect() as db:
                ensure_schema(db)
                action = self.action()
                if action == "health":
                    admin = db.execute("SELECT 1 FROM users WHERE role='super_admin' AND status='active' LIMIT 1").fetchone()
                    return self.reply(200, {"ok": True, "database": True, "adminConfigured": bool(admin)})
                user = self.current_user(db)
                if not user:
                    raise RequestError("não autenticado", 401)
                if action == "me":
                    account = self.account(db, user["organization_id"]) if user["organization_id"] else None
                    return self.reply(200, {"ok": True, "user": public_user(user), "account": account})
                if action == "admin":
                    if user["role"] != "super_admin":
                        raise RequestError("acesso restrito", 403)
                    accounts = db.execute("SELECT o.*,COUNT(u.id)::int AS users_count FROM organizations o LEFT JOIN users u ON u.organization_id=o.id GROUP BY o.id ORDER BY o.created_at DESC").fetchall()
                    for row in accounts:
                        row["permissions"] = public_account(row)["permissions"]
                    users = db.execute("SELECT u.id,u.name,u.email,u.role,u.status,u.last_login_at,u.created_at,u.organization_id,o.name AS organization_name FROM users u LEFT JOIN organizations o ON o.id=u.organization_id ORDER BY u.created_at DESC").fetchall()
                    audits = db.execute("SELECT a.id,a.action,a.metadata,a.created_at,a.organization_id,o.name AS organization_name,u.name AS actor_name FROM audit_logs a LEFT JOIN organizations o ON o.id=a.organization_id LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 100").fetchall()
                    return self.reply(200, {"ok": True, "accounts": accounts, "users": users, "audits": audits,
                                           "summary": {"accounts": len(accounts), "users": len(users), "active": sum(item["status"] == "active" for item in users)}})
                if action == "team":
                    organization_id = self.allowed_organization(user, self.requested_organization())
                    if not organization_id:
                        raise RequestError("conta não autorizada", 403)
                    account = self.account(db, organization_id)
                    require_permission(user, account, "workspace_read")
                    members = db.execute("""SELECT id,name,email,role,status,last_login_at,created_at
                        FROM users WHERE organization_id=%s ORDER BY role='owner' DESC,created_at""", (organization_id,)).fetchall()
                    invites = db.execute("""SELECT id,name,email,expires_at,created_at FROM team_invites
                        WHERE organization_id=%s AND accepted_at IS NULL AND expires_at>NOW() ORDER BY created_at DESC""", (organization_id,)).fetchall()
                    return self.reply(200, {"ok": True, "members": members,
                        "invites": invites, "limit": 3 if account["plan"] == "Equipe" else 1, "plan": account["plan"]})
                if action == "workspace":
                    organization_id = self.allowed_organization(user, self.requested_organization())
                    if not organization_id:
                        raise RequestError("conta não autorizada", 403)
                    account = self.account(db, organization_id)
                    require_permission(user, account, "workspace_read")
                    row = db.execute("SELECT state,revision,updated_at FROM tenant_workspaces WHERE organization_id=%s", (organization_id,)).fetchone()
                    if user["role"] == "super_admin":
                        self.audit(db, user, organization_id, "support.workspace.opened")
                        db.commit()
                    return self.reply(200, {"ok": True, "account": account, "workspace": clean_workspace(row["state"]) if row else None,
                                           "revision": row["revision"] if row else 0, "updated_at": row["updated_at"] if row else None})
                raise RequestError("ação não encontrada", 404)
        except RequestError as error:
            return self.reply(error.status, {"ok": False, "error": str(error), **error.details})
        except Exception:
            return self.reply(503, {"ok": False, "error": "serviço indisponível"})

    def do_POST(self):
        try:
            self.check_origin()
            payload = self.body()
            with connect() as db:
                ensure_schema(db)
                action = self.action()
                if action in ("register", "login"):
                    return self.authenticate(db, action, payload)
                if action == "accept-invite":
                    return self.accept_invite(db, payload)
                if action == "logout":
                    token = self.session_token()
                    if token:
                        db.execute("DELETE FROM sessions WHERE token_hash=%s", (hashlib.sha256(token.encode()).hexdigest(),))
                        db.commit()
                    return self.reply(200, {"ok": True}, "pulseflow_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
                user = self.current_user(db)
                if not user:
                    raise RequestError("não autenticado", 401)
                if action == "workspace":
                    return self.save_workspace(db, user, payload)
                if action == "team-user":
                    return self.manage_team_user(db, user, payload)
                if action == "team-invite":
                    return self.manage_team_invite(db, user, payload)
                if action == "change-password":
                    return self.change_password(db, user, payload)
                if action in ("admin-account", "admin-user"):
                    if user["role"] != "super_admin":
                        raise RequestError("acesso restrito", 403)
                    return self.update_account(db, user, payload) if action == "admin-account" else self.update_user(db, user, payload)
                raise RequestError("ação não encontrada", 404)
        except RequestError as error:
            return self.reply(error.status, {"ok": False, "error": str(error), **error.details})
        except psycopg.errors.UniqueViolation:
            return self.reply(409, {"ok": False, "error": "e-mail já cadastrado"})
        except Exception:
            return self.reply(503, {"ok": False, "error": "serviço indisponível"})

    def authenticate(self, db, action, payload):
        email, password = payload.get("email", ""), payload.get("password", "")
        if not isinstance(email, str) or not isinstance(password, str) or len(email) > 254 or len(password) > 1024:
            raise RequestError("e-mail ou senha inválidos")
        email = email.strip().lower()
        self.rate_limit(db, action, email)
        if action == "register":
            name, company = payload.get("name"), payload.get("company")
            if not isinstance(name, str) or not name.strip() or len(name) > 160 or not isinstance(company, str) or not company.strip() or len(company) > 200:
                raise RequestError("preencha nome e empresa")
            if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise RequestError("informe um e-mail válido")
            if len(password) < 8:
                raise RequestError("a senha precisa ter pelo menos 8 caracteres")
            if payload.get("legal_accepted") is not True or payload.get("legal_version") != LEGAL_VERSION:
                raise RequestError("aceite os Termos de Uso e a Política de Privacidade")
            if db.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
                raise RequestError("e-mail já cadastrado", 409)
            org_id, user_id = uuid.uuid4(), uuid.uuid4()
            db.execute("INSERT INTO organizations(id,name,niche,whatsapp) VALUES(%s,%s,%s,%s)",
                       (org_id, company.strip(), str(payload.get("niche", ""))[:160], str(payload.get("whatsapp", ""))[:32]))
            db.execute("""INSERT INTO users(id,organization_id,name,email,password_hash,role,legal_version,legal_accepted_at)
                VALUES(%s,%s,%s,%s,%s,'owner',%s,NOW())""",
                       (user_id, org_id, name.strip(), email, password_hash(password), LEGAL_VERSION))
            self.audit(db, {"id": user_id}, org_id, "legal.accepted", {"version": LEGAL_VERSION, "source": "registration"})
            return self._create_session(db, user_id)
        user = db.execute("SELECT u.* FROM users u LEFT JOIN organizations o ON o.id=u.organization_id WHERE u.email=%s AND u.status='active' AND (u.role='super_admin' OR o.status='active')", (email,)).fetchone()
        encoded = user["password_hash"] if user else "pbkdf2_sha256$210000$00000000000000000000000000000000$" + "0" * 64
        if not password_valid(password, encoded) or not user:
            raise RequestError("e-mail ou senha inválidos", 401)
        return self._create_session(db, user["id"])

    def save_workspace(self, db, user, payload):
        organization_id = self.allowed_organization(user, str(payload.get("organization_id", "")))
        if not organization_id:
            raise RequestError("conta não autorizada", 403)
        revision = payload.get("revision")
        if type(revision) is not int or revision < 0:
            raise RequestError("recarregue a conta antes de salvar: revisão obrigatória", 428)
        workspace = clean_workspace(payload.get("state"))
        # The account lock also serializes first saves when no workspace row exists.
        account = self.account(db, organization_id, locked=True)
        require_permission(user, account, "workspace_write")
        current = db.execute("SELECT state,revision FROM tenant_workspaces WHERE organization_id=%s FOR UPDATE", (organization_id,)).fetchone()
        current_revision = current["revision"] if current else 0
        if revision != current_revision:
            raise RequestError("esta conta foi alterada em outra sessão; recarregue antes de salvar", 409, revision=current_revision)
        previous = clean_workspace(current["state"]) if current else {}
        if user["role"] != "super_admin" and not account["permissions"]["manage_settings"]:
            previous_ai = {key: value for key, value in previous.get("ai", {}).items() if key not in AI_RUNTIME_FIELDS}
            workspace_ai = {key: value for key, value in workspace.get("ai", {}).items() if key not in AI_RUNTIME_FIELDS}
            if any(previous.get(key) != workspace.get(key) for key in SETTINGS_FIELDS) or previous_ai != workspace_ai:
                raise RequestError("alteração de configurações não autorizada", 403)
        encoded = json.dumps(workspace, ensure_ascii=False)
        if len(encoded.encode()) > MAX_BODY_BYTES:
            raise RequestError("dados da conta excedem o limite", 413)
        saved = db.execute("""INSERT INTO tenant_workspaces(organization_id,state,revision,updated_at)
            VALUES(%s,%s::jsonb,%s,NOW()) ON CONFLICT(organization_id) DO UPDATE
            SET state=EXCLUDED.state,revision=EXCLUDED.revision,updated_at=NOW() RETURNING revision,updated_at""",
                           (organization_id, encoded, current_revision + 1)).fetchone()
        business = workspace.get("businessProfile", {})
        number = workspace.get("whatsapp", {}).get("number", "")
        niche = str(business.get("customNiche") or business.get("niche") or "")[:160]
        company_name = str(workspace.get("whatsapp", {}).get("businessName") or account["name"]).strip()[:200] or account["name"]
        db.execute("UPDATE organizations SET name=%s,niche=%s,whatsapp=%s WHERE id=%s", (company_name, niche, str(number)[:32], organization_id))
        account["name"] = company_name
        if user["role"] == "super_admin":
            self.audit(db, user, organization_id, "support.workspace.updated", {"revision": saved["revision"], "changed_fields": sorted(key for key in set(previous) | set(workspace) if previous.get(key) != workspace.get(key))})
        db.commit()
        return self.reply(200, {"ok": True, "account": account, **saved})

    def update_account(self, db, user, payload):
        organization_id = organization_uuid(payload.get("organization_id"))
        account = self.account(db, organization_id, locked=True)
        changes = {}
        if "status" in payload:
            if payload["status"] not in ("active", "suspended"):
                raise RequestError("status inválido")
            changes["status"] = payload["status"]
        if "plan" in payload:
            if payload["plan"] not in ("Base", "Equipe"):
                raise RequestError("plano inválido")
            changes["plan"] = payload["plan"]
        if "permissions" in payload:
            permissions = payload["permissions"]
            if not isinstance(permissions, dict) or any(key not in PERMISSIONS or type(value) is not bool for key, value in permissions.items()):
                raise RequestError("permissões inválidas")
            changes["permissions"] = {**account["permissions"], **permissions}
        if not changes:
            raise RequestError("informe uma alteração de conta")
        account.update(changes)
        db.execute("UPDATE organizations SET status=%s,plan=%s,permissions=%s::jsonb WHERE id=%s", (account["status"], account["plan"], json.dumps(account["permissions"]), organization_id))
        if account["status"] == "suspended":
            db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE organization_id=%s)", (organization_id,))
        self.audit(db, user, organization_id, "admin.account.updated", changes)
        db.commit()
        return self.reply(200, {"ok": True, "account": account, "status": account["status"]})

    def update_user(self, db, user, payload):
        user_id = organization_uuid(payload.get("user_id"))
        status = payload.get("status")
        if status not in ("active", "suspended"):
            raise RequestError("status inválido")
        target = db.execute("SELECT id,organization_id,role FROM users WHERE id=%s FOR UPDATE", (user_id,)).fetchone()
        if not target:
            raise RequestError("usuário não encontrado", 404)
        if target["role"] == "super_admin":
            raise RequestError("o acesso de administradores globais não pode ser alterado aqui", 403)
        db.execute("UPDATE users SET status=%s WHERE id=%s", (status, user_id))
        if status == "suspended":
            db.execute("DELETE FROM sessions WHERE user_id=%s", (user_id,))
        self.audit(db, user, target["organization_id"], f"admin.user.{status}", {"user_id": user_id})
        db.commit()
        return self.reply(200, {"ok": True, "user_id": user_id, "status": status})

    def manage_team_user(self, db, user, payload):
        organization_id = self.allowed_organization(user, str(payload.get("organization_id", "")))
        if not organization_id:
            raise RequestError("conta não autorizada", 403)
        if user["role"] not in ("owner", "super_admin"):
            raise RequestError("somente o proprietário pode gerenciar a equipe", 403)
        account = self.account(db, organization_id, locked=True)
        require_permission(user, account, "manage_settings")
        operation = payload.get("operation")
        if operation == "create":
            if account["plan"] != "Equipe":
                raise RequestError("adicione usuários somente no plano Equipe", 403)
            active = db.execute("SELECT COUNT(*)::int AS count FROM users WHERE organization_id=%s AND status='active'", (organization_id,)).fetchone()["count"]
            if active >= 3:
                raise RequestError("o plano Equipe permite até 3 usuários ativos", 409)
            name, email, password = payload.get("name"), payload.get("email"), payload.get("password")
            if not isinstance(name, str) or not name.strip() or len(name) > 160:
                raise RequestError("informe o nome do usuário")
            if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email.strip().lower()):
                raise RequestError("informe um e-mail válido")
            if not isinstance(password, str) or not 10 <= len(password) <= 1024:
                raise RequestError("a senha inicial precisa ter pelo menos 10 caracteres")
            member_id, email = uuid.uuid4(), email.strip().lower()
            db.execute("INSERT INTO users(id,organization_id,name,email,password_hash,role) VALUES(%s,%s,%s,%s,%s,'member')",
                       (member_id, organization_id, name.strip(), email, password_hash(password)))
            self.audit(db, user, organization_id, "team.user.created", {"user_id": str(member_id), "email": email})
            db.commit()
            return self.reply(200, {"ok": True, "user_id": member_id, "status": "active"})
        if operation == "status":
            member_id, status = organization_uuid(payload.get("user_id")), payload.get("status")
            if status not in ("active", "suspended"):
                raise RequestError("status inválido")
            target = db.execute("SELECT id,role,status FROM users WHERE id=%s AND organization_id=%s FOR UPDATE", (member_id, organization_id)).fetchone()
            if not target:
                raise RequestError("usuário não encontrado", 404)
            if target["role"] != "member":
                raise RequestError("o proprietário não pode ser alterado por esta ação", 403)
            if status == "active" and target["status"] != "active":
                active = db.execute("SELECT COUNT(*)::int AS count FROM users WHERE organization_id=%s AND status='active'", (organization_id,)).fetchone()["count"]
                if account["plan"] != "Equipe" or active >= 3:
                    raise RequestError("o plano atual não permite reativar este usuário", 409)
            db.execute("UPDATE users SET status=%s WHERE id=%s", (status, member_id))
            if status == "suspended":
                db.execute("DELETE FROM sessions WHERE user_id=%s", (member_id,))
            self.audit(db, user, organization_id, f"team.user.{status}", {"user_id": member_id})
            db.commit()
            return self.reply(200, {"ok": True, "user_id": member_id, "status": status})
        raise RequestError("operação de equipe inválida")

    def manage_team_invite(self, db, user, payload):
        organization_id = self.allowed_organization(user, str(payload.get("organization_id", "")))
        if not organization_id or user["role"] not in ("owner", "super_admin"):
            raise RequestError("somente o proprietário pode convidar a equipe", 403)
        account = self.account(db, organization_id, locked=True)
        require_permission(user, account, "manage_settings")
        operation = payload.get("operation")
        if operation == "cancel":
            invite_id = organization_uuid(payload.get("invite_id"))
            deleted = db.execute("DELETE FROM team_invites WHERE id=%s AND organization_id=%s AND accepted_at IS NULL RETURNING id", (invite_id, organization_id)).fetchone()
            if not deleted:
                raise RequestError("convite não encontrado", 404)
            self.audit(db, user, organization_id, "team.invite.cancelled", {"invite_id": invite_id})
            db.commit()
            return self.reply(200, {"ok": True})
        if operation != "create":
            raise RequestError("operação de convite inválida")
        if account["plan"] != "Equipe":
            raise RequestError("convites de equipe estão disponíveis no plano Equipe", 403)
        name, email = payload.get("name"), payload.get("email")
        if not isinstance(name, str) or not name.strip() or len(name) > 160:
            raise RequestError("informe o nome do vendedor")
        if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email.strip().lower()):
            raise RequestError("informe um e-mail válido")
        email = email.strip().lower()
        if db.execute("SELECT 1 FROM users WHERE email=%s", (email,)).fetchone():
            raise RequestError("e-mail já cadastrado", 409)
        db.execute("DELETE FROM team_invites WHERE accepted_at IS NULL AND expires_at<=NOW()")
        active = db.execute("SELECT COUNT(*)::int AS count FROM users WHERE organization_id=%s AND status='active'", (organization_id,)).fetchone()["count"]
        pending = db.execute("SELECT COUNT(*)::int AS count FROM team_invites WHERE organization_id=%s AND accepted_at IS NULL AND expires_at>NOW()", (organization_id,)).fetchone()["count"]
        if active + pending >= 3:
            raise RequestError("o plano Equipe permite até 3 usuários ou convites ativos", 409)
        db.execute("DELETE FROM team_invites WHERE organization_id=%s AND email=%s AND accepted_at IS NULL", (organization_id, email))
        token, invite_id = secrets.token_urlsafe(32), uuid.uuid4()
        db.execute("""INSERT INTO team_invites(id,organization_id,invited_by,name,email,token_hash,expires_at)
            VALUES(%s,%s,%s,%s,%s,%s,NOW()+INTERVAL '48 hours')""",
                   (invite_id, organization_id, user["id"], name.strip(), email, hashlib.sha256(token.encode()).hexdigest()))
        self.audit(db, user, organization_id, "team.invite.created", {"invite_id": str(invite_id), "email": email})
        db.commit()
        return self.reply(200, {"ok": True, "invite_id": invite_id, "invite_path": "/#invite=" + token, "expires_in_hours": 48})

    def accept_invite(self, db, payload):
        token, password = payload.get("token"), payload.get("password")
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            raise RequestError("convite inválido", 400)
        if not isinstance(password, str) or not 10 <= len(password) <= 1024:
            raise RequestError("a senha precisa ter pelo menos 10 caracteres")
        if payload.get("legal_accepted") is not True or payload.get("legal_version") != LEGAL_VERSION:
            raise RequestError("aceite os Termos de Uso e a Política de Privacidade")
        self.rate_limit(db, "accept-invite")
        invite = db.execute("""SELECT i.*,o.status AS organization_status,o.plan FROM team_invites i
            JOIN organizations o ON o.id=i.organization_id WHERE i.token_hash=%s FOR UPDATE""",
                            (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if not invite or invite["accepted_at"] or invite["expires_at"] <= utcnow() or invite["organization_status"] != "active":
            raise RequestError("convite inválido ou expirado", 410)
        active = db.execute("SELECT COUNT(*)::int AS count FROM users WHERE organization_id=%s AND status='active'", (invite["organization_id"],)).fetchone()["count"]
        if invite["plan"] != "Equipe" or active >= 3:
            raise RequestError("a conta atingiu o limite de usuários", 409)
        if db.execute("SELECT 1 FROM users WHERE email=%s", (invite["email"],)).fetchone():
            raise RequestError("este e-mail já possui acesso", 409)
        user_id = uuid.uuid4()
        db.execute("""INSERT INTO users(id,organization_id,name,email,password_hash,role,legal_version,legal_accepted_at)
            VALUES(%s,%s,%s,%s,%s,'member',%s,NOW())""",
                   (user_id, invite["organization_id"], invite["name"], invite["email"], password_hash(password), LEGAL_VERSION))
        db.execute("UPDATE team_invites SET accepted_at=NOW() WHERE id=%s", (invite["id"],))
        accepted_user = {"id": user_id, "organization_id": invite["organization_id"]}
        self.audit(db, accepted_user, invite["organization_id"], "team.invite.accepted", {"invite_id": str(invite["id"])})
        self.audit(db, accepted_user, invite["organization_id"], "legal.accepted", {"version": LEGAL_VERSION, "source": "team_invite"})
        return self._create_session(db, user_id)

    def change_password(self, db, user, payload):
        current, new = payload.get("current_password"), payload.get("new_password")
        if not isinstance(current, str) or not isinstance(new, str) or not 10 <= len(new) <= 1024:
            raise RequestError("a nova senha precisa ter pelo menos 10 caracteres")
        locked = db.execute("SELECT id,password_hash FROM users WHERE id=%s FOR UPDATE", (user["id"],)).fetchone()
        if not locked or not password_valid(current, locked["password_hash"]):
            raise RequestError("senha atual incorreta", 401)
        if password_valid(new, locked["password_hash"]):
            raise RequestError("escolha uma senha diferente da atual")
        db.execute("UPDATE users SET password_hash=%s WHERE id=%s", (password_hash(new), user["id"]))
        token = self.session_token()
        db.execute("DELETE FROM sessions WHERE user_id=%s AND token_hash<>%s", (user["id"], hashlib.sha256(token.encode()).hexdigest()))
        self.audit(db, user, user.get("organization_id"), "user.password.changed")
        db.commit()
        return self.reply(200, {"ok": True})

    def _create_session(self, db, user_id):
        token = secrets.token_urlsafe(32)
        expires = utcnow() + timedelta(days=30)
        db.execute("DELETE FROM sessions WHERE expires_at<=NOW()")
        old_token = self.session_token()
        if old_token:
            db.execute("DELETE FROM sessions WHERE token_hash=%s", (hashlib.sha256(old_token.encode()).hexdigest(),))
        db.execute("UPDATE users SET last_login_at=NOW() WHERE id=%s", (user_id,))
        db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(%s,%s,%s)", (hashlib.sha256(token.encode()).hexdigest(), user_id, expires))
        user = db.execute("SELECT * FROM users WHERE id=%s", (user_id,)).fetchone()
        account = self.account(db, user["organization_id"]) if user["organization_id"] else None
        db.commit()
        cookie = f"pulseflow_session={token}; Path=/; Max-Age=2592000; HttpOnly; Secure; SameSite=Lax"
        return self.reply(200, {"ok": True, "user": public_user(user), "account": account}, cookie)
