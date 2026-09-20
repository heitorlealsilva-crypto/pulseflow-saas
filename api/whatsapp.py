"""Tenant-scoped WhatsApp Cloud API with explicit seller approval.

Webhook messages live outside workspace JSON, so incoming events never overwrite
a seller's notes. Send reservations are committed before contacting the provider;
ambiguous requests must never be retried automatically.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import unicodedata
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlencode, urlparse

MAX_BODY = 2_000_000
DEFAULT_APP_URL = "https://pulseflow-saas-alpha.vercel.app"
_SCHEMA_READY_FOR = None
PUBLIC_CONNECTION_FIELDS = ("organization_id", "phone_number_id", "waba_id", "business_number",
                            "graph_version", "status", "connected_at", "updated_at",
                            "meta_verified_at", "webhook_verified_at", "last_event_at")


class IntegrationError(Exception):
    def __init__(self, message, code="integration_unavailable", status=503):
        super().__init__(message)
        self.code, self.status = code, status


def connect():
    import psycopg
    from psycopg.rows import dict_row
    url = os.getenv("DATABASE_URL") or os.getenv("STORAGE_URL")
    if not url:
        raise IntegrationError("Banco de dados não configurado.", "database_not_configured")
    return psycopg.connect(url, row_factory=dict_row, connect_timeout=10)


def cipher():
    from cryptography.fernet import Fernet
    raw = os.getenv("PULSEFLOW_ENCRYPTION_KEY", "")
    if len(raw) < 32:
        raise IntegrationError("A criptografia da integração ainda não foi configurada pelo administrador.", "encryption_not_configured")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))


def decrypt(value):
    from cryptography.fernet import InvalidToken
    try:
        return cipher().decrypt(value.encode()).decode()
    except InvalidToken:
        raise IntegrationError("Reconecte as credenciais do WhatsApp: a chave de criptografia mudou.", "credentials_unreadable") from None


def ensure_schema(db):
    global _SCHEMA_READY_FOR
    schema_key = os.getenv("DATABASE_URL") or os.getenv("STORAGE_URL")
    if schema_key and _SCHEMA_READY_FOR == schema_key:
        return
    db.execute("SELECT pg_advisory_xact_lock(817405202)")
    statements = [
        "ALTER TABLE organizations ADD COLUMN IF NOT EXISTS permissions JSONB NOT NULL DEFAULT '{}'::jsonb",
        """CREATE TABLE IF NOT EXISTS whatsapp_connections (
            organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
            phone_number_id TEXT NOT NULL, waba_id TEXT NOT NULL DEFAULT '', business_number TEXT NOT NULL DEFAULT '',
            access_token_enc TEXT NOT NULL, app_secret_enc TEXT NOT NULL, verify_token_hash TEXT NOT NULL,
            graph_version TEXT NOT NULL DEFAULT 'v23.0', status TEXT NOT NULL DEFAULT 'configured',
            connected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )""",
        "ALTER TABLE whatsapp_connections ADD COLUMN IF NOT EXISTS meta_verified_at TIMESTAMPTZ",
        "ALTER TABLE whatsapp_connections ADD COLUMN IF NOT EXISTS webhook_verified_at TIMESTAMPTZ",
        "ALTER TABLE whatsapp_connections ADD COLUMN IF NOT EXISTS last_event_at TIMESTAMPTZ",
        "ALTER TABLE whatsapp_connections ALTER COLUMN status SET DEFAULT 'configured'",
        "UPDATE whatsapp_connections SET status='configured' WHERE status='active'",
        "CREATE SEQUENCE IF NOT EXISTS whatsapp_message_revision_seq",
        """CREATE TABLE IF NOT EXISTS whatsapp_messages (
            id BIGSERIAL PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            wa_message_id TEXT NOT NULL, contact_phone TEXT NOT NULL, contact_name TEXT NOT NULL DEFAULT '',
            direction TEXT NOT NULL, message_type TEXT NOT NULL DEFAULT 'text', body TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'received', occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            raw JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(organization_id, wa_message_id)
        )""",
        "ALTER TABLE whatsapp_messages ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
        "ALTER TABLE whatsapp_messages ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT nextval('whatsapp_message_revision_seq')",
        "CREATE INDEX IF NOT EXISTS wa_messages_org_phone_idx ON whatsapp_messages(organization_id,contact_phone,occurred_at DESC)",
        "CREATE INDEX IF NOT EXISTS wa_messages_org_revision_idx ON whatsapp_messages(organization_id,revision)",
        """CREATE TABLE IF NOT EXISTS whatsapp_send_requests (
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            request_id UUID NOT NULL, actor_user_id UUID NOT NULL REFERENCES users(id),
            lead_id TEXT NOT NULL, content_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'reserved',
            wa_message_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY(organization_id,request_id)
        )""",
        "CREATE INDEX IF NOT EXISTS wa_requests_recent_idx ON whatsapp_send_requests(organization_id,lead_id,created_at DESC)",
    ]
    for statement in statements:
        db.execute(statement)
    db.commit()
    _SCHEMA_READY_FOR = schema_key


def session_user(db, header):
    try:
        jar = cookies.SimpleCookie(header or "")
    except cookies.CookieError:
        return None
    if not jar.get("pulseflow_session"):
        return None
    token_hash = hashlib.sha256(jar["pulseflow_session"].value.encode()).hexdigest()
    return db.execute("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
        LEFT JOIN organizations o ON o.id=u.organization_id
        WHERE s.token_hash=%s AND s.expires_at>NOW() AND u.status='active'
        AND (u.role='super_admin' OR o.status='active')""", (token_hash,)).fetchone()


def normalized_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def allowed_org(user, requested):
    own = normalized_uuid(user.get("organization_id"))
    requested = normalized_uuid(requested) if requested else None
    if user.get("role") == "super_admin":
        return requested
    return own if not requested or requested == own else None


def account_access(db, user, organization_id, permission):
    row = db.execute("SELECT status,permissions FROM organizations WHERE id=%s", (organization_id,)).fetchone()
    if not row or row["status"] != "active":
        raise IntegrationError("A conta está suspensa ou indisponível.", "account_unavailable", 403)
    if user.get("role") != "super_admin" and (row.get("permissions") or {}).get(permission, True) is False:
        raise IntegrationError("Este recurso está desativado para esta conta.", "permission_denied", 403)


def request_origin_allowed(headers):
    if headers.get("Sec-Fetch-Site") == "cross-site":
        return False
    source = urlparse(headers.get("Origin") or headers.get("Referer") or "")
    if source.scheme not in ("https", "http") or not source.netloc or source.username or source.password:
        return False
    if source.scheme == "http" and source.hostname not in ("localhost", "127.0.0.1", "::1"):
        return False
    expected = urlparse(os.getenv("PULSEFLOW_APP_URL", DEFAULT_APP_URL))
    return source.netloc.lower() == headers.get("Host", "").lower() or (source.scheme, source.netloc.lower()) == (expected.scheme, expected.netloc.lower())


def valid_signature(secret, raw, signature):
    if not isinstance(signature, str) or not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature, expected)


def normalize_phone(value):
    raw = str(value or "").strip()
    if not re.fullmatch(r"[+\d\s().-]+", raw):
        return ""
    digits = re.sub(r"\D", "", raw)
    if len(digits) in (10, 11):
        digits = "55" + digits
    return digits if re.fullmatch(r"[1-9][0-9]{7,14}", digits) else ""


def timestamp(value):
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            seconds = float(value)
            return datetime.fromtimestamp(seconds / 1000 if seconds > 100_000_000_000 else seconds, timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def fold(value):
    return "".join(c for c in unicodedata.normalize("NFKD", str(value)).casefold() if not unicodedata.combining(c))


def send_guard(workspace, payload, latest_inbound=None, now=None):
    now = now or datetime.now(timezone.utc)
    if payload.get("approval") is not True or payload.get("automatic"):
        raise IntegrationError("Revise e autorize esta mensagem antes de enviar.", "approval_required", 409)
    if not normalized_uuid(payload.get("request_id")):
        raise IntegrationError("Identificador de envio inválido.", "invalid_request_id", 400)
    lead_id = str(payload.get("lead_id", ""))
    lead = next((item for item in workspace.get("leads", []) if str(item.get("id")) == lead_id), None)
    if not lead:
        raise IntegrationError("Lead não encontrado nesta conta. Sincronize antes de enviar.", "lead_not_found", 404)
    board = fold(lead.get("board") or "Principal").replace("-", "").replace(" ", "")
    if board in ("posvenda", "postsale") or any(str(item.get("leadId")) == lead_id for item in workspace.get("postSaleCustomers", [])):
        raise IntegrationError("O pós-venda está em modo de observação. Revise o contato com o responsável.", "observation_only", 409)
    if lead.get("optOut") or lead.get("opt_out") or lead.get("doNotContact"):
        raise IntegrationError("Este contato solicitou não receber mensagens.", "opted_out", 409)
    if lead.get("stage") == "closed":
        raise IntegrationError("O atendimento está fechado. Revise a etapa antes de enviar.", "lead_closed", 409)
    destination = normalize_phone(lead.get("phone"))
    if not destination:
        raise IntegrationError("Cadastre um número válido no lead.", "invalid_phone", 400)
    consent = lead.get("consentConfirmed") is True or any(
        normalize_phone(item.get("phone")) == destination and item.get("source") and item.get("purpose")
        and not item.get("revoked") and item.get("confirmed", True) is True
        for item in workspace.get("whatsappOfficial", {}).get("consents", []))
    if not consent:
        raise IntegrationError("Registre a autorização deste contato antes do envio.", "consent_required", 409)
    recorded = any(isinstance(call, dict) and call.get("id") and str(call.get("outcome", "")).strip()
                   and fold(call.get("outcome")) not in ("scheduled", "planned", "cancelled", "agendada", "cancelada")
                   and timestamp(call.get("at")) and timestamp(call.get("at")) <= now for call in lead.get("calls", []))
    if not recorded:
        raise IntegrationError("Registre a ligação realizada antes de enviar a primeira mensagem.", "call_required", 409)
    text, template = str(payload.get("text", "")).strip(), payload.get("template")
    if template is not None:
        if not isinstance(template, dict) or not re.fullmatch(r"[a-z0-9_]{1,512}", str(template.get("name", ""))) or not re.fullmatch(r"[a-z]{2}(?:_[A-Z]{2})?", str(template.get("language", ""))):
            raise IntegrationError("Selecione um template válido aprovado na Meta.", "invalid_template", 400)
        parameters = template.get("body_parameters", [])
        if not isinstance(parameters, list) or len(parameters) > 30 or any(not isinstance(item, str) or not item or len(item) > 1024 for item in parameters):
            raise IntegrationError("Parâmetros do template inválidos.", "invalid_template", 400)
    else:
        if not text or len(text) > 4096:
            raise IntegrationError("Escreva uma mensagem de até 4.096 caracteres.", "invalid_message", 400)
        incoming = timestamp(latest_inbound)
        if not incoming or not now - timedelta(hours=24) < incoming <= now:
            raise IntegrationError("Fora da janela de 24 horas, a Meta exige um template aprovado. Use o WhatsApp manual ou um template da sua conta.", "template_required", 409)
    return lead, destination, text, template


def connection_payload(row, organization_id):
    public = {key: row.get(key) for key in PUBLIC_CONNECTION_FIELDS} if row else None
    ready = bool(row and row.get("meta_verified_at") and row.get("webhook_verified_at"))
    encryption_ready = len(os.getenv("PULSEFLOW_ENCRYPTION_KEY", "")) >= 32
    meta_verified = bool(row and row.get("meta_verified_at"))
    webhook_verified = bool(row and row.get("webhook_verified_at"))
    if public:
        public["status"] = "ready" if ready else "configured"
    base = os.getenv("PULSEFLOW_APP_URL", DEFAULT_APP_URL).rstrip("/")
    return {"ok": True, "configured": bool(row), "ready": ready, "connected": ready,
            "encryption_ready": encryption_ready,
            "connection": public, "groups_supported": False,
            "setup": {
                "server_ready": encryption_ready,
                "credentials_saved": bool(row),
                "meta_verified": meta_verified,
                "webhook_verified": webhook_verified,
                "messages_subscribed": webhook_verified,
            },
            "webhook_url": f"{base}/api/whatsapp?action=webhook&organization_id={quote(str(organization_id))}"}


def graph_call(row, path, method="GET", payload=None):
    if not re.fullmatch(r"v\d{1,2}\.0", row["graph_version"]):
        raise IntegrationError("Versão da API inválida.", "invalid_graph_version", 400)
    request = urllib.request.Request(f"https://graph.facebook.com/{row['graph_version']}/{path}",
        data=json.dumps(payload).encode() if payload is not None else None, method=method,
        headers={"Authorization": f"Bearer {decrypt(row['access_token_enc'])}", "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read(MAX_BODY))


def validate_meta(db, organization_id, row):
    phone = graph_call(row, quote(row["phone_number_id"], safe="") + "?fields=id,display_phone_number")
    phones = graph_call(row, quote(row["waba_id"], safe="") + "/phone_numbers?fields=id&limit=100")
    if str(phone.get("id")) != row["phone_number_id"] or not any(str(item.get("id")) == row["phone_number_id"] for item in phones.get("data", [])):
        raise IntegrationError("O número não pertence à conta comercial informada.", "meta_account_mismatch", 409)
    db.execute("""UPDATE whatsapp_connections SET meta_verified_at=NOW(),
        status=CASE WHEN webhook_verified_at IS NOT NULL THEN 'ready' ELSE 'configured' END,updated_at=NOW()
        WHERE organization_id=%s""", (organization_id,))
    db.commit()


def template_payload(row, template):
    query = urlencode({"name": template["name"], "fields": "name,language,status,components", "limit": 100})
    result = graph_call(row, quote(row["waba_id"], safe="") + "/message_templates?" + query)
    approved = next((item for item in result.get("data", []) if item.get("name") == template["name"]
        and item.get("language") == template["language"] and item.get("status") == "APPROVED"), None)
    if not approved:
        raise IntegrationError("O template não está aprovado nesta conta da Meta.", "template_not_approved", 409)
    components = approved.get("components", [])
    if any(item.get("type") not in ("BODY", "FOOTER", "HEADER") or
        (item.get("type") == "HEADER" and (item.get("format") != "TEXT" or "{{" in item.get("text", ""))) for item in components):
        raise IntegrationError("Use um template de texto sem mídia ou botões nesta versão.", "template_not_supported", 409)
    body = next((item.get("text", "") for item in components if item.get("type") == "BODY"), "")
    parameters = template.get("body_parameters", [])
    placeholders = set(re.findall(r"\{\{(\d+)\}\}", body))
    if "{{" in re.sub(r"\{\{\d+\}\}", "", body) or placeholders != {str(index) for index in range(1, len(parameters) + 1)}:
        raise IntegrationError("Preencha todos os parâmetros do template aprovado.", "template_parameters_mismatch", 400)
    value = {"name": template["name"], "language": {"code": template["language"]}}
    if parameters:
        value["components"] = [{"type": "body", "parameters": [{"type": "text", "text": item} for item in parameters]}]
    for index, parameter in enumerate(parameters, 1):
        body = body.replace("{{" + str(index) + "}}", parameter)
    return value, body


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Webhook verification carries a secret in its query string.
        return

    def reply(self, status, value, content_type="application/json; charset=utf-8"):
        raw = (json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def failure(self, error):
        return self.reply(error.status, {"ok": False, "error": str(error), "code": error.code})

    def query(self):
        return {key: values[0] for key, values in parse_qs(urlparse(self.path).query).items()}

    def body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise IntegrationError("Tamanho inválido.", "invalid_body", 400) from None
        if not 0 < length <= MAX_BODY:
            raise IntegrationError("Requisição vazia ou muito grande.", "invalid_body", 413)
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            raise IntegrationError("Envie JSON.", "invalid_content_type", 415)
        self.raw_body = self.rfile.read(length)
        try:
            result = json.loads(self.raw_body)
        except (ValueError, UnicodeDecodeError):
            raise IntegrationError("JSON inválido.", "invalid_body", 400) from None
        if not isinstance(result, dict):
            raise IntegrationError("Objeto JSON obrigatório.", "invalid_body", 400)
        return result

    def authenticated_org(self, db, requested, permission):
        user = session_user(db, self.headers.get("Cookie", ""))
        if not user:
            raise IntegrationError("Entre na sua conta novamente.", "unauthenticated", 401)
        if requested and not normalized_uuid(requested):
            raise IntegrationError("Conta inválida.", "invalid_account", 400)
        organization_id = allowed_org(user, requested)
        if not organization_id:
            raise IntegrationError("Conta não autorizada.", "forbidden", 403)
        account_access(db, user, organization_id, permission)
        return user, organization_id

    def do_GET(self):
        query = self.query()
        try:
            with connect() as db:
                ensure_schema(db)
                if "hub.challenge" in query:
                    organization_id = normalized_uuid(query.get("organization_id"))
                    if not organization_id or query.get("action") != "webhook":
                        return self.reply(403, "verificação recusada", "text/plain; charset=utf-8")
                    row = db.execute("""SELECT w.verify_token_hash FROM whatsapp_connections w JOIN organizations o ON o.id=w.organization_id
                        WHERE w.organization_id=%s AND o.status='active'""", (organization_id,)).fetchone()
                    candidate = hashlib.sha256(query.get("hub.verify_token", "").encode()).hexdigest()
                    if query.get("hub.mode") != "subscribe" or not row or not hmac.compare_digest(row["verify_token_hash"], candidate):
                        return self.reply(403, "verificação recusada", "text/plain; charset=utf-8")
                    db.execute("""UPDATE whatsapp_connections SET webhook_verified_at=NOW(),
                        status=CASE WHEN meta_verified_at IS NOT NULL THEN 'ready' ELSE 'configured' END,updated_at=NOW()
                        WHERE organization_id=%s""", (organization_id,))
                    db.commit()
                    return self.reply(200, query["hub.challenge"], "text/plain; charset=utf-8")
                _, organization_id = self.authenticated_org(db, query.get("organization_id", ""), "whatsapp_read")
                if query.get("action") == "connection":
                    row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s", (organization_id,)).fetchone()
                    return self.reply(200, connection_payload(row, organization_id))
                if query.get("action") == "messages":
                    try:
                        cursor, limit = max(0, int(query.get("cursor", "0"))), min(200, max(1, int(query.get("limit", "100"))))
                        if cursor > 9_223_372_036_854_775_807:
                            raise ValueError
                    except ValueError:
                        raise IntegrationError("Cursor inválido.", "invalid_cursor", 400) from None
                    rows = db.execute("""SELECT id,revision,wa_message_id,contact_phone,contact_name,direction,message_type,body,status,occurred_at,updated_at
                        FROM whatsapp_messages WHERE organization_id=%s AND revision>%s ORDER BY revision ASC LIMIT %s""",
                        (organization_id, cursor, limit + 1)).fetchall()
                    page = rows[:limit]
                    return self.reply(200, {"ok": True, "messages": page, "next_cursor": str(page[-1]["revision"] if page else cursor), "has_more": len(rows) > limit})
                return self.reply(404, {"ok": False, "error": "Ação não encontrada."})
        except IntegrationError as error:
            return self.failure(error)
        except Exception:
            return self.reply(503, {"ok": False, "error": "Integração indisponível. Tente novamente mais tarde.", "code": "integration_unavailable"})

    def do_POST(self):
        try:
            query, payload = self.query(), self.body()
            if query.get("action") != "webhook" and not request_origin_allowed(self.headers):
                raise IntegrationError("Origem da requisição não autorizada.", "invalid_origin", 403)
            with connect() as db:
                ensure_schema(db)
                if query.get("action") == "webhook":
                    return self.handle_webhook(db, query.get("organization_id", ""), payload)
                permission = "whatsapp_send" if query.get("action") == "send" else "whatsapp_manage"
                user, organization_id = self.authenticated_org(db, str(payload.get("organization_id", "")), permission)
                if query.get("action") == "connect":
                    return self.save_connection(db, organization_id, payload)
                if query.get("action") == "validate":
                    row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s FOR UPDATE", (organization_id,)).fetchone()
                    if not row:
                        raise IntegrationError("Cadastre as credenciais primeiro.", "connection_missing", 409)
                    try:
                        validate_meta(db, organization_id, row)
                    except (urllib.error.URLError, ValueError, TimeoutError):
                        raise IntegrationError("Não foi possível validar as credenciais com a Meta.", "meta_validation_failed", 502) from None
                    row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s", (organization_id,)).fetchone()
                    return self.reply(200, connection_payload(row, organization_id))
                if query.get("action") == "send":
                    return self.send_message(db, organization_id, payload, user)
                return self.reply(404, {"ok": False, "error": "Ação não encontrada."})
        except IntegrationError as error:
            return self.failure(error)
        except Exception:
            return self.reply(503, {"ok": False, "error": "Integração indisponível. Nenhum envio será repetido automaticamente.", "code": "integration_unavailable"})

    def save_connection(self, db, organization_id, payload):
        encryption = cipher()
        required = ("phone_number_id", "waba_id", "access_token", "app_secret", "verify_token")
        if any(not isinstance(payload.get(key), str) or not payload[key].strip() for key in required):
            raise IntegrationError("Preencha todos os dados da Meta, incluindo a conta comercial.", "missing_credentials", 400)
        if any(len(payload[key]) > 8192 for key in required) or len(payload["verify_token"]) < 16:
            raise IntegrationError("Use um token de verificação com pelo menos 16 caracteres.", "invalid_credentials", 400)
        phone_id, waba_id = payload["phone_number_id"].strip(), payload["waba_id"].strip()
        version = str(payload.get("graph_version") or os.getenv("META_GRAPH_VERSION", "v23.0")).strip()
        if not re.fullmatch(r"\d{5,30}", phone_id) or not re.fullmatch(r"\d{5,30}", waba_id) or not re.fullmatch(r"v\d{1,2}\.0", version):
            raise IntegrationError("Identificadores ou versão da Meta inválidos.", "invalid_credentials", 400)
        db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", ("wa-phone:" + phone_id,))
        other = db.execute("SELECT organization_id FROM whatsapp_connections WHERE phone_number_id=%s AND organization_id<>%s", (phone_id, organization_id)).fetchone()
        if other:
            raise IntegrationError("Este número já está vinculado a outra conta.", "phone_already_connected", 409)
        db.execute("""INSERT INTO whatsapp_connections(organization_id,phone_number_id,waba_id,business_number,access_token_enc,app_secret_enc,verify_token_hash,graph_version,status)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'configured')
            ON CONFLICT(organization_id) DO UPDATE SET phone_number_id=EXCLUDED.phone_number_id,waba_id=EXCLUDED.waba_id,
            business_number=EXCLUDED.business_number,access_token_enc=EXCLUDED.access_token_enc,app_secret_enc=EXCLUDED.app_secret_enc,
            verify_token_hash=EXCLUDED.verify_token_hash,graph_version=EXCLUDED.graph_version,status='configured',
            meta_verified_at=NULL,webhook_verified_at=NULL,last_event_at=NULL,updated_at=NOW()""",
            (organization_id, phone_id, waba_id, str(payload.get("business_number", ""))[:40],
             encryption.encrypt(payload["access_token"].strip().encode()).decode(), encryption.encrypt(payload["app_secret"].strip().encode()).decode(),
             hashlib.sha256(payload["verify_token"].encode()).hexdigest(), version))
        db.commit()
        row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s FOR UPDATE", (organization_id,)).fetchone()
        warning, validation_code = None, None
        try:
            validate_meta(db, organization_id, row)
        except IntegrationError as error:
            db.rollback()
            warning, validation_code = str(error), error.code
        except (urllib.error.URLError, ValueError, TimeoutError):
            db.rollback()
            warning = "Credenciais salvas. A validação com a Meta ainda está pendente; revise os dados e clique em validar."
            validation_code = "meta_validation_failed"
        row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s", (organization_id,)).fetchone()
        result = connection_payload(row, organization_id)
        if warning:
            result["warning"] = warning
            result["validation_code"] = validation_code
        return self.reply(200, result)

    def handle_webhook(self, db, organization_id, payload):
        organization_id = normalized_uuid(organization_id)
        if not organization_id:
            return self.reply(403, {"ok": False})
        row = db.execute("""SELECT w.* FROM whatsapp_connections w JOIN organizations o ON o.id=w.organization_id
            WHERE w.organization_id=%s AND o.status='active' FOR UPDATE OF w""", (organization_id,)).fetchone()
        if not row or not valid_signature(decrypt(row["app_secret_enc"]), getattr(self, "raw_body", b""), self.headers.get("X-Hub-Signature-256", "")):
            return self.reply(401, {"ok": False})
        if payload.get("object") != "whatsapp_business_account" or not isinstance(payload.get("entry"), list):
            return self.reply(400, {"ok": False})
        values = []
        for entry in payload["entry"]:
            if not isinstance(entry, dict) or str(entry.get("id")) != row["waba_id"]:
                return self.reply(403, {"ok": False})
            for change in entry.get("changes", []):
                if change.get("field") != "messages":
                    continue
                value = change.get("value", {})
                if value.get("messaging_product") != "whatsapp" or str(value.get("metadata", {}).get("phone_number_id")) != row["phone_number_id"]:
                    return self.reply(403, {"ok": False})
                values.append(value)
        # Check the entire batch before writing; mismatched tenants never get inserted.
        for value in values:
            contacts = {item.get("wa_id", ""): str(item.get("profile", {}).get("name", ""))[:300] for item in value.get("contacts", [])}
            for message in value.get("messages", []):
                message_id, phone = message.get("id"), normalize_phone(message.get("from"))
                occurred_at = timestamp(message.get("timestamp"))
                if not isinstance(message_id, str) or not message_id or not phone or not occurred_at or occurred_at > datetime.now(timezone.utc) + timedelta(minutes=5):
                    continue
                kind = str(message.get("type", "unknown"))[:30]
                if message.get("group_id") or message.get("recipient_type") == "group":
                    continue
                body = str(message.get("text", {}).get("body", ""))[:4096] if kind == "text" else f"[{kind}: mídia recebida; visualização ainda indisponível]"
                db.execute("""INSERT INTO whatsapp_messages(organization_id,wa_message_id,contact_phone,contact_name,direction,message_type,body,status,occurred_at,raw)
                    VALUES(%s,%s,%s,%s,'in',%s,%s,'received',%s,%s::jsonb)
                    ON CONFLICT(organization_id,wa_message_id) DO NOTHING""",
                    (organization_id, message_id, phone, contacts.get(message.get("from"), ""), kind, body, occurred_at, json.dumps(message)))
            for event in value.get("statuses", []):
                status = event.get("status")
                if status not in ("sent", "delivered", "read", "failed"):
                    continue
                db.execute("""UPDATE whatsapp_messages SET status=%s,updated_at=NOW(),revision=nextval('whatsapp_message_revision_seq')
                    WHERE organization_id=%s AND wa_message_id=%s AND direction='out' AND status<>%s
                    AND ((%s='failed' AND status IN ('accepted','sent')) OR
                         (%s='sent' AND status='accepted') OR (%s='delivered' AND status IN ('accepted','sent')) OR
                         (%s='read' AND status IN ('accepted','sent','delivered')))""",
                    (status, organization_id, event.get("id", ""), status, status, status, status, status))
        db.execute("UPDATE whatsapp_connections SET last_event_at=NOW() WHERE organization_id=%s", (organization_id,))
        db.commit()
        return self.reply(200, {"ok": True})

    def send_message(self, db, organization_id, payload, user):
        row = db.execute("SELECT * FROM whatsapp_connections WHERE organization_id=%s FOR SHARE", (organization_id,)).fetchone()
        if not row or not row.get("meta_verified_at") or not row.get("webhook_verified_at"):
            raise IntegrationError("Valide as credenciais e o webhook da Meta antes de enviar.", "connection_not_ready", 409)
        workspace_row = db.execute("SELECT state FROM tenant_workspaces WHERE organization_id=%s FOR SHARE", (organization_id,)).fetchone()
        workspace = (workspace_row or {}).get("state") or {}
        lead = next((item for item in workspace.get("leads", []) if str(item.get("id")) == str(payload.get("lead_id", ""))), {})
        inbound = db.execute("""SELECT MAX(occurred_at) AS latest FROM whatsapp_messages WHERE organization_id=%s
            AND contact_phone=%s AND direction='in' AND occurred_at<=NOW()""", (organization_id, normalize_phone(lead.get("phone")))).fetchone()
        # Client-supplied call flags, consent flags and destination are ignored.
        lead, destination, body, template = send_guard(workspace, payload, (inbound or {}).get("latest"))
        content_hash = hashlib.sha256(json.dumps({"to": destination, "text": body, "template": template}, sort_keys=True).encode()).hexdigest()
        request_id = normalized_uuid(payload["request_id"])
        db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"wa-send:{organization_id}:{lead['id']}",))
        existing = db.execute("SELECT content_hash,status,wa_message_id FROM whatsapp_send_requests WHERE organization_id=%s AND request_id=%s", (organization_id, request_id)).fetchone()
        if existing:
            if existing["content_hash"] != content_hash:
                raise IntegrationError("Este identificador já foi usado para outra mensagem.", "idempotency_conflict", 409)
            if existing["status"] == "accepted":
                return self.reply(200, {"ok": True, "status": "accepted", "message_id": existing["wa_message_id"], "replayed": True})
            raise IntegrationError("Este envio já foi registrado. Confira o histórico antes de criar outro envio.", "send_already_recorded", 409)
        duplicate = db.execute("""SELECT 1 FROM whatsapp_send_requests WHERE organization_id=%s AND lead_id=%s AND content_hash=%s
            AND status IN ('reserved','accepted','unknown') AND created_at>NOW()-INTERVAL '5 minutes'""", (organization_id, str(lead["id"]), content_hash)).fetchone()
        if duplicate:
            raise IntegrationError("Uma mensagem igual já foi enviada ou está em verificação. Confira o histórico.", "duplicate_message", 409)
        request_body = {"messaging_product": "whatsapp", "recipient_type": "individual", "to": destination}
        if template:
            try:
                approved_template, body = template_payload(row, template)
            except (urllib.error.URLError, ValueError, TimeoutError):
                raise IntegrationError("Não foi possível confirmar o template com a Meta.", "template_validation_failed", 502) from None
            request_body.update(type="template", template=approved_template)
        else:
            request_body.update(type="text", text={"preview_url": False, "body": body})
        decrypt(row["access_token_enc"])
        db.execute("""INSERT INTO whatsapp_send_requests(organization_id,request_id,actor_user_id,lead_id,content_hash)
            VALUES(%s,%s,%s,%s,%s)""", (organization_id, request_id, user["id"], str(lead["id"]), content_hash))
        db.commit()
        try:
            result = graph_call(row, quote(row["phone_number_id"], safe="") + "/messages", "POST", request_body)
        except urllib.error.HTTPError as error:
            db.execute("UPDATE whatsapp_send_requests SET status=%s,updated_at=NOW() WHERE organization_id=%s AND request_id=%s",
                ("failed" if 400 <= error.code < 500 else "unknown", organization_id, request_id))
            db.commit()
            raise IntegrationError("A Meta não confirmou o envio. Confira o histórico antes de tentar novamente.", "meta_send_failed", 502) from None
        except (urllib.error.URLError, ValueError, TimeoutError, OSError):
            db.execute("UPDATE whatsapp_send_requests SET status='unknown',updated_at=NOW() WHERE organization_id=%s AND request_id=%s", (organization_id, request_id))
            db.commit()
            raise IntegrationError("Não foi possível confirmar o envio. Para evitar duplicidade, ele não será repetido automaticamente.", "send_unknown", 502) from None
        message_id = (result.get("messages") or [{}])[0].get("id")
        if not isinstance(message_id, str) or not message_id:
            db.execute("UPDATE whatsapp_send_requests SET status='unknown',updated_at=NOW() WHERE organization_id=%s AND request_id=%s", (organization_id, request_id))
            db.commit()
            raise IntegrationError("A Meta não retornou a confirmação. Confira o histórico.", "send_unknown", 502)
        db.execute("""INSERT INTO whatsapp_messages(organization_id,wa_message_id,contact_phone,direction,message_type,body,status,raw)
            VALUES(%s,%s,%s,'out',%s,%s,'accepted',%s::jsonb) ON CONFLICT(organization_id,wa_message_id) DO NOTHING""",
            (organization_id, message_id, destination, "template" if template else "text", body, json.dumps(result)))
        db.execute("UPDATE whatsapp_send_requests SET status='accepted',wa_message_id=%s,updated_at=NOW() WHERE organization_id=%s AND request_id=%s", (message_id, organization_id, request_id))
        db.commit()
        return self.reply(200, {"ok": True, "message_id": message_id, "status": "accepted"})
