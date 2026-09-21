"""Tenant-isolated API keys, contact bridge and integration outbox.

Browser sessions are only used to manage API keys. Data-plane requests use a
scoped Bearer token, so an integration never receives a PulseFlow user session.
Raw API keys are returned once and only their SHA-256 digest is persisted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

import psycopg

from api.auth import connect, ensure_schema as ensure_core_schema, normalized_origin


MAX_BODY = 128_000
MAX_WORKSPACE = 2_000_000
MAX_ACTIVE_KEYS = 5
ALLOWED_SCOPES = frozenset(("contacts:read", "contacts:write", "events:read"))
BOARDS = frozenset(("Principal", "Remarketing", "Abandonados", "Pós-venda"))
_SCHEMA_READY_FOR = None


class IntegrationAPIError(Exception):
    def __init__(self, message, code="invalid_request", status=400, **details):
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details


def utcnow():
    return datetime.now(timezone.utc)


def ensure_schema(db):
    """Create local integration state after the core tenant schema exists."""
    global _SCHEMA_READY_FOR
    ensure_core_schema(db)
    # The core helper commits its own schema transaction. A separate advisory
    # lock keeps concurrent cold starts from racing these integration tables.
    database_key = os.getenv("DATABASE_URL") or os.getenv("STORAGE_URL")
    if database_key and database_key == _SCHEMA_READY_FOR:
        return
    db.execute("SELECT pg_advisory_xact_lock(817405205)")
    statements = [
        """CREATE TABLE IF NOT EXISTS integration_api_keys (
            id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            created_by UUID REFERENCES users(id) ON DELETE SET NULL,
            name TEXT NOT NULL, token_hash TEXT NOT NULL UNIQUE, token_prefix TEXT NOT NULL,
            scopes JSONB NOT NULL, last_used_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
        "CREATE INDEX IF NOT EXISTS integration_keys_org_idx ON integration_api_keys(organization_id,created_at DESC)",
        """CREATE TABLE IF NOT EXISTS integration_requests (
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            request_id UUID NOT NULL, api_key_id UUID REFERENCES integration_api_keys(id) ON DELETE SET NULL,
            request_hash TEXT NOT NULL, response JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY(organization_id,request_id))""",
        "CREATE INDEX IF NOT EXISTS integration_requests_created_idx ON integration_requests(organization_id,created_at DESC)",
        "CREATE INDEX IF NOT EXISTS integration_requests_expiry_idx ON integration_requests(created_at)",
        """CREATE TABLE IF NOT EXISTS integration_events (
            id BIGSERIAL PRIMARY KEY,
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL, resource_id TEXT, payload JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
        "CREATE INDEX IF NOT EXISTS integration_events_org_cursor_idx ON integration_events(organization_id,id)",
        "CREATE INDEX IF NOT EXISTS integration_events_created_idx ON integration_events(created_at)",
    ]
    for statement in statements:
        db.execute(statement)
    # The cursor feed is an operational sync queue, not permanent history.
    # Idempotency records only need to cover realistic retry windows.
    db.execute("DELETE FROM integration_requests WHERE created_at < NOW() - INTERVAL '7 days'")
    db.execute("DELETE FROM integration_events WHERE created_at < NOW() - INTERVAL '90 days'")
    db.commit()
    _SCHEMA_READY_FOR = database_key


def normalized_uuid(value, label="identificador"):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise IntegrationAPIError(f"{label} inválido") from None


def normalize_phone(value):
    if value in (None, ""):
        return ""
    raw = str(value).strip()
    if not re.fullmatch(r"[+\d\s().-]+", raw):
        raise IntegrationAPIError("telefone inválido", "invalid_contact")
    digits = re.sub(r"\D", "", raw)
    if len(digits) in (10, 11):
        digits = "55" + digits
    if not re.fullmatch(r"[1-9][0-9]{7,14}", digits):
        raise IntegrationAPIError("telefone inválido", "invalid_contact")
    return digits


def limited_text(value, field, maximum, required=False):
    if value is None:
        value = ""
    if not isinstance(value, str) or "\x00" in value:
        raise IntegrationAPIError(f"campo {field} inválido", "invalid_contact")
    value = value.strip()
    if (required and not value) or len(value) > maximum:
        raise IntegrationAPIError(f"campo {field} inválido", "invalid_contact")
    return value


def bounded_number(value, field, maximum):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0 or value > maximum:
        raise IntegrationAPIError(f"campo {field} inválido", "invalid_contact")
    return value


def normalized_datetime(value, field):
    value = limited_text(value, field, 64, required=True)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IntegrationAPIError(f"campo {field} inválido", "invalid_contact") from None
    if parsed.tzinfo is None:
        raise IntegrationAPIError(f"campo {field} precisa informar o fuso horário", "invalid_contact")
    return parsed.astimezone(timezone.utc).isoformat()


def reject_unexpected(values, allowed):
    unexpected = sorted(set(values) - set(allowed))
    if unexpected:
        raise IntegrationAPIError("campos não permitidos", "unexpected_fields", fields=unexpected)


def public_key(row):
    return {key: row.get(key) for key in
            ("id", "name", "token_prefix", "scopes", "last_used_at", "created_at")}


def public_contact(lead):
    """Expose an intentionally bounded contact view, never chat/call history."""
    return {
        "id": str(lead.get("id", ""))[:80],
        "external_id": str(lead.get("integrationExternalId", ""))[:128],
        "name": str(lead.get("name", ""))[:160],
        "phone": str(lead.get("phone", ""))[:20],
        "email": str(lead.get("email", ""))[:254],
        "source": str(lead.get("origin", ""))[:120],
        "interest": str(lead.get("interest", ""))[:40],
        "tags": [str(item)[:40] for item in lead.get("tags", [])[:20]] if isinstance(lead.get("tags"), list) else [],
        "notes": str(lead.get("notes", ""))[:4000],
        "board": str(lead.get("board", ""))[:40],
        "stage": str(lead.get("stage", ""))[:64],
        "contract_value": lead.get("contractValue", 0),
        "product": str(lead.get("product", ""))[:120],
        "niche": str(lead.get("niche", ""))[:120],
        "revenue": lead.get("revenue", 0),
        "discard_reason": str(lead.get("discardReason", ""))[:500],
        "recovery_at": lead.get("recoveryAt"),
        "consent_confirmed": lead.get("consentConfirmed") is True,
        "opt_out": bool(lead.get("optOut") or lead.get("opt_out") or lead.get("doNotContact")),
        "automation_paused": lead.get("automationPaused") is True,
        "updated_at": lead.get("integrationUpdatedAt"),
    }


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        # Paths may contain cursors; headers may contain secrets. Log neither.
        return

    def reply(self, status, value):
        raw = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def query(self):
        values = parse_qs(urlparse(self.path).query, keep_blank_values=True)
        if any(len(items) != 1 for items in values.values()):
            raise IntegrationAPIError("parâmetro duplicado", "invalid_query")
        return {key: items[0] for key, items in values.items()}

    def body(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise IntegrationAPIError("tamanho de requisição inválido") from None
        if length < 0 or length > MAX_BODY or self.headers.get("Transfer-Encoding"):
            raise IntegrationAPIError("requisição excede o limite", "payload_too_large", 413)
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise IntegrationAPIError("envie dados no formato JSON", "unsupported_media_type", 415)
        try:
            def reject_constant(_):
                raise ValueError
            value = json.loads(self.rfile.read(length) or b"{}", parse_constant=reject_constant)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise IntegrationAPIError("JSON inválido") from None
        if not isinstance(value, dict):
            raise IntegrationAPIError("JSON deve ser um objeto")
        return value

    def check_same_origin(self):
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise IntegrationAPIError("origem não autorizada", "origin_denied", 403)
        origin = normalized_origin(self.headers.get("Origin") or self.headers.get("Referer"))
        host = self.headers.get("Host", "")
        expected = normalized_origin("https://" + host)
        local = normalized_origin("http://" + host)
        configured = normalized_origin(os.getenv("PULSEFLOW_APP_URL", ""))
        if not origin or origin not in {expected, local, configured}:
            raise IntegrationAPIError("origem não autorizada", "origin_denied", 403)

    def session_user(self, db):
        try:
            jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        except cookies.CookieError:
            return None
        session = jar.get("pulseflow_session")
        if not session or len(session.value) > 256:
            return None
        digest = hashlib.sha256(session.value.encode()).hexdigest()
        return db.execute("""SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id
            LEFT JOIN organizations o ON o.id=u.organization_id
            WHERE s.token_hash=%s AND s.expires_at>NOW() AND u.status='active'
            AND (u.role='super_admin' OR o.status='active')""", (digest,)).fetchone()

    def management_org(self, db, user, requested, lock=False, allow_suspended=False):
        if not user or user.get("role") not in ("owner", "super_admin"):
            raise IntegrationAPIError("acesso restrito", "permission_denied", 403)
        requested = normalized_uuid(requested, "conta") if requested else ""
        own = str(user.get("organization_id") or "")
        organization_id = requested if user["role"] == "super_admin" else own
        if not organization_id or (requested and requested != organization_id):
            raise IntegrationAPIError("conta não autorizada", "permission_denied", 403)
        row = db.execute("SELECT id,status,permissions FROM organizations WHERE id=%s" +
                         (" FOR UPDATE" if lock else ""), (organization_id,)).fetchone()
        if not row or (row["status"] != "active"
                       and not (allow_suspended and user["role"] == "super_admin")):
            raise IntegrationAPIError("conta suspensa ou indisponível", "account_unavailable", 403)
        if user["role"] != "super_admin" and (row.get("permissions") or {}).get("manage_settings", True) is False:
            raise IntegrationAPIError("configurações desativadas para esta conta", "permission_denied", 403)
        return organization_id

    def api_key(self, db, required_scope):
        authorization = self.headers.get("Authorization", "")
        match = re.fullmatch(r"Bearer (pfk_[A-Za-z0-9_-]{40,80})", authorization)
        if not match:
            raise IntegrationAPIError("chave de API inválida", "invalid_api_key", 401)
        digest = hashlib.sha256(match.group(1).encode()).hexdigest()
        row = db.execute("""SELECT k.*,o.status AS organization_status,
            o.permissions AS organization_permissions FROM integration_api_keys k
            JOIN organizations o ON o.id=k.organization_id
            WHERE k.token_hash=%s AND k.revoked_at IS NULL""", (digest,)).fetchone()
        if not row or row["organization_status"] != "active":
            raise IntegrationAPIError("chave de API inválida", "invalid_api_key", 401)
        scopes = row.get("scopes") if isinstance(row.get("scopes"), list) else []
        if required_scope not in scopes:
            raise IntegrationAPIError("escopo insuficiente", "insufficient_scope", 403,
                                      required_scope=required_scope)
        account_permission = "workspace_write" if required_scope == "contacts:write" else "workspace_read"
        if (row.get("organization_permissions") or {}).get(account_permission, True) is False:
            raise IntegrationAPIError("recurso desativado para esta conta", "permission_denied", 403)
        db.execute("UPDATE integration_api_keys SET last_used_at=NOW() WHERE id=%s", (row["id"],))
        return row

    def audit(self, db, user_id, organization_id, action, metadata=None):
        db.execute("INSERT INTO audit_logs(actor_user_id,organization_id,action,metadata) VALUES(%s,%s,%s,%s::jsonb)",
                   (user_id, organization_id, action, json.dumps(metadata or {})))

    def do_GET(self):
        try:
            query = self.query()
            action = query.get("action", "")
            with connect() as db:
                ensure_schema(db)
                if action == "keys":
                    reject_unexpected(query, ("action", "organization_id"))
                    self.check_same_origin()
                    user = self.session_user(db)
                    organization_id = self.management_org(
                        db, user, query.get("organization_id", ""), allow_suspended=True)
                    rows = db.execute("""SELECT id,name,token_prefix,scopes,last_used_at,created_at
                        FROM integration_api_keys WHERE organization_id=%s AND revoked_at IS NULL
                        ORDER BY created_at DESC""", (organization_id,)).fetchall()
                    return self.reply(200, {"ok": True, "keys": [public_key(row) for row in rows],
                                            "maximum": MAX_ACTIVE_KEYS, "allowed_scopes": sorted(ALLOWED_SCOPES)})
                if action == "contacts":
                    reject_unexpected(query, ("action", "limit", "offset"))
                    key = self.api_key(db, "contacts:read")
                    limit = self.integer_query(query.get("limit", "100"), "limit", 1, 200)
                    offset = self.integer_query(query.get("offset", "0"), "offset", 0, 100_000)
                    row = db.execute("SELECT state,revision,updated_at FROM tenant_workspaces WHERE organization_id=%s",
                                     (key["organization_id"],)).fetchone()
                    state = row.get("state") if row and isinstance(row.get("state"), dict) else {}
                    leads = [lead for lead in state.get("leads", []) if isinstance(lead, dict)]
                    contacts = [public_contact(lead) for lead in leads[offset:offset + limit]]
                    db.commit()
                    return self.reply(200, {"ok": True, "contacts": contacts, "total": len(leads),
                                            "limit": limit, "offset": offset,
                                            "workspace_revision": row["revision"] if row else 0})
                if action == "events":
                    reject_unexpected(query, ("action", "cursor", "limit"))
                    key = self.api_key(db, "events:read")
                    cursor = self.integer_query(query.get("cursor", "0"), "cursor", 0, 9_223_372_036_854_775_807)
                    limit = self.integer_query(query.get("limit", "100"), "limit", 1, 200)
                    rows = db.execute("""SELECT id AS cursor,event_type,resource_id,payload,created_at
                        FROM integration_events WHERE organization_id=%s AND id>%s
                        ORDER BY id LIMIT %s""", (key["organization_id"], cursor, limit + 1)).fetchall()
                    has_more = len(rows) > limit
                    rows = rows[:limit]
                    next_cursor = rows[-1]["cursor"] if rows else cursor
                    db.commit()
                    return self.reply(200, {"ok": True, "events": rows, "next_cursor": next_cursor,
                                            "has_more": has_more})
                raise IntegrationAPIError("ação não encontrada", "not_found", 404)
        except IntegrationAPIError as error:
            return self.reply(error.status, {"ok": False, "error": str(error), "code": error.code, **error.details})
        except Exception:
            return self.reply(503, {"ok": False, "error": "serviço indisponível", "code": "service_unavailable"})

    def integer_query(self, value, name, minimum, maximum):
        if not re.fullmatch(r"[0-9]+", str(value)):
            raise IntegrationAPIError(f"parâmetro {name} inválido", "invalid_query")
        value = int(value)
        if value < minimum or value > maximum:
            raise IntegrationAPIError(f"parâmetro {name} inválido", "invalid_query")
        return value

    def do_POST(self):
        try:
            query = self.query()
            reject_unexpected(query, ("action",))
            action = query.get("action", "")
            payload = self.body()
            with connect() as db:
                ensure_schema(db)
                if action in ("create-key", "revoke-key"):
                    self.check_same_origin()
                    user = self.session_user(db)
                    if action == "create-key":
                        return self.create_key(db, user, payload)
                    return self.revoke_key(db, user, payload)
                if action == "upsert-contact":
                    key = self.api_key(db, "contacts:write")
                    return self.upsert_contact(db, key, payload)
                raise IntegrationAPIError("ação não encontrada", "not_found", 404)
        except IntegrationAPIError as error:
            return self.reply(error.status, {"ok": False, "error": str(error), "code": error.code, **error.details})
        except psycopg.errors.UniqueViolation:
            return self.reply(409, {"ok": False, "error": "registro duplicado", "code": "conflict"})
        except Exception:
            return self.reply(503, {"ok": False, "error": "serviço indisponível", "code": "service_unavailable"})

    def create_key(self, db, user, payload):
        reject_unexpected(payload, ("organization_id", "name", "scopes"))
        organization_id = self.management_org(db, user, payload.get("organization_id", ""), lock=True)
        name = limited_text(payload.get("name"), "name", 80, required=True)
        scopes = payload.get("scopes", ["contacts:read"])
        if (not isinstance(scopes, list) or not scopes or len(scopes) > len(ALLOWED_SCOPES)
                or any(not isinstance(scope, str) for scope in scopes)):
            raise IntegrationAPIError("escopos inválidos", "invalid_scopes")
        scopes = sorted(set(scopes))
        if any(scope not in ALLOWED_SCOPES for scope in scopes):
            raise IntegrationAPIError("escopos inválidos", "invalid_scopes")
        active = db.execute("SELECT COUNT(*)::int AS count FROM integration_api_keys WHERE organization_id=%s AND revoked_at IS NULL",
                            (organization_id,)).fetchone()["count"]
        if active >= MAX_ACTIVE_KEYS:
            raise IntegrationAPIError("limite de chaves ativas atingido", "key_limit", 409, maximum=MAX_ACTIVE_KEYS)
        token = "pfk_" + secrets.token_urlsafe(32)
        key_id = str(uuid.uuid4())
        prefix = token[:12]
        row = db.execute("""INSERT INTO integration_api_keys
            (id,organization_id,created_by,name,token_hash,token_prefix,scopes)
            VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb)
            RETURNING id,name,token_prefix,scopes,last_used_at,created_at""",
            (key_id, organization_id, user["id"], name, hashlib.sha256(token.encode()).hexdigest(),
             prefix, json.dumps(scopes))).fetchone()
        self.audit(db, user["id"], organization_id, "integration.key.created",
                   {"key_id": key_id, "name": name, "scopes": scopes})
        db.commit()
        return self.reply(201, {"ok": True, "key": {**public_key(row), "token": token},
                                "notice": "copie agora; esta chave não será exibida novamente"})

    def revoke_key(self, db, user, payload):
        reject_unexpected(payload, ("organization_id", "key_id"))
        organization_id = self.management_org(
            db, user, payload.get("organization_id", ""), lock=True, allow_suspended=True)
        key_id = normalized_uuid(payload.get("key_id"), "chave")
        row = db.execute("""UPDATE integration_api_keys SET revoked_at=NOW()
            WHERE id=%s AND organization_id=%s AND revoked_at IS NULL RETURNING id,name""",
                         (key_id, organization_id)).fetchone()
        if not row:
            raise IntegrationAPIError("chave não encontrada", "not_found", 404)
        self.audit(db, user["id"], organization_id, "integration.key.revoked",
                   {"key_id": key_id, "name": row["name"]})
        db.commit()
        return self.reply(200, {"ok": True, "revoked": key_id})

    def validate_contact(self, payload):
        allowed = ("request_id", "external_id", "name", "phone", "email", "source", "interest",
                   "tags", "notes", "board", "stage", "contract_value", "product", "niche",
                   "revenue", "discard_reason", "recovery_at", "opt_out")
        reject_unexpected(payload, allowed)
        request_id = normalized_uuid(payload.get("request_id"), "request_id")
        result = {
            "request_id": request_id,
            "external_id": limited_text(payload.get("external_id"), "external_id", 128, required=True),
            "name": limited_text(payload.get("name"), "name", 160, required=True),
        }
        if "phone" in payload:
            result["phone"] = normalize_phone(payload.get("phone"))
        if "email" in payload:
            email = limited_text(payload.get("email"), "email", 254)
            if email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                raise IntegrationAPIError("campo email inválido", "invalid_contact")
            result["email"] = email.lower()
        for source, maximum in (("source", 120), ("notes", 4000), ("product", 120),
                                ("niche", 120), ("discard_reason", 500)):
            if source in payload:
                result[source] = limited_text(payload.get(source), source, maximum)
        if "recovery_at" in payload:
            result["recovery_at"] = normalized_datetime(payload.get("recovery_at"), "recovery_at")
        if "interest" in payload:
            aliases = {"alta": "Alta", "media": "Média", "média": "Média", "baixa": "Baixa"}
            interest = limited_text(payload.get("interest"), "interest", 20).casefold()
            if interest not in aliases:
                raise IntegrationAPIError("campo interest inválido", "invalid_contact")
            result["interest"] = aliases[interest]
        if "tags" in payload:
            tags = payload.get("tags")
            if not isinstance(tags, list) or len(tags) > 20:
                raise IntegrationAPIError("campo tags inválido", "invalid_contact")
            result["tags"] = list(dict.fromkeys(limited_text(tag, "tags", 40, required=True) for tag in tags))
        if "board" in payload:
            board = limited_text(payload.get("board"), "board", 40, required=True)
            if board not in BOARDS:
                raise IntegrationAPIError("campo board inválido", "invalid_contact")
            result["board"] = board
        if "stage" in payload:
            stage = limited_text(payload.get("stage"), "stage", 64, required=True)
            if not re.fullmatch(r"[A-Za-z0-9_.:-]+", stage):
                raise IntegrationAPIError("campo stage inválido", "invalid_contact")
            result["stage"] = stage
        for source, maximum in (("contract_value", 1_000_000_000), ("revenue", 1_000_000_000_000)):
            if source in payload:
                result[source] = bounded_number(payload.get(source), source, maximum)
        if "opt_out" in payload:
            if type(payload.get("opt_out")) is not bool:
                raise IntegrationAPIError("campo opt_out inválido", "invalid_contact")
            result["opt_out"] = payload["opt_out"]
        return result

    def valid_stages(self, workspace, board):
        field = "postSaleColumns" if board == "Pós-venda" else "columns"
        configured = workspace.get(field)
        ids = [str(item.get("id")) for item in configured or []
               if isinstance(item, dict) and item.get("id") and len(str(item.get("id"))) <= 64]
        if ids:
            return ids
        return ["onboarding", "adoption", "expansion", "renewal"] if board == "Pós-venda" else ["new", "service", "waiting", "closed"]

    def upsert_contact(self, db, api_key, payload):
        values = self.validate_contact(payload)
        organization_id = api_key["organization_id"]
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        request_hash = hashlib.sha256(canonical.encode()).hexdigest()
        # Serialize the idempotency key, then follow the same organization ->
        # workspace lock order used by the browser workspace writer.
        db.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                   (f"integration:{organization_id}:{values['request_id']}",))
        cached = db.execute("""SELECT request_hash,response FROM integration_requests
            WHERE organization_id=%s AND request_id=%s""",
                            (organization_id, values["request_id"])).fetchone()
        if cached:
            if cached["request_hash"] != request_hash:
                raise IntegrationAPIError("request_id já usado com outros dados", "idempotency_conflict", 409)
            db.commit()
            response = cached["response"] if isinstance(cached["response"], dict) else {}
            return self.reply(200, {**response, "idempotent_replay": True})
        organization = db.execute("SELECT status FROM organizations WHERE id=%s FOR UPDATE",
                                  (organization_id,)).fetchone()
        if not organization or organization["status"] != "active":
            raise IntegrationAPIError("conta suspensa ou indisponível", "account_unavailable", 403)
        workspace_row = db.execute("SELECT state,revision FROM tenant_workspaces WHERE organization_id=%s FOR UPDATE",
                                   (organization_id,)).fetchone()
        workspace = workspace_row.get("state") if workspace_row and isinstance(workspace_row.get("state"), dict) else {}
        leads = workspace.get("leads")
        if not isinstance(leads, list):
            leads = []
            workspace["leads"] = leads
        integration_key_id = str(api_key["id"])
        # Credentials may be rotated. The external identifier therefore belongs
        # to the tenant, not to a particular key that can later be revoked.
        lead = next((item for item in leads if isinstance(item, dict)
                     and str(item.get("integrationExternalId", "")) == values["external_id"]), None)
        created = lead is None
        now = utcnow()
        target_board = values.get("board", "Principal" if created else lead.get("board", "Principal"))
        if target_board not in BOARDS:
            target_board = "Principal"
        stages = self.valid_stages(workspace, target_board)
        if "stage" in values and values["stage"] not in stages:
            raise IntegrationAPIError("etapa não existe neste pipeline", "invalid_stage")
        current_stage = "" if created else str(lead.get("stage", ""))
        target_stage = values.get("stage") or (current_stage if current_stage in stages else stages[0])
        existing_opted_out = False if created else bool(
            lead.get("optOut") or lead.get("opt_out") or lead.get("doNotContact"))
        if (target_board == "Abandonados" and not existing_opted_out
                and (created or lead.get("board") != "Abandonados")):
            if not values.get("discard_reason") or not values.get("recovery_at"):
                raise IntegrationAPIError(
                    "informe discard_reason e recovery_at ao mover para Abandonados",
                    "recovery_required")
            recovery_at = datetime.fromisoformat(values["recovery_at"])
            if recovery_at <= now:
                raise IntegrationAPIError(
                    "recovery_at precisa estar no futuro", "invalid_recovery_at")
        if created:
            lead = {
                "id": str(uuid.uuid4()), "integrationKeyId": integration_key_id,
                "integrationExternalId": values["external_id"],
                "name": values["name"], "phone": values.get("phone", ""),
                "email": values.get("email", ""), "origin": values.get("source", "Integração"),
                "interest": values.get("interest", "Média"), "tags": values.get("tags", []),
                "notes": values.get("notes", ""), "board": target_board,
                "stage": target_stage, "contractValue": values.get("contract_value", 0),
                "product": values.get("product", ""),
                "niche": values.get("niche", ""), "revenue": values.get("revenue", 0),
                "discardReason": values.get("discard_reason", ""),
                "recoveryAt": values.get("recovery_at", ""),
                "entered": int(now.timestamp() * 1000), "messages": [], "calls": [],
                "consentConfirmed": False, "optOut": values.get("opt_out") is True,
                "automationPaused": True,
            }
            leads.append(lead)
        else:
            old_board, old_stage = lead.get("board"), lead.get("stage")
            mapping = {
                "name": "name", "phone": "phone", "email": "email", "source": "origin",
                "interest": "interest", "tags": "tags", "notes": "notes", "board": "board",
                "stage": "stage", "contract_value": "contractValue", "product": "product",
                "niche": "niche", "revenue": "revenue", "discard_reason": "discardReason",
                "recovery_at": "recoveryAt",
            }
            for source, destination in mapping.items():
                if source in values:
                    lead[destination] = values[source]
            lead["board"], lead["stage"] = target_board, target_stage
            if values.get("opt_out") is True:
                lead["optOut"] = True
                lead["automationPaused"] = True
            # An external system cannot reactivate a person who opted out or
            # grant permission. For opt-outs, even pipeline movement is ignored.
            opted_out = bool(lead.get("optOut") or lead.get("opt_out") or lead.get("doNotContact"))
            if opted_out:
                lead["board"], lead["stage"], lead["automationPaused"] = old_board, old_stage, True
            if (lead.get("board"), lead.get("stage")) != (old_board, old_stage):
                lead["entered"] = int(now.timestamp() * 1000)
        lead["integrationKeyId"] = integration_key_id
        lead["integrationExternalId"] = values["external_id"]
        lead["integrationUpdatedAt"] = now.isoformat()
        encoded = json.dumps(workspace, ensure_ascii=False)
        if len(encoded.encode("utf-8")) > MAX_WORKSPACE:
            raise IntegrationAPIError("a conta excedeu o limite de armazenamento", "workspace_too_large", 413)
        revision = (workspace_row["revision"] if workspace_row else 0) + 1
        db.execute("""INSERT INTO tenant_workspaces(organization_id,state,revision,updated_at)
            VALUES(%s,%s::jsonb,%s,NOW()) ON CONFLICT(organization_id) DO UPDATE SET
            state=EXCLUDED.state,revision=EXCLUDED.revision,updated_at=NOW()""",
                   (organization_id, encoded, revision))
        contact = public_contact(lead)
        event = db.execute("""INSERT INTO integration_events
            (organization_id,event_type,resource_id,payload)
            VALUES(%s,%s,%s,%s::jsonb) RETURNING id,created_at""",
            (organization_id, "contact.created" if created else "contact.updated",
             lead["id"], json.dumps({"contact": {key: contact[key] for key in
                 ("id", "external_id", "board", "stage", "opt_out", "automation_paused")}}))).fetchone()
        response = {"ok": True, "created": created, "contact": contact,
                    "workspace_revision": revision,
                    "event": {"cursor": event["id"],
                              "event_type": "contact.created" if created else "contact.updated"}}
        db.execute("""INSERT INTO integration_requests
            (organization_id,request_id,api_key_id,request_hash,response)
            VALUES(%s,%s,%s,%s,%s::jsonb)""",
            (organization_id, values["request_id"], api_key["id"], request_hash,
             json.dumps(response, ensure_ascii=False, default=str)))
        db.commit()
        return self.reply(201 if created else 200, response)
