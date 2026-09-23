"""Explicitly LOCAL UI contract fixture. NOT a production database or API.

Run: python tests/serve_test.py --test-only
Only listens on 127.0.0.1:8788. All data vanish on restart; never calls providers.
Fixtures: seller@example.test and admin@example.test / PulseFlow-local-2026!
This validates browser flows against the API contract, not PostgreSQL persistence.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import secrets
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import Handler as StaticHandler  # noqa: E402

PERMISSIONS = {name: True for name in (
    "workspace_read", "workspace_write", "manage_settings", "whatsapp_read", "whatsapp_send", "whatsapp_manage"
)}
LEGAL_VERSION = "2026-09-20"
LOCK = threading.RLock()
STORE = {
    "accounts": {}, "users": {}, "sessions": {}, "workspaces": {}, "audits": [],
    "invites": {}, "password_resets": {}, "integration_keys": {}, "integration_webhooks": {},
    "integration_requests": {}, "integration_events": [],
}


def now():
    return datetime.now(timezone.utc).isoformat()


def identifier():
    return str(uuid.uuid4())


def password_digest(value):
    # Local fixture only. Production password handling lives in api/auth.py.
    return hashlib.sha256(value.encode()).hexdigest()


def normalized_phone(value):
    digits = "".join(character for character in str(value or "") if character.isdigit())
    if len(digits) in (10, 11):
        digits = "55" + digits
    return digits if 8 <= len(digits) <= 15 and not digits.startswith("0") else ""


def normalized_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        return None


def contact_payload(value):
    """Expose operational contact data without leaking server-only structures."""
    if not isinstance(value, dict):
        return {}
    return {
        "id": str(value.get("id", ""))[:80],
        "external_id": str(value.get("integrationExternalId", ""))[:128],
        "name": str(value.get("name", ""))[:160],
        "phone": str(value.get("phone", ""))[:20],
        "email": str(value.get("email", ""))[:254],
        "source": str(value.get("origin", ""))[:120],
        "interest": str(value.get("interest", ""))[:40],
        "tags": copy.deepcopy(value.get("tags", [])) if isinstance(value.get("tags"), list) else [],
        "notes": str(value.get("notes", ""))[:4000],
        "board": str(value.get("board", ""))[:40],
        "stage": str(value.get("stage", ""))[:64],
        "contract_value": value.get("contractValue", 0),
        "product": str(value.get("product", ""))[:120],
        "niche": str(value.get("niche", ""))[:120],
        "revenue": value.get("revenue", 0),
        "discard_reason": str(value.get("discardReason", ""))[:500],
        "recovery_at": value.get("recoveryAt"),
        "consent_confirmed": value.get("consentConfirmed") is True,
        "opt_out": bool(value.get("optOut") or value.get("opt_out") or value.get("doNotContact")),
        "automation_paused": value.get("automationPaused") is True,
        "updated_at": value.get("integrationUpdatedAt"),
    }


WEBHOOK_EVENTS = {
    "contact.created", "contact.updated", "contact.stage_changed",
    "contact.deleted", "contact.reply_received", "contacts.resync_required",
}


def public_webhook(value):
    parsed = urlsplit(value["endpoint_url"])
    return {
        "id": value["id"], "name": value["name"],
        "url": f"{parsed.scheme}://{parsed.netloc}/…", "host": parsed.hostname,
        "event_types": copy.deepcopy(value["event_types"]), "status": value["status"],
        "created_at": value["created_at"], "updated_at": value["updated_at"],
        "last_delivery_at": value.get("last_delivery_at"),
        "last_status_code": value.get("last_status_code"), "last_error": value.get("last_error"),
    }


def seed():
    account_id = identifier()
    STORE["accounts"][account_id] = {
        "id": account_id, "name": "Empresa de teste local", "plan": "Base", "niche": "",
        "whatsapp": "", "status": "active", "created_at": now(), "permissions": dict(PERMISSIONS),
    }
    for email, role, organization_id in (
        ("seller@example.test", "owner", account_id), ("admin@example.test", "super_admin", None)
    ):
        user_id = identifier()
        STORE["users"][user_id] = {
            "id": user_id, "name": "Administrador local" if role == "super_admin" else "Vendedor local",
            "email": email, "role": role, "status": "active", "organization_id": organization_id,
            "password_hash": password_digest("PulseFlow-local-2026!"), "created_at": now(), "last_login_at": None,
        }


def public_user(user):
    return {key: value for key, value in user.items() if key != "password_hash"}


class Handler(StaticHandler):
    def end_headers(self):
        self.send_header("X-PulseFlow-Test-Fixture", "local-memory-only")
        super().end_headers()

    def reply(self, status, payload, token=None):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        if token is not None:
            age = 3600 if token else 0
            self.send_header("Set-Cookie", f"pulseflow_session={token}; Path=/; Max-Age={age}; HttpOnly; SameSite=Strict")
        self.end_headers()
        self.wfile.write(data)

    def fail(self, status, message):
        return self.reply(status, {"ok": False, "error": message})

    def current_user(self):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie.get("pulseflow_session")
            user = STORE["users"].get(STORE["sessions"].get(token.value if token else ""))
        except Exception:
            return None
        if not user or user["status"] != "active":
            return None
        account = STORE["accounts"].get(user["organization_id"])
        if user["role"] != "super_admin" and (not account or account["status"] != "active"):
            return None
        return user

    def requested_account(self, user, requested=None):
        own = user["organization_id"]
        if user["role"] != "super_admin" and requested and requested != own:
            return None
        return STORE["accounts"].get(requested if user["role"] == "super_admin" else own)

    def allowed(self, user, account, permission):
        return user["role"] == "super_admin" or account["permissions"].get(permission, False)

    def session(self, user):
        token = secrets.token_urlsafe(32)
        STORE["sessions"][token] = user["id"]
        user["last_login_at"] = now()
        self.reply(200, {"ok": True, "user": public_user(user), "account": STORE["accounts"].get(user["organization_id"])}, token)

    def audit(self, user, account, action):
        STORE["audits"].insert(0, {"action": action, "created_at": now(), "actor_name": user["name"], "organization_name": account["name"]})
        del STORE["audits"][100:]

    def integration_key(self, required_scope):
        authorization = str(self.headers.get("Authorization", ""))
        if not authorization.startswith("Bearer "):
            return None, None
        secret = authorization[7:].strip()
        if not secret.startswith("pfk_") or len(secret) > 256:
            return None, None
        token_hash = password_digest(secret)
        key = next((item for item in STORE["integration_keys"].values()
                    if item["token_hash"] == token_hash and not item.get("revoked_at")), None)
        account = STORE["accounts"].get(key["organization_id"]) if key else None
        if not account or account["status"] != "active":
            return None, None
        if required_scope not in key.get("scopes", []):
            return key, "insufficient_scope"
        permission = "workspace_write" if required_scope == "contacts:write" else "workspace_read"
        if account["permissions"].get(permission, True) is False:
            return key, "permission_denied"
        key["last_used_at"] = now()
        return key, account

    def integration_account(self, user, requested):
        if not user or user["role"] not in ("owner", "super_admin"):
            return None
        account = self.requested_account(user, requested)
        if (account and user["role"] != "super_admin"
                and account["permissions"].get("manage_settings", True) is False):
            return None
        return account

    def integration_keys(self, user, account, action, payload):
        if self.command == "GET" and action == "keys":
            keys = []
            for item in STORE["integration_keys"].values():
                if item["organization_id"] != account["id"] or item.get("revoked_at"):
                    continue
                keys.append({key: item.get(key) for key in (
                    "id", "name", "token_prefix", "scopes", "last_used_at", "created_at",
                )})
            keys.sort(key=lambda item: item["created_at"], reverse=True)
            return self.reply(200, {"ok": True, "keys": keys, "maximum": 5,
                                    "allowed_scopes": ["contacts:read", "contacts:write", "events:read"]})
        if self.command == "POST" and action == "create-key":
            name = str(payload.get("name", "")).strip()
            if not name or len(name) > 80:
                return self.fail(400, "informe um nome de até 80 caracteres")
            scopes = payload.get("scopes", ["contacts:read"])
            allowed_scopes = {"contacts:read", "contacts:write", "events:read"}
            if not isinstance(scopes, list) or not scopes or any(scope not in allowed_scopes for scope in scopes):
                return self.fail(400, "escopos inválidos")
            scopes = sorted(set(scopes))
            active = sum(item["organization_id"] == account["id"] and not item.get("revoked_at")
                         for item in STORE["integration_keys"].values())
            if active >= 5:
                return self.fail(409, "limite de chaves ativas atingido")
            secret = "pfk_" + secrets.token_urlsafe(32)
            key_id = identifier()
            STORE["integration_keys"][key_id] = {
                "id": key_id, "organization_id": account["id"], "name": name,
                "token_prefix": secret[:12], "token_hash": password_digest(secret), "scopes": scopes,
                "created_by": user["id"], "created_at": now(), "last_used_at": None,
                "revoked_at": None,
            }
            self.audit(user, account, "integration.key.created")
            return self.reply(201, {"ok": True, "key": {
                "id": key_id, "name": name, "token_prefix": secret[:12], "scopes": scopes,
                "last_used_at": None, "created_at": STORE["integration_keys"][key_id]["created_at"],
                "token": secret,
            }, "notice": "copie agora; esta chave não será exibida novamente"})
        if self.command == "POST" and action == "revoke-key":
            key = STORE["integration_keys"].get(payload.get("key_id"))
            if not key or key["organization_id"] != account["id"] or key.get("revoked_at"):
                return self.fail(404, "chave não encontrada")
            key["revoked_at"] = now()
            self.audit(user, account, "integration.key.revoked")
            return self.reply(200, {"ok": True, "revoked": key["id"]})
        if self.command == "GET" and action == "webhooks":
            hooks = [public_webhook(item) for item in STORE["integration_webhooks"].values()
                     if item["organization_id"] == account["id"] and not item.get("revoked_at")]
            hooks.sort(key=lambda item: item["created_at"], reverse=True)
            return self.reply(200, {"ok": True, "webhooks": hooks, "maximum": 3,
                                    "allowed_event_types": sorted(WEBHOOK_EVENTS)})
        if self.command == "POST" and action == "create-webhook":
            if account.get("plan") != "Equipe":
                return self.fail(403, "webhooks de saída exigem o plano Equipe")
            name, endpoint = str(payload.get("name", "")).strip(), str(payload.get("url", "")).strip()
            event_types = payload.get("event_types")
            parsed = urlsplit(endpoint)
            if not name or len(name) > 80:
                return self.fail(400, "informe um nome de até 80 caracteres")
            if len(endpoint) > 2048 or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                return self.fail(400, "informe uma URL HTTPS válida")
            if (not isinstance(event_types, list) or not event_types
                    or any(item not in WEBHOOK_EVENTS for item in event_types)):
                return self.fail(400, "eventos inválidos")
            active = sum(item["organization_id"] == account["id"] and not item.get("revoked_at")
                         for item in STORE["integration_webhooks"].values())
            if active >= 3:
                return self.fail(409, "limite de webhooks ativos atingido")
            secret, webhook_id, timestamp = "whsec_" + secrets.token_urlsafe(32), identifier(), now()
            record = {
                "id": webhook_id, "organization_id": account["id"], "name": name,
                "endpoint_url": endpoint, "secret_hash": password_digest(secret),
                "event_types": sorted(set(event_types)), "status": "active",
                "created_by": user["id"], "created_at": timestamp, "updated_at": timestamp,
                "last_delivery_at": None, "last_status_code": None, "last_error": None,
                "revoked_at": None,
            }
            STORE["integration_webhooks"][webhook_id] = record
            self.audit(user, account, "integration.webhook.created")
            return self.reply(201, {"ok": True, "webhook": {**public_webhook(record), "secret": secret},
                                    "notice": "copie agora; este segredo não será exibido novamente"})
        if self.command == "POST" and action in ("revoke-webhook", "test-webhook"):
            hook = STORE["integration_webhooks"].get(payload.get("webhook_id"))
            if not hook or hook["organization_id"] != account["id"] or hook.get("revoked_at"):
                return self.fail(404, "webhook não encontrado")
            if action == "revoke-webhook":
                hook["revoked_at"], hook["status"], hook["updated_at"] = now(), "revoked", now()
                self.audit(user, account, "integration.webhook.revoked")
                return self.reply(200, {"ok": True, "revoked": hook["id"]})
            if account.get("plan") != "Equipe":
                return self.fail(403, "webhooks de saída exigem o plano Equipe")
            timestamp, delivery_id = now(), identifier()
            hook["updated_at"] = timestamp
            self.audit(user, account, "integration.webhook.tested")
            return self.reply(202, {"ok": True, "delivery": {
                "id": delivery_id, "status": "pending", "created_at": timestamp,
            }, "status_code": None, "duration_ms": None})
        return self.fail(404, "ação de integração não encontrada")

    def integration_bearer(self, key, account, action, payload, query):
        workspace_record = STORE["workspaces"].setdefault(account["id"], {
            "workspace": {"schemaVersion": 4, "leads": []}, "revision": 0, "updated_at": None,
        })
        if not isinstance(workspace_record.get("workspace"), dict):
            workspace_record["workspace"] = {"schemaVersion": 4, "leads": []}
        workspace = workspace_record["workspace"]
        leads = workspace.setdefault("leads", [])
        if self.command == "GET" and action == "contacts":
            try:
                limit, offset = int(query.get("limit", 100)), int(query.get("offset", 0))
            except (TypeError, ValueError):
                return self.fail(400, "paginação inválida")
            if not 1 <= limit <= 200 or not 0 <= offset <= 100_000:
                return self.fail(400, "paginação inválida")
            contacts = [contact_payload(item) for item in leads if isinstance(item, dict)]
            return self.reply(200, {"ok": True, "contacts": contacts[offset:offset + limit],
                                    "total": len(contacts), "limit": limit, "offset": offset,
                                    "workspace_revision": workspace_record["revision"]})
        if self.command == "GET" and action == "events":
            try:
                cursor, limit = int(query.get("cursor", 0)), int(query.get("limit", 100))
            except (TypeError, ValueError):
                return self.fail(400, "paginação inválida")
            if cursor < 0 or not 1 <= limit <= 200:
                return self.fail(400, "paginação inválida")
            events = [copy.deepcopy(item) for item in STORE["integration_events"]
                      if item["organization_id"] == account["id"] and item["cursor"] > cursor]
            events.sort(key=lambda item: item["cursor"])
            page, has_more = events[:limit], len(events) > limit
            for item in page:
                item.pop("organization_id", None)
            return self.reply(200, {"ok": True, "events": page,
                                    "next_cursor": page[-1]["cursor"] if page else cursor,
                                    "has_more": has_more})
        if self.command != "POST" or action != "upsert-contact":
            return self.fail(404, "ação de integração não encontrada")
        request_id = normalized_uuid(payload.get("request_id"))
        allowed = {"request_id", "external_id", "name", "phone", "email", "source", "interest",
                   "tags", "notes", "board", "stage", "contract_value", "product", "niche",
                   "revenue", "discard_reason", "recovery_at", "opt_out"}
        if set(payload) - allowed:
            return self.fail(400, "campos não permitidos")
        if not request_id:
            return self.fail(400, "request_id inválido")
        # The request hash detects accidental reuse with a different operation while
        # retaining only the minimum idempotency material in this local fixture.
        request_hash = password_digest(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
        request_key = (account["id"], request_id)
        existing_request = STORE["integration_requests"].get(request_key)
        if existing_request:
            if existing_request["request_hash"] != request_hash:
                return self.fail(409, "request_id já utilizado com outro conteúdo")
            replay = copy.deepcopy(existing_request["response"])
            replay["idempotent_replay"] = True
            return self.reply(200, replay)
        name = str(payload.get("name", "")).strip()
        phone = normalized_phone(payload.get("phone")) if "phone" in payload else ""
        external_id = str(payload.get("external_id") or "").strip()
        if not external_id or len(external_id) > 128 or not name or len(name) > 160 or ("phone" in payload and not phone):
            return self.fail(400, "contato inválido")
        if "opt_out" in payload and type(payload["opt_out"]) is not bool:
            return self.fail(400, "contato inválido")
        lead = next((item for item in leads if isinstance(item, dict)
                     and str(item.get("integrationExternalId") or "") == external_id), None)
        created = lead is None
        target_board = str(payload.get("board") or ("Principal" if created else lead.get("board", "Principal")))
        if target_board not in {"Principal", "Remarketing", "Abandonados", "Pós-venda"}:
            return self.fail(400, "pipeline inválido")
        stage_field = "postSaleColumns" if target_board == "Pós-venda" else "columns"
        stages = [str(item.get("id")) for item in workspace.get(stage_field, [])
                  if isinstance(item, dict) and item.get("id")]
        if not stages:
            stages = (["onboarding", "adoption", "expansion", "renewal"]
                      if target_board == "Pós-venda" else ["new", "service", "waiting", "closed"])
        target_stage = str(payload.get("stage") or (stages[0] if created else lead.get("stage", stages[0])))
        if target_stage not in stages:
            return self.fail(400, "etapa não existe neste pipeline")
        existing_opted_out = False if created else bool(
            lead.get("optOut") or lead.get("opt_out") or lead.get("doNotContact"))
        if (target_board == "Abandonados" and not existing_opted_out
                and (created or lead.get("board") != "Abandonados")):
            if not str(payload.get("discard_reason") or "").strip() or not payload.get("recovery_at"):
                return self.fail(400, "informe motivo e data de recuperação")
        if created:
            lead = {
                "id": identifier(), "integrationKeyId": key["id"],
                "integrationExternalId": external_id, "name": name, "phone": phone,
                "email": "", "origin": str(payload.get("source") or "Integração")[:120],
                "interest": str(payload.get("interest") or "Média")[:40], "tags": [],
                "board": target_board, "stage": target_stage,
                "messages": [], "calls": [], "notes": "", "entered": int(datetime.now(timezone.utc).timestamp() * 1000),
                "product": str(payload.get("product") or "")[:120],
                "discardReason": str(payload.get("discard_reason") or "")[:500],
                "recoveryAt": payload.get("recovery_at") or "",
                "consentConfirmed": False, "optOut": payload.get("opt_out") is True,
                "automationPaused": True,
            }
            leads.append(lead)
        old_board, old_stage = lead.get("board"), lead.get("stage")
        mapping = {"name": "name", "phone": "phone", "email": "email", "source": "origin",
                   "interest": "interest", "tags": "tags", "notes": "notes", "board": "board",
                   "stage": "stage", "contract_value": "contractValue", "product": "product",
                   "niche": "niche", "revenue": "revenue", "discard_reason": "discardReason",
                   "recovery_at": "recoveryAt"}
        for source, target in mapping.items():
            if source in payload:
                lead[target] = phone if source == "phone" else copy.deepcopy(payload[source])
        if payload.get("opt_out") is True:
            lead["optOut"] = True
            lead["automationPaused"] = True
        if lead.get("optOut") or lead.get("opt_out") or lead.get("doNotContact"):
            lead["board"], lead["stage"], lead["automationPaused"] = old_board, old_stage, True
        elif (lead.get("board"), lead.get("stage")) != (old_board, old_stage):
            lead["entered"] = int(datetime.now(timezone.utc).timestamp() * 1000)
        lead["integrationKeyId"] = key["id"]
        lead["integrationExternalId"] = external_id
        lead["integrationUpdatedAt"] = now()
        workspace_record["revision"] += 1
        workspace_record["updated_at"] = now()
        public = contact_payload(lead)
        cursor = len(STORE["integration_events"]) + 1
        event = {
            "cursor": cursor, "organization_id": account["id"],
            "event_type": "contact.created" if created else "contact.updated",
            "resource_id": lead["id"], "payload": {"contact": {field: public[field] for field in
                ("id", "external_id", "board", "stage", "opt_out", "automation_paused")}},
            "created_at": now(),
        }
        STORE["integration_events"].append(event)
        response = {"ok": True, "created": created, "contact": public,
                    "workspace_revision": workspace_record["revision"],
                    "event": {"cursor": cursor, "event_type": event["event_type"]},
                    "idempotent_replay": False}
        STORE["integration_requests"][request_key] = {
            "request_hash": request_hash, "response": copy.deepcopy(response),
        }
        return self.reply(201 if created else 200, response)

    def route(self):
        if not self.local_host():
            return self.fail(403, "somente localhost")
        parsed = urlsplit(self.path)
        if not parsed.path.startswith("/api/"):
            return super().dispatch()
        query = {key: value[0] for key, value in parse_qs(parsed.query).items()}
        action = query.get("action", "")
        payload = {}
        if self.command == "POST":
            bearer_integration = (parsed.path == "/api/integrations"
                                  and str(self.headers.get("Authorization", "")).startswith("Bearer "))
            source = self.headers.get("Origin") or self.headers.get("Referer", "")
            if not bearer_integration and urlsplit(source).netloc != self.headers.get("Host"):
                return self.fail(403, "origem não permitida")
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 2_000_000:
                    return self.fail(413, "corpo excede o limite")
                payload = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(payload, dict):
                    return self.fail(400, "objeto JSON necessário")
            except (ValueError, json.JSONDecodeError):
                return self.fail(400, "JSON inválido")
        with LOCK:
            user = self.current_user()
            if parsed.path == "/api/integrations":
                authorization = str(self.headers.get("Authorization", ""))
                if authorization.startswith("Bearer "):
                    required_scope = {"contacts": "contacts:read", "upsert-contact": "contacts:write",
                                      "events": "events:read"}.get(action, "contacts:read")
                    key, account = self.integration_key(required_scope)
                    if not key:
                        return self.fail(401, "chave de integração inválida ou revogada")
                    if account in ("insufficient_scope", "permission_denied"):
                        return self.fail(403, "escopo insuficiente")
                    return self.integration_bearer(key, account, action, payload, query)
                source = self.headers.get("Origin") or self.headers.get("Referer", "")
                if urlsplit(source).netloc != self.headers.get("Host"):
                    return self.fail(403, "origem não permitida")
                account = self.integration_account(
                    user, query.get("organization_id") or payload.get("organization_id"))
                if not user:
                    return self.fail(401, "não autenticado")
                if user["role"] not in ("owner", "super_admin"):
                    return self.fail(403, "somente o proprietário pode gerenciar integrações")
                if not account:
                    return self.fail(403, "conta não autorizada")
                return self.integration_keys(user, account, action, payload)
            if parsed.path == "/api/send-whatsapp":
                return self.fail(410, "endpoint legado desativado")
            if parsed.path == "/api/whatsapp":
                if not user:
                    return self.fail(401, "não autenticado")
                account = self.requested_account(user, query.get("organization_id") or payload.get("organization_id"))
                if not account:
                    return self.fail(403, "conta não autorizada")
                if self.command == "GET" and action == "connection":
                    return self.reply(200, {"ok": True, "connection": None, "configured": False, "connected": False, "encryptionReady": False, "manualMode": True})
                if self.command == "GET" and action == "messages":
                    return self.reply(200, {"ok": True, "messages": [], "contacts": [], "connected": False})
                return self.fail(503, "ambiente de teste local: provedores externos desativados")
            if parsed.path == "/api/ai":
                if not user:
                    return self.fail(401, "não autenticado")
                account = self.requested_account(user, query.get("organization_id") or payload.get("organization_id"))
                if not account:
                    return self.fail(403, "conta não autorizada")
                if self.command == "GET" and action == "status":
                    return self.reply(200, {"ok": True, "configured": True, "model": "fixture-only",
                        "mode": "suggest_only", "used_today": 0, "daily_limit": 10, "remaining_today": 10})
                if self.command == "POST" and action == "analyze":
                    current = STORE["workspaces"].get(account["id"], {"workspace": {}})["workspace"] or {}
                    lead = next((item for item in current.get("leads", []) if item.get("id") == payload.get("lead_id")), None)
                    if not lead:
                        return self.fail(404, "contato não encontrado")
                    if not current.get("ai", {}).get("enabled"):
                        return self.fail(409, "ative o agente")
                    return self.reply(200, {"ok": True, "analysis_id": identifier(), "model": "fixture-only",
                        "used_today": 1, "daily_limit": 10, "analysis": {
                            "summary": "O cliente demonstrou interesse e indicou um horário preferido.",
                            "stage": "Em atendimento", "intent": "Agendar o próximo passo",
                            "awareness": "Reconhece a necessidade", "objections": [],
                            "signals": ["Interesse confirmado", "Preferência por sexta-feira"],
                            "recommended_next_action": "message",
                            "suggested_message": "Posso reservar um horário na sexta-feira para você?",
                            "follow_up_reason": "Transformar o interesse em um compromisso claro.",
                            "follow_up_after_hours": 24, "confidence": 0.91,
                            "memory_facts": ["Prefere atendimento na sexta-feira"],
                            "observation_only": False, "requires_seller_approval": True}})
                return self.fail(404, "ação não encontrada")
            if parsed.path != "/api/auth":
                return self.fail(404, "ação não encontrada")
            if self.command == "GET" and action == "health":
                return self.reply(200, {"ok": True, "database": False, "testFixture": True})
            if self.command == "POST" and action == "register":
                required = ("name", "company", "email", "password")
                if any(not isinstance(payload.get(field), str) or not payload[field].strip() for field in required):
                    return self.fail(400, "preencha nome, empresa, e-mail e senha")
                email = payload["email"].strip().lower()
                if "@" not in email or len(payload["password"]) < 8:
                    return self.fail(400, "e-mail inválido ou senha com menos de 8 caracteres")
                if payload.get("legal_accepted") is not True or payload.get("legal_version") != LEGAL_VERSION:
                    return self.fail(400, "aceite os Termos de Uso e a Política de Privacidade")
                if any(item["email"] == email for item in STORE["users"].values()):
                    return self.fail(409, "e-mail já cadastrado")
                account_id, user_id = identifier(), identifier()
                STORE["accounts"][account_id] = {"id": account_id, "name": payload["company"].strip(), "plan": "Base", "status": "active", "permissions": dict(PERMISSIONS), "niche": "", "whatsapp": "", "created_at": now()}
                user = {"id": user_id, "name": payload["name"].strip(), "email": email, "role": "owner", "status": "active", "organization_id": account_id, "password_hash": password_digest(payload["password"]), "legal_version": LEGAL_VERSION, "legal_accepted_at": now(), "created_at": now(), "last_login_at": None}
                STORE["users"][user_id] = user
                self.audit(user, STORE["accounts"][account_id], "legal.accepted")
                return self.session(user)
            if self.command == "POST" and action == "login":
                email = str(payload.get("email", "")).strip().lower()
                match = next((item for item in STORE["users"].values() if item["email"] == email), None)
                if not match or match["status"] != "active" or not secrets.compare_digest(match["password_hash"], password_digest(str(payload.get("password", "")))):
                    return self.fail(401, "e-mail ou senha inválidos")
                account = STORE["accounts"].get(match["organization_id"])
                if account and account["status"] != "active":
                    return self.fail(401, "e-mail ou senha inválidos")
                return self.session(match)
            if self.command == "POST" and action == "logout":
                if user:
                    STORE["sessions"] = {key: value for key, value in STORE["sessions"].items() if value != user["id"]}
                return self.reply(200, {"ok": True}, "")
            if self.command == "POST" and action == "accept-invite":
                token, password = str(payload.get("token", "")), str(payload.get("password", ""))
                match = next((item for item in STORE["invites"].values() if item["token_hash"] == password_digest(token) and not item.get("accepted_at")), None)
                if payload.get("legal_accepted") is not True or payload.get("legal_version") != LEGAL_VERSION:
                    return self.fail(400, "aceite os Termos de Uso e a Política de Privacidade")
                if not match or len(password) < 10:
                    return self.fail(410, "convite inválido ou expirado")
                account = STORE["accounts"].get(match["organization_id"])
                if not account or account["plan"] != "Equipe" or sum(item["organization_id"] == account["id"] and item["status"] == "active" for item in STORE["users"].values()) >= 3:
                    return self.fail(409, "a conta atingiu o limite de usuários")
                user_id = identifier(); new_user = {"id": user_id, "name": match["name"], "email": match["email"], "role": "member", "status": "active", "organization_id": account["id"], "password_hash": password_digest(password), "legal_version": LEGAL_VERSION, "legal_accepted_at": now(), "created_at": now(), "last_login_at": None}
                STORE["users"][user_id] = new_user; match["accepted_at"] = now(); self.audit(new_user, account, "team.invite.accepted")
                return self.session(new_user)
            if self.command == "POST" and action == "accept-password-reset":
                token, password = str(payload.get("token", "")), str(payload.get("password", ""))
                if not 32 <= len(token) <= 256:
                    return self.fail(400, "link de recuperação inválido")
                if len(password) < 10:
                    return self.fail(400, "a nova senha precisa ter pelo menos 10 caracteres")
                token_hash = password_digest(token)
                reset = next((item for item in STORE["password_resets"].values() if item["token_hash"] == token_hash), None)
                target = STORE["users"].get(reset["user_id"]) if reset else None
                account = STORE["accounts"].get(target["organization_id"]) if target else None
                if (
                    not reset or reset.get("used_at") or reset["expires_at"] <= datetime.now(timezone.utc)
                    or not target or target["role"] == "super_admin" or target["status"] != "active"
                    or not account or account["status"] != "active"
                ):
                    return self.fail(410, "link de recuperação inválido ou expirado")
                target["password_hash"] = password_digest(password)
                reset["used_at"] = now()
                STORE["sessions"] = {key: value for key, value in STORE["sessions"].items() if value != target["id"]}
                self.audit(target, account, "user.password_reset.completed")
                return self.session(target)
            if not user:
                return self.fail(401, "não autenticado")
            if self.command == "GET" and action == "me":
                return self.reply(200, {"ok": True, "user": public_user(user), "account": STORE["accounts"].get(user["organization_id"])})
            if self.command == "GET" and action == "team":
                account = self.requested_account(user, query.get("organization_id"))
                if not account or not self.allowed(user, account, "workspace_read"):
                    return self.fail(403, "conta não autorizada")
                members = [public_user(item) | {"last_login_at": item.get("last_login_at"), "created_at": item.get("created_at")} for item in STORE["users"].values() if item["organization_id"] == account["id"]]
                invites = [{key: item[key] for key in ("id", "name", "email", "expires_at", "created_at")} for item in STORE["invites"].values() if item["organization_id"] == account["id"] and not item.get("accepted_at")]
                return self.reply(200, {"ok": True, "members": members, "invites": invites, "limit": 3 if account["plan"] == "Equipe" else 1, "plan": account["plan"]})
            if action == "workspace":
                account = self.requested_account(user, query.get("organization_id") if self.command == "GET" else payload.get("organization_id"))
                if not account:
                    return self.fail(403, "conta não autorizada")
                current = STORE["workspaces"].get(account["id"], {"workspace": None, "revision": 0, "updated_at": None})
                if self.command == "GET":
                    if not self.allowed(user, account, "workspace_read"):
                        return self.fail(403, "acesso de leitura suspenso")
                    if user["role"] == "super_admin":
                        self.audit(user, account, "support.workspace.opened")
                    return self.reply(200, {"ok": True, "account": account, **current})
                if not self.allowed(user, account, "workspace_write"):
                    return self.fail(403, "acesso de edição suspenso")
                if not isinstance(payload.get("state"), dict) or type(payload.get("revision")) is not int:
                    return self.fail(400, "state e revision são obrigatórios")
                if payload["revision"] != current["revision"]:
                    return self.reply(409, {"ok": False, "error": "dados atualizados em outra sessão; recarregue antes de salvar", "revision": current["revision"]})
                updated = {"workspace": copy.deepcopy(payload["state"]), "revision": current["revision"] + 1, "updated_at": now()}
                STORE["workspaces"][account["id"]] = updated
                if user["role"] == "super_admin":
                    self.audit(user, account, "support.workspace.updated")
                return self.reply(200, {"ok": True, "account": account, "revision": updated["revision"], "updated_at": updated["updated_at"]})
            if self.command == "POST" and action == "team-user":
                account = self.requested_account(user, payload.get("organization_id"))
                if not account or user["role"] not in ("owner", "super_admin"):
                    return self.fail(403, "somente o proprietário pode gerenciar a equipe")
                if payload.get("operation") == "create":
                    if account["plan"] != "Equipe":
                        return self.fail(403, "adicione usuários somente no plano Equipe")
                    if sum(item["organization_id"] == account["id"] and item["status"] == "active" for item in STORE["users"].values()) >= 3:
                        return self.fail(409, "o plano Equipe permite até 3 usuários ativos")
                    name, email, password = str(payload.get("name", "")).strip(), str(payload.get("email", "")).strip().lower(), str(payload.get("password", ""))
                    if not name or "@" not in email or len(password) < 10:
                        return self.fail(400, "nome, e-mail e senha inicial são obrigatórios")
                    if any(item["email"] == email for item in STORE["users"].values()):
                        return self.fail(409, "e-mail já cadastrado")
                    member_id = identifier(); STORE["users"][member_id] = {"id": member_id, "name": name, "email": email, "role": "member", "status": "active", "organization_id": account["id"], "password_hash": password_digest(password), "created_at": now(), "last_login_at": None}
                    self.audit(user, account, "team.user.created")
                    return self.reply(200, {"ok": True, "user_id": member_id, "status": "active"})
                if payload.get("operation") == "status":
                    target = STORE["users"].get(payload.get("user_id")); status = payload.get("status")
                    if not target or target["organization_id"] != account["id"]:
                        return self.fail(404, "usuário não encontrado")
                    if target["role"] != "member" or status not in ("active", "suspended"):
                        return self.fail(403, "alteração não permitida")
                    target["status"] = status
                    if status == "suspended":
                        STORE["sessions"] = {key: value for key, value in STORE["sessions"].items() if value != target["id"]}
                    self.audit(user, account, "team.user." + status)
                    return self.reply(200, {"ok": True, "user_id": target["id"], "status": status})
                return self.fail(400, "operação de equipe inválida")
            if self.command == "POST" and action == "team-invite":
                account = self.requested_account(user, payload.get("organization_id"))
                if not account or user["role"] not in ("owner", "super_admin"):
                    return self.fail(403, "somente o proprietário pode convidar a equipe")
                if payload.get("operation") == "cancel":
                    invite = STORE["invites"].get(payload.get("invite_id"))
                    if not invite or invite["organization_id"] != account["id"] or invite.get("accepted_at"):
                        return self.fail(404, "convite não encontrado")
                    del STORE["invites"][invite["id"]]; self.audit(user, account, "team.invite.cancelled")
                    return self.reply(200, {"ok": True})
                if payload.get("operation") != "create" or account["plan"] != "Equipe":
                    return self.fail(403, "convites de equipe estão disponíveis no plano Equipe")
                name, email = str(payload.get("name", "")).strip(), str(payload.get("email", "")).strip().lower()
                if not name or "@" not in email or any(item["email"] == email for item in STORE["users"].values()):
                    return self.fail(400, "nome e e-mail válidos são obrigatórios")
                active = sum(item["organization_id"] == account["id"] and item["status"] == "active" for item in STORE["users"].values())
                pending = sum(item["organization_id"] == account["id"] and not item.get("accepted_at") for item in STORE["invites"].values())
                if active + pending >= 3:
                    return self.fail(409, "o plano Equipe permite até 3 usuários ou convites ativos")
                token, invite_id = secrets.token_urlsafe(32), identifier(); STORE["invites"][invite_id] = {"id": invite_id, "organization_id": account["id"], "name": name, "email": email, "token_hash": password_digest(token), "expires_at": now(), "created_at": now(), "accepted_at": None}
                self.audit(user, account, "team.invite.created")
                return self.reply(200, {"ok": True, "invite_id": invite_id, "invite_path": "/#invite=" + token, "expires_in_hours": 48})
            if self.command == "POST" and action == "change-password":
                current, new = str(payload.get("current_password", "")), str(payload.get("new_password", ""))
                if len(new) < 10 or not secrets.compare_digest(user["password_hash"], password_digest(current)):
                    return self.fail(400, "senha atual incorreta ou nova senha inválida")
                user["password_hash"] = password_digest(new)
                return self.reply(200, {"ok": True})
            if user["role"] != "super_admin":
                return self.fail(403, "acesso restrito")
            if self.command == "POST" and action == "admin-password-reset":
                target = STORE["users"].get(payload.get("user_id"))
                if not target:
                    return self.fail(404, "usuário não encontrado")
                if target["role"] == "super_admin":
                    return self.fail(403, "use o procedimento de recuperação do administrador")
                account = STORE["accounts"].get(target["organization_id"])
                if target["status"] != "active" or not account or account["status"] != "active":
                    return self.fail(409, "reative o usuário e a conta antes de redefinir a senha")
                for previous in STORE["password_resets"].values():
                    if previous["user_id"] == target["id"] and not previous.get("used_at"):
                        previous["used_at"] = now()
                token, reset_id = secrets.token_urlsafe(32), identifier()
                STORE["password_resets"][reset_id] = {
                    "id": reset_id, "user_id": target["id"], "created_by": user["id"],
                    "token_hash": password_digest(token),
                    "expires_at": datetime.now(timezone.utc) + timedelta(minutes=30),
                    "used_at": None, "created_at": now(),
                }
                self.audit(user, account, "admin.password_reset.created")
                return self.reply(200, {"ok": True, "reset_path": "/#reset=" + token, "expires_in_minutes": 30})
            if self.command == "GET" and action == "admin":
                accounts = [{**account, "users_count": sum(item["organization_id"] == account["id"] for item in STORE["users"].values())} for account in STORE["accounts"].values()]
                users = [{**public_user(item), "organization_name": STORE["accounts"].get(item["organization_id"], {}).get("name")} for item in STORE["users"].values()]
                return self.reply(200, {"ok": True, "accounts": accounts, "users": users, "audits": STORE["audits"], "summary": {"accounts": len(accounts), "users": len(users), "active": sum(item["status"] == "active" for item in users)}})
            if self.command == "POST" and action == "admin-account":
                account = STORE["accounts"].get(payload.get("organization_id"))
                if not account:
                    return self.fail(404, "conta não encontrada")
                if "status" in payload and payload["status"] not in ("active", "suspended"):
                    return self.fail(400, "status inválido")
                if "plan" in payload and payload["plan"] not in ("Base", "Equipe"):
                    return self.fail(400, "plano inválido")
                changes = payload.get("permissions", {})
                if not isinstance(changes, dict) or any(key not in PERMISSIONS or type(value) is not bool for key, value in changes.items()):
                    return self.fail(400, "permissões inválidas")
                account.update({key: payload[key] for key in ("status", "plan") if key in payload})
                account["permissions"].update(changes)
                self.audit(user, account, "admin.account.updated")
                return self.reply(200, {"ok": True, "account": account, "status": account["status"]})
            if self.command == "POST" and action == "admin-user":
                target = STORE["users"].get(payload.get("user_id"))
                if not target:
                    return self.fail(404, "usuário não encontrado")
                if target["role"] == "super_admin":
                    return self.fail(403, "administrador global não pode ser suspenso por esta ação")
                if payload.get("status") not in ("active", "suspended"):
                    return self.fail(400, "status inválido")
                target["status"] = payload["status"]
                self.audit(user, STORE["accounts"][target["organization_id"]], "admin.user.updated")
                return self.reply(200, {"ok": True, "user": public_user(target)})
            return self.fail(404, "ação não encontrada")

    do_GET = route
    do_POST = route


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-only", action="store_true", help="confirmar uso apenas como fixture local")
    if not parser.parse_args().test_only:
        parser.error("use --test-only; este processo não é o backend de produção")
    seed()
    server = ThreadingHTTPServer(("127.0.0.1", 8788), Handler)
    print("TESTE LOCAL EM MEMÓRIA: http://127.0.0.1:8788 — sem PostgreSQL, Meta ou envio externo", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
