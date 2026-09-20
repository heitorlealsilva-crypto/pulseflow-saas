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
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server import Handler as StaticHandler  # noqa: E402

PERMISSIONS = {name: True for name in (
    "workspace_read", "workspace_write", "manage_settings", "whatsapp_read", "whatsapp_send", "whatsapp_manage"
)}
LOCK = threading.RLock()
STORE = {"accounts": {}, "users": {}, "sessions": {}, "workspaces": {}, "audits": []}


def now():
    return datetime.now(timezone.utc).isoformat()


def identifier():
    return str(uuid.uuid4())


def password_digest(value):
    # Local fixture only. Production password handling lives in api/auth.py.
    return hashlib.sha256(value.encode()).hexdigest()


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
            source = self.headers.get("Origin") or self.headers.get("Referer", "")
            if urlsplit(source).netloc != self.headers.get("Host"):
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
                if any(item["email"] == email for item in STORE["users"].values()):
                    return self.fail(409, "e-mail já cadastrado")
                account_id, user_id = identifier(), identifier()
                STORE["accounts"][account_id] = {"id": account_id, "name": payload["company"].strip(), "plan": "Base", "status": "active", "permissions": dict(PERMISSIONS), "niche": "", "whatsapp": "", "created_at": now()}
                user = {"id": user_id, "name": payload["name"].strip(), "email": email, "role": "owner", "status": "active", "organization_id": account_id, "password_hash": password_digest(payload["password"]), "created_at": now(), "last_login_at": None}
                STORE["users"][user_id] = user
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
            if not user:
                return self.fail(401, "não autenticado")
            if self.command == "GET" and action == "me":
                return self.reply(200, {"ok": True, "user": public_user(user), "account": STORE["accounts"].get(user["organization_id"])})
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
            if user["role"] != "super_admin":
                return self.fail(403, "acesso restrito")
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
