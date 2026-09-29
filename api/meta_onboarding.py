"""Server-side Meta OAuth/Embedded Signup primitives.

The browser receives only public application identifiers and a short-lived
authorization URL.  App secrets, authorization codes, access tokens and PKCE
verifiers never become tenant workspace data and are never returned by status
endpoints.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlencode, urlparse


MAX_PROVIDER_BODY = 1_000_000
FLOW_TTL = timedelta(minutes=10)


class OnboardingError(Exception):
    def __init__(self, message, code="meta_onboarding_unavailable", status=503):
        super().__init__(message)
        self.code, self.status = code, status


def _truthy(name, default=False):
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _graph_version():
    value = os.getenv("META_GRAPH_VERSION", "v23.0").strip()
    if not re.fullmatch(r"v\d{1,2}\.0", value):
        raise OnboardingError("A versão da API da Meta está inválida.", "meta_configuration_invalid")
    return value


def _app_origin():
    value = os.getenv("PULSEFLOW_APP_URL", "https://pulseflow-saas-alpha.vercel.app").strip().rstrip("/")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        raise OnboardingError("A URL pública do PulseFlow está inválida.", "meta_configuration_invalid")
    if parsed.scheme == "http" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise OnboardingError("A conexão com a Meta exige HTTPS.", "meta_configuration_invalid")
    return value


def oauth_config(require_secret=True):
    app_id = os.getenv("META_APP_ID", "").strip()
    app_secret = os.getenv("META_APP_SECRET", "").strip()
    config_id = os.getenv("META_EMBEDDED_SIGNUP_CONFIG_ID", "").strip()
    if not re.fullmatch(r"\d{5,30}", app_id):
        raise OnboardingError("O aplicativo da Meta ainda não foi configurado.", "meta_app_not_configured")
    if not re.fullmatch(r"\d{5,40}", config_id):
        raise OnboardingError("A configuração do Cadastro Incorporado da Meta ainda não foi criada.", "meta_embedded_signup_not_configured")
    if require_secret and len(app_secret) < 16:
        raise OnboardingError("O segredo do aplicativo da Meta ainda não foi configurado no servidor.", "meta_app_secret_not_configured")
    graph_version = _graph_version()
    default_redirect = _app_origin() + "/api/whatsapp?action=onboarding-callback"
    redirect_uri = os.getenv("META_OAUTH_REDIRECT_URI", default_redirect).strip()
    redirect = urlparse(redirect_uri)
    expected = urlparse(_app_origin())
    if ((redirect.scheme, redirect.netloc.lower()) != (expected.scheme, expected.netloc.lower())
            or redirect.path.rstrip("/") != "/api/whatsapp"
            or parse_qs(redirect.query).get("action") != ["onboarding-callback"]):
        raise OnboardingError("A URL de retorno da Meta não corresponde ao PulseFlow.", "meta_redirect_invalid")
    return {
        "app_id": app_id,
        "app_secret": app_secret,
        "config_id": config_id,
        "graph_version": graph_version,
        "redirect_uri": redirect_uri,
        "pkce_enabled": _truthy("META_OAUTH_PKCE_ENABLED", False),
    }


def public_configuration():
    missing = []
    for name in ("META_APP_ID", "META_APP_SECRET", "META_EMBEDDED_SIGNUP_CONFIG_ID",
                 "META_WEBHOOK_VERIFY_TOKEN", "PULSEFLOW_ENCRYPTION_KEY"):
        value = os.getenv(name, "")
        minimum = 32 if name in ("META_WEBHOOK_VERIFY_TOKEN", "PULSEFLOW_ENCRYPTION_KEY") else 1
        if len(value.strip()) < minimum:
            missing.append(name)
    try:
        config = oauth_config(require_secret=False)
    except OnboardingError as error:
        return {"ready": False, "code": error.code, "missing": missing}
    return {
        "ready": not missing,
        "app_id": config["app_id"],
        "config_id": config["config_id"],
        "graph_version": config["graph_version"],
        "pkce_enabled": config["pkce_enabled"],
        "missing": missing,
    }


def _fernet():
    from cryptography.fernet import Fernet
    raw = os.getenv("PULSEFLOW_ENCRYPTION_KEY", "")
    if len(raw) < 32:
        raise OnboardingError("A criptografia do servidor ainda não foi configurada.", "encryption_not_configured")
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw.encode()).digest()))


def encrypt_private(value):
    return _fernet().encrypt(value.encode()).decode("ascii")


def decrypt_private(value):
    from cryptography.fernet import InvalidToken
    try:
        return _fernet().decrypt(value.encode()).decode()
    except (InvalidToken, AttributeError, TypeError):
        raise OnboardingError("Reinicie a conexão com a Meta.", "onboarding_credentials_unreadable", 409) from None


def ensure_schema(db):
    statements = [
        """CREATE TABLE IF NOT EXISTS meta_onboarding_flows (
            id UUID PRIMARY KEY, organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            session_hash TEXT NOT NULL, state_hash TEXT NOT NULL UNIQUE,
            return_path TEXT NOT NULL DEFAULT '/', code_verifier_enc TEXT,
            access_token_enc TEXT, waba_id TEXT, phone_number_id TEXT,
            status TEXT NOT NULL DEFAULT 'pending', error_code TEXT,
            expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ,
            authorized_at TIMESTAMPTZ, completed_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
        "CREATE INDEX IF NOT EXISTS meta_onboarding_org_idx ON meta_onboarding_flows(organization_id,created_at DESC)",
        "CREATE INDEX IF NOT EXISTS meta_onboarding_expiry_idx ON meta_onboarding_flows(expires_at)",
        """CREATE TABLE IF NOT EXISTS meta_app_configuration (
            singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
            webhook_verified_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""",
    ]
    for statement in statements:
        db.execute(statement)


def session_hash_from_cookie(cookie_header):
    from http import cookies
    try:
        jar = cookies.SimpleCookie(cookie_header or "")
        token = jar.get("pulseflow_session")
    except cookies.CookieError:
        token = None
    if not token or not token.value or len(token.value) > 256:
        return ""
    return hashlib.sha256(token.value.encode()).hexdigest()


def safe_return_path(value):
    raw = str(value or "/").strip()
    if not raw or len(raw) > 1000 or any(ord(char) < 32 for char in raw):
        return "/"
    parsed = urlparse(raw)
    if parsed.scheme or parsed.netloc:
        try:
            expected = urlparse(_app_origin())
        except OnboardingError:
            return "/"
        if ((parsed.scheme, parsed.netloc.lower()) !=
                (expected.scheme, expected.netloc.lower())):
            return "/"
    if not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return "/"
    return parsed.path + (("?" + parsed.query) if parsed.query else "")


def _now():
    return datetime.now(timezone.utc)


def start_flow(db, organization_id, user_id, session_hash, return_url="/"):
    if not session_hash:
        raise OnboardingError("Entre novamente antes de conectar a Meta.", "unauthenticated", 401)
    config = oauth_config()
    # Fail before creating a flow if the shared webhook cannot be verified.
    verify_token = os.getenv("META_WEBHOOK_VERIFY_TOKEN", "").strip()
    if len(verify_token) < 32:
        raise OnboardingError("O webhook compartilhado da Meta ainda não foi configurado no servidor.", "meta_webhook_not_configured")
    _fernet()
    db.execute("""UPDATE meta_onboarding_flows SET status='expired',access_token_enc=NULL,
        code_verifier_enc=NULL,updated_at=NOW() WHERE expires_at<=NOW() AND status IN ('pending','authorized','asset_selection_required')""")
    recent = db.execute("""SELECT COUNT(*) AS count FROM meta_onboarding_flows
        WHERE user_id=%s AND created_at>NOW()-INTERVAL '10 minutes'""", (user_id,)).fetchone()
    if recent and int(recent.get("count") or 0) >= 5:
        raise OnboardingError("Muitas tentativas de conexão. Aguarde alguns minutos.", "onboarding_rate_limited", 429)
    db.execute("""UPDATE meta_onboarding_flows SET status='superseded',access_token_enc=NULL,
        code_verifier_enc=NULL,updated_at=NOW() WHERE organization_id=%s AND user_id=%s
        AND session_hash=%s AND status IN ('pending','authorized','asset_selection_required')""",
        (organization_id, user_id, session_hash))
    flow_id = str(uuid.uuid4())
    state = secrets.token_urlsafe(32)
    verifier, verifier_enc = None, None
    params = {
        "client_id": config["app_id"],
        "redirect_uri": config["redirect_uri"],
        "state": state,
        "response_type": "code",
        "config_id": config["config_id"],
        "override_default_response_type": "true",
    }
    if config["pkce_enabled"]:
        verifier = secrets.token_urlsafe(64)
        verifier_enc = encrypt_private(verifier)
        params.update(code_challenge=base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(),
            code_challenge_method="S256")
    expires_at = _now() + FLOW_TTL
    db.execute("""INSERT INTO meta_onboarding_flows(
        id,organization_id,user_id,session_hash,state_hash,return_path,code_verifier_enc,expires_at)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s)""",
        (flow_id, organization_id, user_id, session_hash, hashlib.sha256(state.encode()).hexdigest(),
         safe_return_path(return_url), verifier_enc, expires_at))
    db.commit()
    url = f"https://www.facebook.com/{config['graph_version']}/dialog/oauth?{urlencode(params)}"
    return {"authorization_url": url, "flow_id": flow_id, "state": state,
            "expires_at": expires_at, "app_id": config["app_id"],
            "config_id": config["config_id"], "pkce_enabled": config["pkce_enabled"]}


def consume_state(db, state, session_hash):
    if not isinstance(state, str) or not 32 <= len(state) <= 256 or not session_hash:
        raise OnboardingError("A tentativa de conexão é inválida ou expirou.", "invalid_oauth_state", 400)
    row = db.execute("""UPDATE meta_onboarding_flows SET used_at=NOW(),status='exchanging',updated_at=NOW()
        WHERE state_hash=%s AND session_hash=%s AND used_at IS NULL AND expires_at>NOW()
          AND status='pending' RETURNING *""",
        (hashlib.sha256(state.encode()).hexdigest(), session_hash)).fetchone()
    if not row:
        raise OnboardingError("A tentativa de conexão é inválida, expirou ou já foi usada.", "invalid_oauth_state", 409)
    db.commit()
    return row


def _provider_json(request):
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(MAX_PROVIDER_BODY + 1)
    except urllib.error.HTTPError as error:
        if error.code in (400, 401, 403):
            raise OnboardingError("A Meta recusou a autorização. Recomece a conexão e confirme as permissões.", "meta_authorization_rejected", 409) from None
        raise OnboardingError("A Meta está temporariamente indisponível.", "meta_provider_unavailable", 502) from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise OnboardingError("Não foi possível falar com a Meta agora.", "meta_provider_unavailable", 502) from None
    if len(raw) > MAX_PROVIDER_BODY:
        raise OnboardingError("A Meta retornou uma resposta inesperada.", "meta_invalid_response", 502)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise OnboardingError("A Meta retornou uma resposta inválida.", "meta_invalid_response", 502) from None
    if not isinstance(value, dict):
        raise OnboardingError("A Meta retornou uma resposta inválida.", "meta_invalid_response", 502)
    return value


def exchange_code(code, flow):
    if not isinstance(code, str) or not 8 <= len(code) <= 4096 or not re.fullmatch(r"[A-Za-z0-9._-]+", code):
        raise OnboardingError("O código de autorização da Meta é inválido.", "invalid_authorization_code", 400)
    config = oauth_config()
    fields = {"client_id": config["app_id"], "client_secret": config["app_secret"],
              "redirect_uri": config["redirect_uri"], "code": code}
    if flow.get("code_verifier_enc"):
        fields["code_verifier"] = decrypt_private(flow["code_verifier_enc"])
    request = urllib.request.Request(
        f"https://graph.facebook.com/{config['graph_version']}/oauth/access_token",
        data=urlencode(fields).encode(), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    result = _provider_json(request)
    token = result.get("access_token")
    if not isinstance(token, str) or not 16 <= len(token) <= 8192:
        raise OnboardingError("A Meta não devolveu uma credencial utilizável.", "meta_invalid_response", 502)
    return token


def graph_call(access_token, path, method="GET"):
    config = oauth_config()
    if not isinstance(path, str) or not path or path.startswith(("http://", "https://")):
        raise OnboardingError("Consulta inválida à Meta.", "meta_invalid_request", 500)
    request = urllib.request.Request(
        f"https://graph.facebook.com/{config['graph_version']}/{path}", method=method,
        data=b"" if method == "POST" else None,
        headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
    return _provider_json(request)


def discover_assets(access_token):
    """Return visible WABA/phone pairs without guessing an association.

    Embedded Signup deployments can pin ``META_BUSINESS_ID``.  Otherwise we
    enumerate only businesses explicitly visible to the short-lived token.
    An empty or ambiguous result is left for the UI to resolve; it is never
    silently attached to a tenant.
    """
    configured_business = os.getenv("META_BUSINESS_ID", "").strip()
    if configured_business:
        if not re.fullmatch(r"\d{5,30}", configured_business):
            raise OnboardingError("O identificador empresarial da Meta está inválido.",
                                  "meta_configuration_invalid")
        business_ids = [configured_business]
    else:
        businesses = graph_call(access_token, "me/businesses?fields=id&limit=100")
        business_ids = [str(item.get("id")) for item in businesses.get("data", [])
                        if re.fullmatch(r"\d{5,30}", str(item.get("id", "")))][:100]
    wabas = {}
    for business_id in business_ids:
        for edge in ("owned_whatsapp_business_accounts", "client_whatsapp_business_accounts"):
            try:
                result = graph_call(access_token, f"{business_id}/{edge}?fields=id,name&limit=100")
            except OnboardingError as error:
                if error.code == "meta_authorization_rejected":
                    continue
                raise
            for item in result.get("data", []):
                value = str(item.get("id", ""))
                if re.fullmatch(r"\d{5,30}", value):
                    wabas[value] = str(item.get("name") or "")[:200]
    assets = []
    for waba_id, waba_name in list(wabas.items())[:100]:
        phones = graph_call(access_token,
                            f"{waba_id}/phone_numbers?fields=id,display_phone_number,verified_name&limit=100")
        for phone in phones.get("data", []):
            phone_id = str(phone.get("id", ""))
            if re.fullmatch(r"\d{5,30}", phone_id):
                assets.append({"waba_id": waba_id, "waba_name": waba_name,
                               "phone_number_id": phone_id,
                               "display_phone_number": str(phone.get("display_phone_number") or "")[:40],
                               "verified_name": str(phone.get("verified_name") or "")[:200]})
    return assets


def validate_assets(access_token, waba_id, phone_number_id):
    if not re.fullmatch(r"\d{5,30}", str(waba_id or "")) or not re.fullmatch(r"\d{5,30}", str(phone_number_id or "")):
        raise OnboardingError("A Meta não informou uma conta e um número válidos.", "meta_assets_missing", 409)
    phone = graph_call(access_token, f"{phone_number_id}?fields=id,display_phone_number")
    phones = graph_call(access_token, f"{waba_id}/phone_numbers?fields=id,display_phone_number&limit=100")
    match = next((item for item in phones.get("data", [])
                  if str(item.get("id")) == str(phone_number_id)), None)
    if str(phone.get("id")) != str(phone_number_id) or not match:
        raise OnboardingError("O número escolhido não pertence à conta WhatsApp autorizada.", "meta_account_mismatch", 409)
    return str(phone.get("display_phone_number") or match.get("display_phone_number") or "")[:40]


def subscribe_app(access_token, waba_id):
    result = graph_call(access_token, f"{waba_id}/subscribed_apps", "POST")
    if result.get("success") is not True:
        raise OnboardingError("A conta foi autorizada, mas a Meta não confirmou o webhook.", "meta_subscription_failed", 502)


def remember_authorization(db, flow_id, access_token, status="authorized", error_code=None):
    db.execute("""UPDATE meta_onboarding_flows SET access_token_enc=%s,status=%s,error_code=%s,
        authorized_at=NOW(),code_verifier_enc=NULL,updated_at=NOW() WHERE id=%s""",
        (encrypt_private(access_token), status, error_code, flow_id))
    db.commit()


def mark_failed(db, flow_id, code):
    db.execute("""UPDATE meta_onboarding_flows SET status='failed',error_code=%s,
        code_verifier_enc=NULL,access_token_enc=NULL,updated_at=NOW() WHERE id=%s""", (str(code)[:100], flow_id))
    db.commit()


def complete_flow(db, flow_id, organization_id, user_id, session_hash, waba_id, phone_number_id):
    try:
        normalized = str(uuid.UUID(str(flow_id)))
    except (ValueError, TypeError, AttributeError):
        raise OnboardingError("A autorização informada é inválida.", "invalid_onboarding_flow", 400) from None
    row = db.execute("""SELECT * FROM meta_onboarding_flows WHERE id=%s AND organization_id=%s
        AND user_id=%s AND session_hash=%s FOR UPDATE""",
        (normalized, organization_id, user_id, session_hash)).fetchone()
    if not row or row.get("status") not in ("authorized", "asset_selection_required") or not row.get("access_token_enc"):
        raise OnboardingError("A autorização não está disponível para conclusão.", "onboarding_not_authorized", 409)
    if row.get("expires_at") and row["expires_at"] <= _now():
        raise OnboardingError("A autorização expirou. Comece novamente.", "onboarding_expired", 409)
    token = decrypt_private(row["access_token_enc"])
    business_number = validate_assets(token, str(waba_id), str(phone_number_id))
    return row, token, business_number


def status_payload(db, organization_id, session_hash):
    row = db.execute("""SELECT id,status,error_code,waba_id,phone_number_id,expires_at,created_at,completed_at
        FROM meta_onboarding_flows WHERE organization_id=%s AND session_hash=%s
        ORDER BY created_at DESC LIMIT 1""", (organization_id, session_hash)).fetchone()
    flow = None
    if row:
        flow = {key: row.get(key) for key in ("id", "status", "error_code", "waba_id",
                "phone_number_id", "expires_at", "created_at", "completed_at")}
    raw_status = str((flow or {}).get("status") or "idle")
    if raw_status == "completed":
        ui_status = "connected"
    elif raw_status in ("failed", "expired", "superseded"):
        ui_status = "failed"
    elif raw_status in ("pending", "exchanging", "authorized"):
        ui_status = "pending"
    elif raw_status == "asset_selection_required":
        # The current simplified UI has no asset picker. Reporting an honest
        # actionable error is preferable to polling forever.
        ui_status = "failed"
    else:
        ui_status = "idle"
    onboarding = {"status": ui_status, "provider_status": raw_status}
    if flow:
        onboarding.update({"flow_id": flow.get("id"), "expires_at": flow.get("expires_at"),
                           "error_code": flow.get("error_code")})
        if raw_status == "asset_selection_required":
            onboarding["error"] = ("A Meta autorizou a conta, mas há mais de um ativo disponível. "
                                   "Escolha o número na configuração avançada ou reinicie o cadastro.")
    return {"configuration": public_configuration(), "flow": flow,
            "onboarding": onboarding}
