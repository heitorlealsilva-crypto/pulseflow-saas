"""Tenant-scoped integration events and signed outbound webhook delivery.

The helpers that mutate configuration or append events deliberately do not
commit.  Their caller owns the business transaction.  ``process_deliveries``
is the exception: it commits a short lease before performing network I/O so a
slow customer endpoint never holds workspace or tenant locks.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet, InvalidToken

from api import outbound_webhooks


MAX_ENDPOINTS_PER_ORGANIZATION = 3
MAX_ENDPOINT_CREATIONS_PER_HOUR = 10
MAX_EVENT_BODY = 64_000
MAX_ATTEMPTS = 8
LEASE_TIMEOUT = timedelta(minutes=10)
BATCH_DELIVERY_BUDGET_SECONDS = 20
EVENT_SCHEMA_VERSION = "1"
SUPPORTED_EVENT_TYPES = frozenset({
    "contact.created",
    "contact.updated",
    "contact.stage_changed",
    "contact.deleted",
    "contact.reply_received",
    "contacts.resync_required",
})
RETRYABLE_STATUS_CODES = frozenset({408, 425, 429})
RETRYABLE_TARGET_ERRORS = frozenset({"dns_failed", "dns_empty"})
RETRYABLE_CREDENTIAL_ERRORS = frozenset({
    "encryption_not_configured", "credentials_unreadable",
})
RETRY_DELAYS_SECONDS = (60, 300, 1_800, 7_200, 28_800, 86_400, 172_800)


class IntegrationEventError(Exception):
    def __init__(self, message, code="invalid_request", status=400):
        super().__init__(message)
        self.code = code
        self.status = status


def utcnow():
    return datetime.now(timezone.utc)


def _aware(value):
    value = value or utcnow()
    if not isinstance(value, datetime):
        raise IntegrationEventError("horário inválido", "invalid_time")
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _uuid(value, label="identificador"):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise IntegrationEventError(f"{label} inválido") from None


def _cipher():
    raw = os.getenv("PULSEFLOW_ENCRYPTION_KEY", "")
    if len(raw) < 32:
        raise IntegrationEventError(
            "A criptografia das integrações não está configurada.",
            "encryption_not_configured", 503)
    key = base64.urlsafe_b64encode(hashlib.sha256(raw.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_private_value(value):
    if not isinstance(value, str) or not value:
        raise IntegrationEventError("segredo inválido", "invalid_secret")
    return _cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_private_value(value):
    try:
        return _cipher().decrypt(str(value).encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError):
        raise IntegrationEventError(
            "A credencial do webhook não pôde ser lida.",
            "credentials_unreadable", 503) from None


def ensure_schema(db):
    """Create/upgrade event tables without committing the caller transaction."""
    db.execute("SELECT pg_advisory_xact_lock(817405209)")
    db.execute("""CREATE TABLE IF NOT EXISTS integration_events (
        id BIGSERIAL PRIMARY KEY,
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        event_type TEXT NOT NULL,
        resource_id TEXT,
        payload JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())""")
    db.execute("ALTER TABLE integration_events ADD COLUMN IF NOT EXISTS event_id UUID")
    db.execute("ALTER TABLE integration_events ADD COLUMN IF NOT EXISTS schema_version TEXT NOT NULL DEFAULT '1'")
    # Keep legacy INSERT statements compatible while giving old rows stable IDs.
    db.execute("UPDATE integration_events SET event_id=gen_random_uuid() WHERE event_id IS NULL")
    db.execute("ALTER TABLE integration_events ALTER COLUMN event_id SET DEFAULT gen_random_uuid()")
    db.execute("ALTER TABLE integration_events ALTER COLUMN event_id SET NOT NULL")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS integration_events_event_id_idx ON integration_events(event_id)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS integration_events_org_event_id_idx ON integration_events(organization_id,event_id)")
    db.execute("CREATE INDEX IF NOT EXISTS integration_events_org_cursor_idx ON integration_events(organization_id,id)")
    db.execute("""CREATE TABLE IF NOT EXISTS integration_webhook_endpoints (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
        created_by UUID REFERENCES users(id) ON DELETE SET NULL,
        name TEXT NOT NULL,
        url_enc TEXT NOT NULL,
        url_host TEXT NOT NULL,
        secret_enc TEXT NOT NULL,
        secret_prefix TEXT NOT NULL,
        event_types JSONB NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        consecutive_failures INTEGER NOT NULL DEFAULT 0,
        last_delivery_at TIMESTAMPTZ,
        last_status_code INTEGER,
        last_error TEXT,
        paused_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(organization_id,id),
        CHECK(status IN ('active','paused','revoked')),
        CHECK(jsonb_typeof(event_types)='array'))""")
    db.execute("CREATE INDEX IF NOT EXISTS webhook_endpoints_org_idx ON integration_webhook_endpoints(organization_id,created_at DESC)")
    db.execute("""CREATE TABLE IF NOT EXISTS integration_webhook_deliveries (
        id UUID PRIMARY KEY,
        organization_id UUID NOT NULL,
        endpoint_id UUID NOT NULL,
        event_id UUID NOT NULL,
        event_type TEXT NOT NULL,
        raw_body TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        lease_token UUID,
        leased_at TIMESTAMPTZ,
        response_status INTEGER,
        error_code TEXT,
        delivered_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE(organization_id,endpoint_id,event_id),
        FOREIGN KEY(organization_id,endpoint_id)
            REFERENCES integration_webhook_endpoints(organization_id,id) ON DELETE CASCADE,
        FOREIGN KEY(organization_id,event_id)
            REFERENCES integration_events(organization_id,event_id) ON DELETE CASCADE,
        CHECK(status IN ('pending','running','retry','delivered','dead','cancelled')))""")
    db.execute("CREATE INDEX IF NOT EXISTS webhook_deliveries_due_idx ON integration_webhook_deliveries(status,next_attempt_at)")
    db.execute("CREATE INDEX IF NOT EXISTS webhook_deliveries_endpoint_idx ON integration_webhook_deliveries(organization_id,endpoint_id,created_at)")


def validated_public_url(value):
    """Return the canonical URL produced by the shared pinned transport."""
    configured = os.getenv("PULSEFLOW_APP_URL", "").strip()
    if not configured:
        hostname = (os.getenv("VERCEL_PROJECT_PRODUCTION_URL", "").strip()
                    or os.getenv("VERCEL_URL", "").strip())
        configured = "https://" + hostname if hostname else None
    try:
        target = outbound_webhooks.validate_target(value, app_url=configured)
    except outbound_webhooks.WebhookError:
        # Do not expose DNS/address validation details to an authenticated
        # caller. The transport keeps its internal code for worker policy, but
        # endpoint creation has one deliberately generic public failure.
        raise IntegrationEventError(
            "Use uma URL HTTPS pública e segura.", "invalid_target") from None
    return f"https://{target.hostname}{target.path}", target.hostname


def _redacted_url(host):
    return f"https://{host}/••••"


def public_endpoint(row):
    events = row.get("event_types") if isinstance(row.get("event_types"), list) else []
    host = str(row.get("url_host") or "")
    return {
        "id": str(row.get("id") or ""),
        "name": str(row.get("name") or ""),
        "url": _redacted_url(host),
        "host": host,
        "event_types": events,
        "status": str(row.get("status") or ""),
        "created_at": row.get("created_at"),
        "updated_at": row.get("updated_at"),
        "last_delivery_at": row.get("last_delivery_at"),
        "last_status_code": row.get("last_status_code"),
        "last_error": row.get("last_error"),
    }


def list_endpoints(db, organization_id):
    organization_id = _uuid(organization_id, "conta")
    rows = db.execute("""SELECT id,name,url_host,event_types,status,created_at,updated_at,
        last_delivery_at,last_status_code,last_error
        FROM integration_webhook_endpoints
        WHERE organization_id=%s AND status<>'revoked' ORDER BY created_at DESC""",
        (organization_id,)).fetchall()
    return [public_endpoint(row) for row in rows]


def has_consumers(db, organization_id, event_type):
    """Return whether this tenant can currently consume ``event_type``."""
    organization_id = _uuid(organization_id, "conta")
    webhook = db.execute("""SELECT EXISTS(
        SELECT 1 FROM integration_webhook_endpoints e
        JOIN organizations o ON o.id=e.organization_id
        WHERE e.organization_id=%s AND e.status='active' AND e.event_types ? %s
          AND o.status='active' AND o.plan='Equipe'
          AND COALESCE(o.permissions->'workspace_read','true'::jsonb)='true'::jsonb
        ) AS subscribed""", (organization_id, event_type)).fetchone()
    if webhook and webhook.get("subscribed"):
        return True
    relation = db.execute(
        "SELECT to_regclass('public.integration_api_keys') AS keys_table"
    ).fetchone()
    if not relation or not relation.get("keys_table"):
        return False
    return bool(db.execute("""SELECT 1 FROM integration_api_keys k
        JOIN organizations o ON o.id=k.organization_id
        WHERE k.organization_id=%s AND k.revoked_at IS NULL
          AND k.scopes ? 'events:read' AND o.status='active'
          AND COALESCE(o.permissions->'workspace_read','true'::jsonb)='true'::jsonb
        LIMIT 1""", (organization_id,)).fetchone())


def _validated_event_types(values):
    if not isinstance(values, list) or not values or len(values) > len(SUPPORTED_EVENT_TYPES):
        raise IntegrationEventError("Selecione ao menos um evento válido.", "invalid_event_types")
    if any(not isinstance(value, str) or value not in SUPPORTED_EVENT_TYPES for value in values):
        raise IntegrationEventError("Evento de webhook não permitido.", "invalid_event_types")
    return sorted(set(values))


def create_endpoint(db, organization_id, *, name, url, event_types, created_by=None):
    """Create an endpoint; caller must already require owner/admin and Equipe."""
    organization_id = _uuid(organization_id, "conta")
    created_by = _uuid(created_by, "usuário") if created_by else None
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80:
        raise IntegrationEventError("Nome do webhook inválido.", "invalid_name")
    normalized_url, host = validated_public_url(url)
    events = _validated_event_types(event_types)
    organization = db.execute(
        "SELECT id,status FROM organizations WHERE id=%s FOR UPDATE",
        (organization_id,)).fetchone()
    if not organization or organization.get("status") != "active":
        raise IntegrationEventError("Conta suspensa ou indisponível.", "account_unavailable", 403)
    recent = db.execute("""SELECT COUNT(*)::int AS count
        FROM integration_webhook_endpoints
        WHERE organization_id=%s AND created_at>NOW() - INTERVAL '1 hour'""",
        (organization_id,)).fetchone()
    if int((recent or {}).get("count") or 0) >= MAX_ENDPOINT_CREATIONS_PER_HOUR:
        raise IntegrationEventError(
            "Muitas configurações de webhook em pouco tempo. Tente novamente mais tarde.",
            "rate_limited", 429)
    count = db.execute("""SELECT COUNT(*)::int AS count FROM integration_webhook_endpoints
        WHERE organization_id=%s AND status<>'revoked'""", (organization_id,)).fetchone()
    if int((count or {}).get("count") or 0) >= MAX_ENDPOINTS_PER_ORGANIZATION:
        raise IntegrationEventError("Limite de webhooks atingido.", "webhook_limit", 409)
    endpoint_id = str(uuid.uuid4())
    secret = "whsec_" + secrets.token_urlsafe(32)
    row = db.execute("""INSERT INTO integration_webhook_endpoints(
            id,organization_id,created_by,name,url_enc,url_host,secret_enc,secret_prefix,event_types)
        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
        RETURNING id,name,url_host,event_types,status,created_at,updated_at,
            last_delivery_at,last_status_code,last_error""",
        (endpoint_id, organization_id, created_by, name.strip(),
         encrypt_private_value(normalized_url), host, encrypt_private_value(secret),
         secret[:12], json.dumps(events))).fetchone()
    if not row:
        raise IntegrationEventError("Não foi possível criar o webhook.", "service_unavailable", 503)
    return {**public_endpoint(row), "secret": secret}


def revoke_endpoint(db, organization_id, endpoint_id):
    organization_id = _uuid(organization_id, "conta")
    endpoint_id = _uuid(endpoint_id, "webhook")
    row = db.execute("""UPDATE integration_webhook_endpoints
        SET status='revoked',revoked_at=NOW(),updated_at=NOW()
        WHERE organization_id=%s AND id=%s AND status<>'revoked'
        RETURNING id,name,url_host,event_types,status,created_at,updated_at,
            last_delivery_at,last_status_code,last_error""",
        (organization_id, endpoint_id)).fetchone()
    if not row:
        raise IntegrationEventError("Webhook não encontrado.", "not_found", 404)
    db.execute("""UPDATE integration_webhook_deliveries
        SET status='cancelled',error_code='endpoint_revoked',
            lease_token=NULL,leased_at=NULL,updated_at=NOW()
        WHERE organization_id=%s AND endpoint_id=%s
          AND status IN ('pending','retry','running')""",
        (organization_id, endpoint_id))
    return public_endpoint(row)


def _canonical_json(value):
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise IntegrationEventError("Payload de evento inválido.", "invalid_event_payload") from None
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_EVENT_BODY:
        raise IntegrationEventError("Payload de evento excede o limite.", "event_too_large", 413)
    return raw


def contact_snapshot(contact):
    """Build the only public contact shape used by integration events."""
    contact = contact if isinstance(contact, dict) else {}
    return {
        "id": str(contact.get("id") or contact.get("contact_id") or "")[:160],
        "board": str(contact.get("board") or "")[:40],
        "stage": str(contact.get("stage") or "")[:64],
        "opt_out": bool(contact.get("opt_out") or contact.get("optOut")
                        or contact.get("doNotContact")),
        "automation_paused": bool(contact.get("automation_paused")
                                  or contact.get("automationPaused")),
    }


def contact_event_payload(contact, *, workspace_revision=None):
    payload = {"contact": contact_snapshot(contact)}
    if workspace_revision is not None:
        payload["workspace_revision"] = int(workspace_revision)
    return payload


def stage_changed_payload(contact, previous, *, workspace_revision=None):
    payload = contact_event_payload(contact, workspace_revision=workspace_revision)
    previous = previous if isinstance(previous, dict) else {}
    payload["from"] = {
        "board": str(previous.get("board") or "")[:40],
        "stage": str(previous.get("stage") or "")[:64],
    }
    payload["to"] = {
        "board": payload["contact"]["board"],
        "stage": payload["contact"]["stage"],
    }
    return payload


def reply_received_payload(contact, message_id, occurred_at):
    return {
        **contact_event_payload(contact),
        "message": {"id": str(message_id or "")[:160]},
        "received_at": str(occurred_at or "")[:64],
    }


def emit_event(db, organization_id, event_type, resource_id, payload, now=None):
    """Append one immutable event and fan it out in the current transaction."""
    organization_id = _uuid(organization_id, "conta")
    if not isinstance(event_type, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{2,80}", event_type):
        raise IntegrationEventError("Tipo de evento inválido.", "invalid_event_type")
    if resource_id is not None and (not isinstance(resource_id, str) or len(resource_id) > 160):
        raise IntegrationEventError("Recurso do evento inválido.", "invalid_resource")
    if not isinstance(payload, dict):
        raise IntegrationEventError("Payload de evento inválido.", "invalid_event_payload")
    occurred_at = _aware(now).astimezone(timezone.utc)
    event_id = str(uuid.uuid4())
    envelope = {
        "data": payload,
        "id": event_id,
        "organization_id": organization_id,
        "resource_id": resource_id,
        "schema_version": EVENT_SCHEMA_VERSION,
        "type": event_type,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
    }
    raw_body = _canonical_json(envelope)
    inserted_event = db.execute("""INSERT INTO integration_events(
            organization_id,event_id,schema_version,event_type,resource_id,payload,created_at)
        VALUES(%s,%s,%s,%s,%s,%s::jsonb,%s)
        RETURNING id AS cursor""",
        (organization_id, event_id, EVENT_SCHEMA_VERSION, event_type,
         resource_id, json.dumps(payload, ensure_ascii=False, allow_nan=False), occurred_at)).fetchone()
    endpoints = db.execute("""SELECT e.id FROM integration_webhook_endpoints e
        JOIN organizations o ON o.id=e.organization_id
        WHERE e.organization_id=%s AND e.status='active' AND e.event_types ? %s
          AND o.status='active' AND o.plan='Equipe'
          AND COALESCE(o.permissions->'workspace_read','true'::jsonb)='true'::jsonb
        ORDER BY e.created_at""", (organization_id, event_type)).fetchall()
    deliveries = []
    for endpoint in endpoints:
        delivery_id = str(uuid.uuid4())
        inserted = db.execute("""INSERT INTO integration_webhook_deliveries(
                id,organization_id,endpoint_id,event_id,event_type,raw_body,next_attempt_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT(organization_id,endpoint_id,event_id) DO NOTHING
            RETURNING id,status,created_at""",
            (delivery_id, organization_id, endpoint["id"], event_id,
             event_type, raw_body, occurred_at)).fetchone()
        if inserted:
            deliveries.append({"id": str(inserted["id"]),
                               "status": inserted.get("status", "pending"),
                               "created_at": inserted.get("created_at", occurred_at)})
    return {"id": event_id, "cursor": (inserted_event or {}).get("cursor"),
            "type": event_type, "occurred_at": occurred_at,
            "raw_body": raw_body, "deliveries": deliveries}


def enqueue_test_delivery(db, organization_id, endpoint_id, now=None):
    """Queue a synthetic delivery without exposing any customer data."""
    organization_id = _uuid(organization_id, "conta")
    endpoint_id = _uuid(endpoint_id, "webhook")
    occurred_at = _aware(now).astimezone(timezone.utc)
    endpoint = db.execute("""SELECT id FROM integration_webhook_endpoints
        WHERE organization_id=%s AND id=%s AND status='active' FOR UPDATE""",
        (organization_id, endpoint_id)).fetchone()
    if not endpoint:
        raise IntegrationEventError("Webhook não encontrado.", "not_found", 404)
    recent_test = db.execute("""SELECT 1 FROM integration_webhook_deliveries
        WHERE organization_id=%s AND endpoint_id=%s
          AND event_type='pulseflow.webhook_test'
          AND created_at>NOW() - INTERVAL '30 seconds' LIMIT 1""",
        (organization_id, endpoint_id)).fetchone()
    if recent_test:
        raise IntegrationEventError(
            "Aguarde alguns segundos antes de testar novamente.",
            "rate_limited", 429)
    event_id, delivery_id = str(uuid.uuid4()), str(uuid.uuid4())
    event_type = "pulseflow.webhook_test"
    payload = {"test": True, "message": "Teste de entrega do PulseFlow"}
    envelope = {
        "data": payload,
        "id": event_id,
        "organization_id": organization_id,
        "resource_id": None,
        "schema_version": EVENT_SCHEMA_VERSION,
        "type": event_type,
        "occurred_at": occurred_at.isoformat().replace("+00:00", "Z"),
    }
    raw_body = _canonical_json(envelope)
    db.execute("""INSERT INTO integration_events(
            organization_id,event_id,schema_version,event_type,resource_id,payload,created_at)
        VALUES(%s,%s,%s,%s,NULL,%s::jsonb,%s)""",
        (organization_id, event_id, EVENT_SCHEMA_VERSION, event_type,
         json.dumps(payload, ensure_ascii=False), occurred_at))
    row = db.execute("""INSERT INTO integration_webhook_deliveries(
            id,organization_id,endpoint_id,event_id,event_type,raw_body,next_attempt_at)
        VALUES(%s,%s,%s,%s,%s,%s,%s)
        RETURNING id,status,created_at""",
        (delivery_id, organization_id, endpoint_id, event_id,
         event_type, raw_body, occurred_at)).fetchone()
    return {
        "event_id": event_id,
        "delivery": {
            "id": str(row["id"] if row else delivery_id),
            "status": (row or {}).get("status", "pending"),
            "created_at": (row or {}).get("created_at", occurred_at),
        },
    }


def _sender_result(value):
    if isinstance(value, outbound_webhooks.DeliveryResult):
        return int(value.status_code)
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return int(value.get("status_code") or value.get("status") or 0)
    raise ValueError("invalid sender result")


def _retry_time(now, attempts):
    index = min(max(0, attempts - 1), len(RETRY_DELAYS_SECONDS) - 1)
    return now + timedelta(seconds=RETRY_DELAYS_SECONDS[index])


def _cancel_endpoint_backlog(db, organization_id, endpoint_id, reason):
    db.execute("""UPDATE integration_webhook_deliveries
        SET status='cancelled',error_code=%s,lease_token=NULL,leased_at=NULL,
            updated_at=NOW()
        WHERE organization_id=%s AND endpoint_id=%s
          AND status IN ('pending','retry')""",
        (reason, organization_id, endpoint_id))


def _claim_delivery(db, now):
    lease_token = str(uuid.uuid4())
    row = db.execute("""WITH candidate AS (
        SELECT d.id FROM integration_webhook_deliveries d
        JOIN integration_webhook_endpoints e
          ON e.organization_id=d.organization_id AND e.id=d.endpoint_id
        JOIN organizations o ON o.id=d.organization_id
        WHERE d.status IN ('pending','retry') AND d.next_attempt_at<=%s
          AND e.status='active' AND o.status='active' AND o.plan='Equipe'
          AND COALESCE(o.permissions->'workspace_read','true'::jsonb)='true'::jsonb
          AND NOT EXISTS (
            SELECT 1 FROM integration_webhook_deliveries older
            WHERE older.organization_id=d.organization_id
              AND older.endpoint_id=d.endpoint_id
              AND (older.created_at<d.created_at
                OR (older.created_at=d.created_at AND older.id<d.id))
              AND older.status IN ('pending','running','retry'))
        ORDER BY d.next_attempt_at,d.created_at
        LIMIT 1 FOR UPDATE OF d SKIP LOCKED)
        UPDATE integration_webhook_deliveries d
        SET status='running',attempts=d.attempts+1,lease_token=%s,leased_at=%s,
            error_code=NULL,updated_at=NOW()
        FROM candidate WHERE d.id=candidate.id
        RETURNING d.*, %s::uuid AS claimed_lease""",
        (now, lease_token, now, lease_token)).fetchone()
    return row


def process_deliveries(db, now=None, limit=20, sender=None, delivery_clock=None,
                       monotonic_clock=None, batch_budget_seconds=BATCH_DELIVERY_BUDGET_SECONDS):
    """Deliver due jobs with short leases and at-least-once semantics."""
    now = _aware(now).astimezone(timezone.utc)
    sender = sender or outbound_webhooks.deliver
    delivery_clock = delivery_clock or utcnow
    monotonic_clock = monotonic_clock or time.monotonic
    limit = max(0, min(int(limit), 100))
    try:
        batch_budget_seconds = max(0, min(float(batch_budget_seconds), 120))
    except (TypeError, ValueError):
        batch_budget_seconds = BATCH_DELIVERY_BUDGET_SECONDS
    batch_deadline = monotonic_clock() + batch_budget_seconds
    stats = {"claimed": 0, "delivered": 0, "retry": 0, "dead": 0, "paused": 0}
    # If the final attempt crashed after a network call, pause the destination
    # before recovering its lease. Newer rows must not remain queued forever
    # behind an endpoint that can no longer be claimed.
    db.execute("""UPDATE integration_webhook_endpoints e SET status='paused',
        paused_at=%s,last_error='lease_expired_max_attempts',updated_at=NOW()
        WHERE e.status='active' AND EXISTS (
            SELECT 1 FROM integration_webhook_deliveries d
            WHERE d.organization_id=e.organization_id AND d.endpoint_id=e.id
              AND d.status='running' AND d.attempts>=%s AND d.leased_at<%s)""",
        (now, MAX_ATTEMPTS, now - LEASE_TIMEOUT))
    db.execute("""UPDATE integration_webhook_deliveries SET
        status=CASE WHEN attempts>=%s THEN 'dead' ELSE 'retry' END,
        next_attempt_at=%s,lease_token=NULL,leased_at=NULL,
        error_code='lease_expired',updated_at=NOW()
        WHERE status='running' AND leased_at<%s""",
        (MAX_ATTEMPTS, now, now - LEASE_TIMEOUT))
    db.execute("""UPDATE integration_webhook_deliveries d
        SET status='cancelled',error_code=COALESCE(d.error_code,'endpoint_paused'),
            lease_token=NULL,leased_at=NULL,updated_at=NOW()
        FROM integration_webhook_endpoints e
        WHERE e.organization_id=d.organization_id AND e.id=d.endpoint_id
          AND e.status='paused' AND d.status IN ('pending','retry')""")
    db.commit()
    for _ in range(limit):
        if monotonic_clock() >= batch_deadline:
            break
        delivery = _claim_delivery(db, now)
        if not delivery:
            db.commit()
            break
        db.commit()  # The lease must be visible before customer-controlled I/O.
        stats["claimed"] += 1
        delivery_id = delivery["id"]
        organization_id = delivery["organization_id"]
        endpoint_id = delivery["endpoint_id"]
        lease_token = delivery.get("claimed_lease") or delivery.get("lease_token")
        attempts = int(delivery.get("attempts") or 0)
        endpoint = db.execute("""SELECT url_enc,secret_enc,status FROM integration_webhook_endpoints
            WHERE organization_id=%s AND id=%s""",
            (organization_id, endpoint_id)).fetchone()
        if not endpoint or endpoint.get("status") != "active":
            db.execute("""UPDATE integration_webhook_deliveries
                SET status='cancelled',lease_token=NULL,leased_at=NULL,
                    error_code='endpoint_inactive',updated_at=NOW()
                WHERE organization_id=%s AND id=%s AND lease_token=%s""",
                (organization_id, delivery_id, lease_token))
            db.commit()
            continue
        response_status = None
        retryable = False
        error_code = None
        pause_reason = None
        try:
            url = decrypt_private_value(endpoint["url_enc"])
            secret = decrypt_private_value(endpoint["secret_enc"])
            raw_body = str(delivery["raw_body"]).encode("utf-8")
            attempt_time = _aware(delivery_clock()).astimezone(timezone.utc)
            response_status = _sender_result(sender(
                url, secret, str(delivery["event_id"]), str(delivery_id),
                str(delivery["event_type"]), raw_body, now=attempt_time))
            retryable = response_status in RETRYABLE_STATUS_CODES or response_status >= 500
            error_code = None if 200 <= response_status < 300 else f"http_{response_status or 'invalid'}"
        except outbound_webhooks.TargetValidationError as error:
            retryable = error.code in RETRYABLE_TARGET_ERRORS
            error_code = error.code
            pause_reason = None if retryable else error.code
        except outbound_webhooks.DeliveryError as error:
            retryable = error.code == "delivery_failed"
            error_code = error.code
        except outbound_webhooks.WebhookError as error:
            retryable, error_code = False, error.code
            pause_reason = error.code
        except (TimeoutError, OSError, ValueError):
            retryable, error_code = True, "network_error"
        except IntegrationEventError as error:
            retryable = error.code in RETRYABLE_CREDENTIAL_ERRORS
            error_code = error.code
            pause_reason = None if retryable else error.code
        except Exception:
            # One customer endpoint must never abort the scheduler for every
            # tenant. Keep the diagnostic deliberately generic: third-party
            # exceptions can contain URLs, response bodies or credentials.
            retryable, error_code = True, "delivery_exception"

        if response_status is not None and 200 <= response_status < 300:
            status, next_attempt = "delivered", None
            stats["delivered"] += 1
        elif response_status == 410:
            status, next_attempt = "dead", None
            stats["dead"] += 1
            stats["paused"] += 1
            db.execute("""UPDATE integration_webhook_endpoints SET status='paused',
                paused_at=%s,last_delivery_at=%s,last_status_code=410,
                last_error='http_410',consecutive_failures=consecutive_failures+1,updated_at=NOW()
                WHERE organization_id=%s AND id=%s AND status='active'""",
                (now, now, organization_id, endpoint_id))
            _cancel_endpoint_backlog(db, organization_id, endpoint_id, "http_410")
        elif retryable and attempts < MAX_ATTEMPTS:
            status = "retry"
            next_attempt = _retry_time(now, attempts)
            stats["retry"] += 1
        else:
            status, next_attempt = "dead", None
            stats["dead"] += 1
            if pause_reason or (retryable and attempts >= MAX_ATTEMPTS):
                stats["paused"] += 1
                db.execute("""UPDATE integration_webhook_endpoints SET status='paused',
                    paused_at=%s,last_delivery_at=%s,last_status_code=%s,
                    last_error=%s,consecutive_failures=consecutive_failures+1,
                    updated_at=NOW()
                    WHERE organization_id=%s AND id=%s AND status='active'""",
                    (now, now, response_status, pause_reason or "max_attempts",
                     organization_id, endpoint_id))
                _cancel_endpoint_backlog(
                    db, organization_id, endpoint_id,
                    pause_reason or "max_attempts")

        db.execute("""UPDATE integration_webhook_deliveries SET status=%s,
            next_attempt_at=COALESCE(%s,next_attempt_at),response_status=%s,error_code=%s,
            delivered_at=CASE WHEN %s='delivered' THEN %s ELSE delivered_at END,
            lease_token=NULL,leased_at=NULL,updated_at=NOW()
            WHERE organization_id=%s AND id=%s AND lease_token=%s""",
            (status, next_attempt, response_status, error_code, status, now,
             organization_id, delivery_id, lease_token))
        if (response_status != 410 and not pause_reason
                and not (retryable and attempts >= MAX_ATTEMPTS)):
            db.execute("""UPDATE integration_webhook_endpoints SET
                last_delivery_at=%s,last_status_code=%s,last_error=%s,
                consecutive_failures=CASE WHEN %s='delivered' THEN 0 ELSE consecutive_failures+1 END,
                updated_at=NOW() WHERE organization_id=%s AND id=%s""",
                (now, response_status, error_code, status, organization_id, endpoint_id))
        db.commit()
    return stats


def cleanup_history(db, now=None, limit=500):
    """Delete bounded, completed integration history older than 90 days."""
    now = _aware(now).astimezone(timezone.utc)
    cutoff = now - timedelta(days=90)
    limit = max(1, min(int(limit), 5_000))
    deliveries = db.execute("""DELETE FROM integration_webhook_deliveries
        WHERE id IN (
            SELECT id FROM integration_webhook_deliveries
            WHERE created_at<%s AND status IN ('delivered','dead','cancelled')
            ORDER BY created_at LIMIT %s)
        RETURNING id""", (cutoff, limit)).fetchall()
    events = db.execute("""DELETE FROM integration_events e
        WHERE e.id IN (
            SELECT candidate.id FROM integration_events candidate
            WHERE candidate.created_at<%s AND NOT EXISTS (
                SELECT 1 FROM integration_webhook_deliveries d
                WHERE d.organization_id=candidate.organization_id
                  AND d.event_id=candidate.event_id)
            ORDER BY candidate.created_at LIMIT %s)
        RETURNING e.id""", (cutoff, limit)).fetchall()
    endpoints = db.execute("""DELETE FROM integration_webhook_endpoints e
        WHERE e.id IN (
            SELECT candidate.id FROM integration_webhook_endpoints candidate
            WHERE candidate.status='revoked' AND candidate.revoked_at<%s
              AND NOT EXISTS (
                SELECT 1 FROM integration_webhook_deliveries d
                WHERE d.organization_id=candidate.organization_id
                  AND d.endpoint_id=candidate.id)
            ORDER BY candidate.revoked_at LIMIT %s)
        RETURNING e.id""", (cutoff, limit)).fetchall()
    db.commit()
    return {"deliveries": len(deliveries), "events": len(events),
            "endpoints": len(endpoints)}
