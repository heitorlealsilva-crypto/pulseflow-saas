"""Shared durable runtime events for background processing.

The workspace JSON remains the UI read model, while ``platform_alerts`` is the
durable, tenant-scoped source of truth.  Helpers in this module never commit;
the caller owns the transaction so an inbound message and its workspace update
cannot be partially applied.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

_SCHEMA_READY_FOR = None


def ensure_schema(db, schema_key=None):
    global _SCHEMA_READY_FOR
    if schema_key and _SCHEMA_READY_FOR == schema_key:
        return
    db.execute("SELECT pg_advisory_xact_lock(817405205)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS platform_alerts (
            id UUID PRIMARY KEY,
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            lead_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL DEFAULT '',
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            dedupe_key TEXT NOT NULL,
            read_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(organization_id, dedupe_key))
    """)
    db.execute("CREATE INDEX IF NOT EXISTS platform_alerts_org_created_idx ON platform_alerts(organization_id,created_at DESC)")
    if schema_key:
        _SCHEMA_READY_FOR = schema_key


def _iso(value):
    if isinstance(value, datetime):
        value = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    return str(value or datetime.now(timezone.utc).isoformat())[:64]


def _phone_digits(value):
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    # Workspaces created before the official integration may contain a
    # Brazilian number with DDD but without the E.164 country prefix.
    if len(digits) in {10, 11}:
        digits = "55" + digits
    return digits


def _pause_on_reply(workspace, lead):
    if str(lead.get("board") or "") == "Pós-venda":
        return True
    columns = workspace.get("columns") or []
    column = next((item for item in columns if isinstance(item, dict)
                   and str(item.get("id")) == str(lead.get("stage"))), {})
    automations = column.get("automations") if isinstance(column.get("automations"), dict) else {}
    return automations.get("pauseOnReply", True) is not False


def persist_alert(db, organization_id, workspace, *, dedupe_key, lead_id, kind,
                  title, body="", at=None, payload=None):
    """Persist one alert and mirror it into the bounded workspace inbox."""
    alert_id = uuid.uuid4()
    row = db.execute("""
        INSERT INTO platform_alerts(
            id,organization_id,lead_id,kind,title,body,payload,dedupe_key,created_at)
        VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
        ON CONFLICT(organization_id,dedupe_key) DO NOTHING
        RETURNING id
    """, (alert_id, organization_id, str(lead_id)[:128], str(kind)[:40],
          str(title)[:200], str(body)[:2000],
          json.dumps(payload or {}, ensure_ascii=False), str(dedupe_key)[:300],
          at or datetime.now(timezone.utc))).fetchone()
    if not row:
        return False
    notifications = workspace.setdefault("notifications", [])
    notifications.insert(0, {
        "id": str(alert_id),
        "eventId": str(dedupe_key)[:300],
        "leadId": str(lead_id)[:128],
        "type": str(kind)[:40],
        "text": str(title)[:300],
        "detail": str(body)[:1000],
        "at": _iso(at),
    })
    workspace["notifications"] = notifications[:1000]
    return True


def apply_inbound_response(workspace, *, message_id, phone, name, body,
                           occurred_at):
    """Apply an already authenticated individual reply to one tenant state.

    No outbound action is created here.  The cadence is paused before any
    future scheduler pass, and repeated webhook deliveries are idempotent.
    """
    leads = workspace.setdefault("leads", [])
    normalized_phone = _phone_digits(phone)
    lead = next((item for item in leads if isinstance(item, dict)
                 and _phone_digits(item.get("phone")) == normalized_phone), None)
    if lead is None:
        lead = {
            "id": str(uuid.uuid4()),
            "name": str(name or phone)[:160],
            "phone": normalized_phone,
            "origin": "WhatsApp",
            "interest": "Média",
            "board": "Principal",
            "stage": "new",
            "entered": int((occurred_at or datetime.now(timezone.utc)).timestamp() * 1000),
            "messages": [],
            "calls": [],
            "notes": "",
            "consentConfirmed": False,
        }
        leads.append(lead)
    if str(lead.get("lastReplyId") or "") == str(message_id):
        return lead, False
    current_reply_at = lead.get("lastReplyAt")
    try:
        current_reply_at = datetime.fromisoformat(
            str(current_reply_at).replace("Z", "+00:00"))
        if current_reply_at.tzinfo is None:
            current_reply_at = current_reply_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        current_reply_at = None
    inbound_at = occurred_at if isinstance(occurred_at, datetime) else None
    if inbound_at is not None and inbound_at.tzinfo is None:
        inbound_at = inbound_at.replace(tzinfo=timezone.utc)
    if current_reply_at is not None and inbound_at is not None and inbound_at < current_reply_at:
        return lead, False
    at = _iso(occurred_at)
    pause_automation = _pause_on_reply(workspace, lead)
    if pause_automation:
        lead["automationPaused"] = True
    lead["lastReplyId"] = str(message_id)[:300]
    lead["lastReplyAt"] = at
    lead["lastContactAt"] = at
    lead["last"] = str(body or "Nova mensagem recebida")[:1000]
    for approval in workspace.get("manualApprovals", []) if pause_automation else []:
        if (isinstance(approval, dict)
                and str(approval.get("leadId") or "") == str(lead.get("id"))
                and approval.get("status") in {"pending", "reviewing"}
                and approval.get("kind") != "appointment"):
            approval["status"] = "superseded"
            approval["supersededAt"] = at
            approval["supersededReason"] = "reply_received"
    return lead, True
