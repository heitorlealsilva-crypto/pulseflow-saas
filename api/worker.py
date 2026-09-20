"""Durable scheduler for tenant follow-up actions.

The worker never sends a message. It materializes due work in a persistent
queue and mirrors each item into the tenant review inbox. A seller still has
to review and authorize every outbound message.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler

from api.auth import connect, ensure_schema

MAX_TENANTS_PER_RUN = 100


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    if isinstance(value, (int, float)):
        # Workspace timestamps are milliseconds, but tolerate Unix seconds.
        return float(value) / (1000 if abs(float(value)) > 10_000_000_000 else 1)
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def can_contact(lead):
    return bool(lead and not lead.get("optOut") and lead.get("stage") != "closed"
                and lead.get("board") != "Pós-venda")


def call_recorded(lead, now_ts):
    cancelled = {"agendada", "cancelada", "scheduled", "planned", "cancelled"}
    for call in lead.get("calls") or []:
        at = timestamp(call.get("at")) if isinstance(call, dict) else None
        if (isinstance(call, dict) and call.get("id") and call.get("outcome")
                and str(call["outcome"]).strip().lower() not in cancelled
                and at is not None and at <= now_ts):
            return True
    return False


def followup_text(workspace, lead):
    name = str(lead.get("name") or "Contato").split()[0]
    if lead.get("discardReason"):
        return (f"{name}, quando conversamos, você mencionou {lead['discardReason']}. "
                "Esse cenário mudou ou prefere retomar em outro momento?")
    return (f"{name}, ficou alguma dúvida sobre "
            f"{lead.get('product') or 'o que conversamos'}? "
            "Posso ajudar a definir o próximo passo.")


def _action(key, lead, title, summary, due_at, text="", rule_id=None, kind="review"):
    return {
        "dedupe_key": key,
        "lead_id": str(lead.get("id") or ""),
        "lead_name": str(lead.get("name") or "Contato")[:160],
        "rule_id": rule_id,
        "kind": kind,
        "title": title[:200],
        "summary": summary[:1000],
        "text": text[:4000],
        "due_at": datetime.fromtimestamp(due_at, timezone.utc),
    }


def collect_due_actions(workspace, now=None):
    """Return deterministic, idempotent actions due at ``now``."""
    now = now or utcnow()
    now_ts = now.timestamp()
    actions = []
    leads = [lead for lead in workspace.get("leads", []) if isinstance(lead, dict) and lead.get("id")]
    existing_runs = {str(run.get("key")) for run in workspace.get("automationRuns", [])
                     if isinstance(run, dict) and run.get("key")}

    # Explicit appointments, recovery and cadences work even without an AI model.
    for lead in leads:
        if not can_contact(lead) or lead.get("automationPaused"):
            continue
        lead_id = str(lead["id"])
        next_at = timestamp(lead.get("nextDate"))
        if next_at is not None and next_at <= now_ts:
            action_name = str(lead.get("nextAction") or "Acompanhamento")
            actions.append(_action(
                f"schedule:{lead_id}:{int(next_at)}", lead,
                f"{action_name} agendada", "Revise o contexto e conclua a próxima ação.",
                next_at, kind="appointment"))
            continue

        if lead.get("board") == "Abandonados":
            recovery_at = timestamp(lead.get("recoveryAt"))
            if lead.get("discardReason") and recovery_at is not None and recovery_at <= now_ts:
                actions.append(_action(
                    f"recovery:{lead_id}:{int(recovery_at)}", lead,
                    "Revisar recuperação", str(lead["discardReason"]), recovery_at,
                    followup_text(workspace, lead), kind="recovery"))
            continue

        if not call_recorded(lead, now_ts):
            entered = timestamp(lead.get("entered")) or now_ts
            if entered <= now_ts:
                actions.append(_action(
                    f"call-first:{lead_id}:{int(entered)}", lead,
                    "Primeiro contato por ligação",
                    "Registre uma tentativa de ligação antes de preparar qualquer mensagem.",
                    entered, kind="call"))
            continue

        if lead.get("cadenceEnabled"):
            cadence = workspace.get("cadence") or []
            index = max(0, int(lead.get("cadenceIndex") or 0))
            if index < len(cadence) and isinstance(cadence[index], dict):
                step = cadence[index]
                start = timestamp(lead.get("cadenceStarted")) or timestamp(lead.get("entered"))
                factor = 86400 if re.search("dia", str(step.get("unit") or ""), re.I) else 3600
                due = (start or now_ts) + max(0, float(step.get("delay") or 0)) * factor
                if due <= now_ts:
                    text = str(step.get("text") or "").replace("{nome}", str(lead.get("name") or "Contato").split()[0])
                    is_call = str(step.get("action") or "").lower() in {"ligar", "ligação", "ligacao"}
                    actions.append(_action(
                        f"cadence:{lead_id}:{index}:{int(due)}", lead,
                        f"Cadência · etapa {index + 1}",
                        "Faça a ligação e registre o resultado." if is_call else "Revise a mensagem antes de autorizar o envio.",
                        due, "" if is_call else text, kind="call" if is_call else "cadence"))

    # AI automation rules prepare reviews only while the tenant agent is active.
    if (workspace.get("ai") or {}).get("enabled"):
        day = now.date().isoformat()
        columns = {str(c.get("id")): c for c in workspace.get("columns", []) if isinstance(c, dict)}
        for rule in workspace.get("automations") or []:
            if not isinstance(rule, dict) or not rule.get("enabled"):
                continue
            trigger = rule.get("trigger")
            if trigger not in {"stage_timeout", "inactive_lead"}:
                continue
            for lead in leads:
                if not can_contact(lead) or lead.get("automationPaused"):
                    continue
                board = rule.get("board")
                if board and board != "Todos" and board != lead.get("board"):
                    continue
                base = timestamp(lead.get("entered")) or now_ts
                if trigger == "stage_timeout":
                    column = columns.get(str(lead.get("stage"))) or {}
                    hours = float(rule.get("delay") or column.get("limit") or 24)
                    due = base + max(0, hours) * 3600
                else:
                    base = timestamp(lead.get("lastContactAt")) or base
                    due = base + max(0, float(rule.get("delay") or 720)) * 3600
                if due > now_ts:
                    continue
                run_key = f"{rule.get('id')}:{lead.get('id')}:{day}"
                if run_key in existing_runs:
                    continue
                actions.append(_action(
                    run_key, lead, str(rule.get("name") or "Automação"),
                    str(rule.get("instructions") or "Revise o contexto e decida o próximo passo."),
                    due, followup_text(workspace, lead) if rule.get("action") == "prepare_followup" else "",
                    str(rule.get("id") or ""), "automation"))
    return actions


def ensure_worker_schema(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS scheduled_actions (
            id UUID PRIMARY KEY,
            organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
            dedupe_key TEXT NOT NULL,
            lead_id TEXT NOT NULL,
            automation_id TEXT,
            kind TEXT NOT NULL,
            payload JSONB NOT NULL DEFAULT '{}'::jsonb,
            due_at TIMESTAMPTZ NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending_approval',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE(organization_id, dedupe_key))
    """)
    db.execute("CREATE INDEX IF NOT EXISTS scheduled_actions_due_idx ON scheduled_actions(status, due_at)")
    db.execute("""
        CREATE TABLE IF NOT EXISTS worker_runs (
            id BIGSERIAL PRIMARY KEY, started_at TIMESTAMPTZ NOT NULL,
            finished_at TIMESTAMPTZ, tenants_scanned INTEGER NOT NULL DEFAULT 0,
            actions_created INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL,
            error_code TEXT)
    """)


def materialize_action(db, organization_id, workspace, action, now):
    job_id = uuid.uuid4()
    row = db.execute("""
        INSERT INTO scheduled_actions(
            id,organization_id,dedupe_key,lead_id,automation_id,kind,payload,due_at)
        VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
        ON CONFLICT(organization_id,dedupe_key) DO NOTHING
        RETURNING id
    """, (job_id, organization_id, action["dedupe_key"], action["lead_id"],
          action.get("rule_id"), action["kind"], json.dumps({
              "leadName": action["lead_name"], "title": action["title"],
              "summary": action["summary"], "text": action["text"]
          }, ensure_ascii=False), action["due_at"])).fetchone()
    if not row:
        return False

    approvals = workspace.setdefault("manualApprovals", [])
    approvals.insert(0, {
        "id": str(job_id), "jobId": str(job_id), "ruleId": action.get("rule_id"),
        "dedupeKey": action["dedupe_key"],
        "leadId": action["lead_id"], "leadName": action["lead_name"],
        "status": "pending", "createdAt": now.isoformat(),
        "dueAt": action["due_at"].isoformat(), "kind": action["kind"],
        "title": action["title"], "summary": action["summary"], "text": action["text"],
    })
    workspace["manualApprovals"] = approvals[:2000]
    if action.get("rule_id"):
        runs = workspace.setdefault("automationRuns", [])
        runs.append({"key": action["dedupe_key"], "ruleId": action["rule_id"],
                     "leadId": action["lead_id"], "at": now.isoformat()})
        workspace["automationRuns"] = runs[-1000:]
    return True


def run_batch(db, now=None, limit=MAX_TENANTS_PER_RUN):
    now = now or utcnow()
    ensure_schema(db)
    ensure_worker_schema(db)
    run = db.execute("INSERT INTO worker_runs(started_at,status) VALUES(%s,'running') RETURNING id", (now,)).fetchone()
    run_id = run["id"]
    scanned = created = 0
    try:
        rows = db.execute("""
            SELECT organization_id,state,revision FROM tenant_workspaces
            ORDER BY updated_at ASC LIMIT %s FOR UPDATE SKIP LOCKED
        """, (max(1, min(int(limit), 500)),)).fetchall()
        for row in rows:
            scanned += 1
            workspace = row.get("state") if isinstance(row.get("state"), dict) else {}
            tenant_created = 0
            for action in collect_due_actions(workspace, now):
                if materialize_action(db, row["organization_id"], workspace, action, now):
                    tenant_created += 1
            if tenant_created:
                db.execute("""
                    UPDATE tenant_workspaces SET state=%s::jsonb,revision=revision+1,updated_at=NOW()
                    WHERE organization_id=%s
                """, (json.dumps(workspace, ensure_ascii=False), row["organization_id"]))
                created += tenant_created
        db.execute("""
            UPDATE worker_runs SET finished_at=NOW(),tenants_scanned=%s,actions_created=%s,status='completed'
            WHERE id=%s
        """, (scanned, created, run_id))
        db.commit()
        return {"ok": True, "tenantsScanned": scanned, "actionsCreated": created}
    except Exception:
        db.rollback()
        # Keep production responses free of database/contact details.
        try:
            ensure_worker_schema(db)
            db.execute("""
                INSERT INTO worker_runs(started_at,finished_at,tenants_scanned,actions_created,status,error_code)
                VALUES(%s,NOW(),%s,%s,'failed','worker_failed')
            """, (now, scanned, created))
            db.commit()
        except Exception:
            db.rollback()
        raise


def authorized(headers):
    secret = os.getenv("CRON_SECRET", "")
    if len(secret) < 16:
        return False
    supplied = headers.get("Authorization", "")
    expected = "Bearer " + secret
    return hmac.compare_digest(supplied.encode(), expected.encode())


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def reply(self, status, value):
        raw = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not authorized(self.headers):
            return self.reply(401, {"ok": False, "error": "agendador não autorizado"})
        try:
            with connect() as db:
                return self.reply(200, run_batch(db))
        except Exception:
            return self.reply(503, {"ok": False, "error": "agendador temporariamente indisponível"})

    def do_POST(self):
        return self.do_GET()
