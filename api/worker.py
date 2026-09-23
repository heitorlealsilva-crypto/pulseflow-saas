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
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler

from api import ai as ai_service
from api import integration_events
from api.auth import connect, ensure_schema
from api.runtime import ensure_schema as ensure_runtime_schema, persist_alert

MAX_TENANTS_PER_RUN = 100
MAX_AI_ANALYSES_PER_RUN = 2
MAX_AI_JOBS_PER_TENANT = 10
MAX_PENDING_AI_JOBS_PER_TENANT = 50


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    if isinstance(value, datetime):
        value = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return value.timestamp()
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
    return bool(lead and not lead.get("optOut") and not lead.get("doNotContact")
                and lead.get("stage") != "closed" and not ai_service.is_post_sale(lead))


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


def _action(key, lead, title, summary, due_at, text="", rule_id=None, kind="review",
            requires_approval=True):
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
        "requires_approval": requires_approval,
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
        if lead.get("optOut") or lead.get("doNotContact") or lead.get("stage") == "closed":
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

        if not can_contact(lead) or lead.get("automationPaused"):
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

    # Column-specific cadences are independent of the legacy global cadence.
    for lead in leads:
        if lead.get("board") == "Abandonados":
            continue
        column = ai_service.column_for_lead(workspace, lead)
        config = column.get("automations") if isinstance(column.get("automations"), dict) else {}
        if not config.get("enabled"):
            continue
        for index, step in enumerate(config.get("cadence") or []):
            if not isinstance(step, dict):
                continue
            trigger = str(step.get("trigger") or "entry")
            if trigger == "reply":
                anchor = timestamp(lead.get("lastReplyAt"))
                entered = timestamp(lead.get("entered"))
                if anchor is not None and entered is not None and anchor < entered:
                    anchor = None
            else:
                anchor = timestamp(lead.get("entered"))
                if trigger == "deadline" and anchor is not None:
                    try:
                        limit_hours = max(0, float(column.get("limit") or 0))
                        anchor = anchor + limit_hours * 3600 if limit_hours else None
                    except (TypeError, ValueError):
                        anchor = None
            if anchor is None:
                continue
            factor = 86400 if re.search("dia", str(step.get("unit") or ""), re.I) else 3600
            try:
                due = anchor + max(0, float(step.get("delay") or 0)) * factor
            except (TypeError, ValueError):
                continue
            if due > now_ts:
                continue
            action_type = str(step.get("action") or "notify").lower()
            post_sale = ai_service.is_post_sale(lead)
            if post_sale and action_type not in {"notify", "observe"}:
                continue
            if action_type in {"message", "call"}:
                # A reply-specific rule may prepare a review after pausing the
                # ordinary cadence. It still never sends anything itself.
                if not can_contact(lead) or (lead.get("automationPaused") and trigger != "reply"):
                    continue
            step_id = str(step.get("id") or index)[:100]
            key = f"column:{lead.get('board')}:{column.get('id')}:{step_id}:{lead.get('id')}:{int(anchor)}"
            text = str(step.get("text") or "").replace(
                "{nome}", str(lead.get("name") or "Contato").split()[0]).replace(
                "{produto}", str(lead.get("product") or "o que conversamos"))
            if action_type == "message":
                if config.get("callFirst", True) and not call_recorded(lead, now_ts):
                    entered = timestamp(lead.get("entered")) or due
                    actions.append(_action(
                        f"call-first:{lead.get('id')}:{int(entered)}", lead,
                        f"{column.get('name') or 'Etapa'} · ligação primeiro",
                        "Registre a tentativa de ligação antes de revisar a mensagem desta etapa.",
                        due, "", step_id, "call"))
                    continue
                actions.append(_action(
                    key, lead, f"{column.get('name') or 'Etapa'} · mensagem",
                    "Revise o contexto e autorize somente se ainda fizer sentido.", due,
                    text, step_id, "column_cadence"))
            elif action_type == "call":
                actions.append(_action(
                    key, lead, f"{column.get('name') or 'Etapa'} · ligação",
                    "Faça a ligação e registre o resultado antes de qualquer mensagem.", due,
                    "", step_id, "call"))
            else:
                actions.append(_action(
                    key, lead, f"Revisar {lead.get('name') or 'contato'}",
                    text or "A etapa chegou ao momento configurado para observação.", due,
                    "", step_id, "column_observation", requires_approval=False))

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
    # Global and per-column rules can point to the same required first call.
    # Keep the first deterministic action so the seller never sees duplicates.
    unique = {}
    for action in actions:
        unique.setdefault(action["dedupe_key"], action)
    return list(unique.values())


def ensure_worker_schema(db):
    db.execute("ALTER TABLE tenant_workspaces ADD COLUMN IF NOT EXISTS last_worker_at TIMESTAMPTZ")
    db.execute("ALTER TABLE tenant_workspaces ADD COLUMN IF NOT EXISTS last_ai_worker_at TIMESTAMPTZ")
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
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS ai_jobs_queued INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS ai_analyses_completed INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS ai_analyses_failed INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS webhook_deliveries_claimed INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS webhook_deliveries_delivered INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS webhook_deliveries_retried INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS webhook_deliveries_dead INTEGER NOT NULL DEFAULT 0")
    db.execute("ALTER TABLE worker_runs ADD COLUMN IF NOT EXISTS webhook_endpoints_paused INTEGER NOT NULL DEFAULT 0")


def materialize_action(db, organization_id, workspace, action, now):
    job_id = uuid.uuid4()
    # A visible browser can prepare the same deterministic action before the
    # background worker reaches it. Adopt that workspace item into the durable
    # queue instead of showing it to the seller twice.
    already_approved = any(
        isinstance(item, dict) and item.get("dedupeKey") == action["dedupe_key"]
        for item in workspace.get("manualApprovals", []))
    alert_key = f"scheduled:{action['dedupe_key']}"
    already_notified = any(
        isinstance(item, dict) and item.get("eventId") == alert_key
        for item in workspace.get("notifications", []))
    status = ("pending_approval" if already_approved else "notified"
              if already_notified or not action.get("requires_approval", True)
              else "pending_approval")
    row = db.execute("""
        INSERT INTO scheduled_actions(
            id,organization_id,dedupe_key,lead_id,automation_id,kind,payload,due_at,status)
        VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb,%s,%s)
        ON CONFLICT(organization_id,dedupe_key) DO NOTHING
        RETURNING id
    """, (job_id, organization_id, action["dedupe_key"], action["lead_id"],
          action.get("rule_id"), action["kind"], json.dumps({
              "leadName": action["lead_name"], "title": action["title"],
              "summary": action["summary"], "text": action["text"]
          }, ensure_ascii=False), action["due_at"], status)).fetchone()
    if not row:
        return False

    if already_approved or already_notified:
        return True

    if not action.get("requires_approval", True):
        persist_alert(
            db, organization_id, workspace,
            dedupe_key=f"scheduled:{action['dedupe_key']}", lead_id=action["lead_id"],
            kind=action["kind"], title=action["title"], body=action["summary"],
            at=action["due_at"], payload={"scheduledActionId": str(job_id)})
        return True

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


def _lead_priority(lead):
    value = timestamp(lead.get("lastReplyAt")) or timestamp(lead.get("lastContactAt"))
    return value or timestamp(lead.get("entered")) or 0


def queue_ai_observations(db, organization_id, workspace, now,
                          limit=MAX_AI_JOBS_PER_TENANT):
    """Queue bounded, fingerprinted observations without calling the provider."""
    if not os.getenv("OPENAI_API_KEY", "").strip() or not (workspace.get("ai") or {}).get("enabled"):
        return 0
    pending = db.execute("""SELECT COUNT(*)::int AS count FROM ai_observation_jobs
        WHERE organization_id=%s AND status IN ('pending','retry','running')""",
        (organization_id,)).fetchone()
    room = max(0, MAX_PENDING_AI_JOBS_PER_TENANT - int((pending or {}).get("count") or 0))
    if not room:
        return 0
    rows = db.execute("""SELECT DISTINCT ON (lead_id) lead_id,status,source_meta,created_at
        FROM ai_observation_jobs WHERE organization_id=%s
        ORDER BY lead_id,created_at DESC""", (organization_id,)).fetchall()
    previous_by_lead = {str(row["lead_id"]): row for row in rows}
    leads = [lead for lead in workspace.get("leads", [])
             if isinstance(lead, dict) and lead.get("id")
             and not lead.get("optOut") and not lead.get("doNotContact")
             and not (lead.get("stage") == "closed" and not ai_service.is_post_sale(lead))
             and ai_service.observation_policy(workspace, lead)["enabled"]]
    # Oldest/never-observed leads come first. A handful of noisy contacts can
    # no longer monopolize the per-run observation budget.
    leads.sort(key=lambda lead: (
        timestamp((previous_by_lead.get(str(lead["id"])) or {}).get("created_at")) or 0,
        -_lead_priority(lead)))
    queued = 0
    for lead in leads:
        if queued >= min(max(1, int(limit)), room):
            break
        policy = ai_service.observation_policy(workspace, lead)
        lead_id = str(lead["id"])
        source_meta = ai_service.observation_source_meta(workspace, lead)
        trigger = ai_service.classify_observation(
            (previous_by_lead.get(lead_id) or {}).get("source_meta") or {},
            source_meta, policy, lead, now)
        if not trigger:
            continue
        context = ai_service.build_context(
            db, organization_id, workspace, lead, trigger, policy["column"])
        input_hash = ai_service.context_hash(context)
        row = db.execute("""INSERT INTO ai_observation_jobs(
                id,organization_id,lead_id,trigger,input_hash,source_meta)
            VALUES(%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT(organization_id,lead_id,trigger,input_hash) DO NOTHING
            RETURNING id""", (uuid.uuid4(), organization_id, lead_id, trigger,
                               input_hash, json.dumps(source_meta))).fetchone()
        if row:
            queued += 1
            previous_by_lead[lead_id] = {"source_meta": source_meta, "created_at": now}
    return queued


def reserve_continuous_usage(db, organization_id, plan, today):
    return db.execute("""INSERT INTO ai_usage_daily(
            organization_id,usage_date,requests,continuous_requests)
        VALUES(%s,%s,1,1)
        ON CONFLICT(organization_id,usage_date) DO UPDATE SET
            requests=ai_usage_daily.requests+1,
            continuous_requests=ai_usage_daily.continuous_requests+1,
            updated_at=NOW()
        WHERE ai_usage_daily.requests < %s
          AND ai_usage_daily.continuous_requests < %s
        RETURNING requests,continuous_requests""",
        (organization_id, today, ai_service.plan_limit(plan),
         ai_service.continuous_limit(plan))).fetchone()


def claim_ai_job(db, now):
    # A function timeout must not leave a job permanently locked in "running".
    db.execute("""UPDATE ai_observation_jobs SET status='retry',not_before=%s,
        error_code='worker_interrupted',updated_at=NOW()
        WHERE status='running' AND updated_at < %s""",
        (now, now - timedelta(minutes=10)))
    row = db.execute("""SELECT j.* FROM ai_observation_jobs j
        JOIN organizations o ON o.id=j.organization_id
        JOIN tenant_workspaces w ON w.organization_id=j.organization_id
        WHERE j.status IN ('pending','retry') AND j.not_before<=%s
          AND o.status='active'
          AND COALESCE(o.permissions->'workspace_write','true'::jsonb)='true'::jsonb
        ORDER BY w.last_ai_worker_at ASC NULLS FIRST,
                 CASE j.trigger WHEN 'reply' THEN 0 WHEN 'context_changed' THEN 1
                 WHEN 'deadline' THEN 2 ELSE 3 END,j.created_at
        LIMIT 1 FOR UPDATE OF j,w SKIP LOCKED""", (now,)).fetchone()
    if not row:
        db.commit()
        return None
    db.execute("""UPDATE ai_observation_jobs SET status='running',attempts=attempts+1,
        error_code=NULL,updated_at=NOW() WHERE id=%s""", (row["id"],))
    db.execute("UPDATE tenant_workspaces SET last_ai_worker_at=%s WHERE organization_id=%s",
               (now, row["organization_id"]))
    row["attempts"] = int(row.get("attempts") or 0) + 1
    db.commit()
    return row


def finish_ai_job(db, job_id, status, error_code=None, not_before=None):
    db.execute("""UPDATE ai_observation_jobs SET status=%s,error_code=%s,
        not_before=COALESCE(%s,not_before),completed_at=CASE WHEN %s IN ('completed','skipped','failed')
            THEN NOW() ELSE completed_at END,updated_at=NOW() WHERE id=%s""",
        (status, error_code, not_before, status, job_id))
    db.commit()


def _retry_ai_job(db, job, error_code, now):
    if int(job.get("attempts") or 0) >= 3:
        finish_ai_job(db, job["id"], "failed", error_code)
        return "failed"
    delay = timedelta(minutes=min(60, 5 * (2 ** max(0, int(job.get("attempts") or 1) - 1))))
    finish_ai_job(db, job["id"], "retry", error_code, now + delay)
    return "retry"


def _approval_from_analysis(analysis_id, lead, result, job, now):
    action = result.get("recommended_next_action")
    labels = {
        "call": "Ligação recomendada pela IA",
        "message": "Mensagem sugerida pela IA",
        "meeting": "Reunião sugerida pela IA",
    }
    return {
        "id": analysis_id,
        "jobId": str(job["id"]),
        "leadId": str(lead.get("id")),
        "leadName": str(lead.get("name") or "Contato")[:160],
        "status": "pending",
        "createdAt": now.isoformat(),
        "kind": "ai_suggestion",
        "title": labels.get(action, "Próximo passo sugerido pela IA"),
        "summary": str(result.get("follow_up_reason") or result.get("summary") or "Revise o contexto.")[:1000],
        "text": str(result.get("suggested_message") or "")[:4000],
        "analysisId": analysis_id,
        "requiresSellerApproval": True,
    }


def process_ai_job(db, job, now):
    """Analyze one claimed job. Provider failures are isolated to this job."""
    account = db.execute("SELECT plan,status,permissions FROM organizations WHERE id=%s",
                         (job["organization_id"],)).fetchone()
    row = db.execute("SELECT state FROM tenant_workspaces WHERE organization_id=%s",
                     (job["organization_id"],)).fetchone()
    workspace = (row or {}).get("state") or {}
    lead = next((item for item in workspace.get("leads", [])
                 if str(item.get("id")) == str(job["lead_id"])), None)
    if (not account or account.get("status") != "active"
            or (account.get("permissions") or {}).get("workspace_write", True) is False
            or not lead):
        finish_ai_job(db, job["id"], "skipped", "source_unavailable")
        return "skipped"
    policy = ai_service.observation_policy(workspace, lead)
    if not policy["enabled"] or lead.get("optOut") or lead.get("doNotContact"):
        finish_ai_job(db, job["id"], "skipped", "observation_disabled")
        return "skipped"
    context = ai_service.build_context(
        db, job["organization_id"], workspace, lead, job["trigger"], policy["column"])
    if ai_service.context_hash(context) != job["input_hash"]:
        finish_ai_job(db, job["id"], "skipped", "stale_input")
        return "skipped"
    reserved = reserve_continuous_usage(db, job["organization_id"], account.get("plan") or "Base", now.date())
    if not reserved:
        tomorrow = datetime.combine(now.date() + timedelta(days=1), datetime.min.time(), tzinfo=timezone.utc)
        finish_ai_job(db, job["id"], "retry", "continuous_daily_limit", tomorrow)
        return "deferred"
    request_payload = ai_service.provider_request(
        context, job["organization_id"], f"worker:{job['lead_id']}")
    db.commit()
    try:
        response = ai_service.call_provider(request_payload)
        result = ai_service.enforce_safety(ai_service.extract_analysis(response), lead)
    except ai_service.AIError as error:
        return _retry_ai_job(db, job, error.code, now)

    # Revalidate after the network call; stale advice is never presented.
    current_row = db.execute("""SELECT state,revision FROM tenant_workspaces
        WHERE organization_id=%s FOR UPDATE""", (job["organization_id"],)).fetchone()
    current = (current_row or {}).get("state") or {}
    current_lead = next((item for item in current.get("leads", [])
                         if str(item.get("id")) == str(job["lead_id"])), None)
    if not current_lead:
        db.rollback()
        finish_ai_job(db, job["id"], "skipped", "lead_removed")
        return "skipped"
    current_policy = ai_service.observation_policy(current, current_lead)
    current_context = ai_service.build_context(
        db, job["organization_id"], current, current_lead, job["trigger"], current_policy["column"])
    if (not current_policy["enabled"] or ai_service.context_hash(current_context) != job["input_hash"]
            or current_lead.get("optOut") or current_lead.get("doNotContact")):
        db.rollback()
        finish_ai_job(db, job["id"], "skipped", "stale_input")
        return "skipped"
    result = ai_service.enforce_safety(result, current_lead)
    analysis_id = str(uuid.uuid4())
    usage = response.get("usage") or {}
    db.execute("""UPDATE ai_usage_daily SET input_tokens=input_tokens+%s,
        output_tokens=output_tokens+%s,updated_at=NOW()
        WHERE organization_id=%s AND usage_date=%s""",
        (int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0),
         job["organization_id"], now.date()))
    db.execute("""INSERT INTO ai_analyses(
            id,organization_id,lead_id,actor_user_id,model,result,input_hash,source,trigger)
        VALUES(%s,%s,%s,NULL,%s,%s::jsonb,%s,'continuous',%s)""",
        (analysis_id, job["organization_id"], str(current_lead["id"]),
         request_payload["model"], json.dumps(result, ensure_ascii=False),
         job["input_hash"], job["trigger"]))

    ai_config = current.get("ai") or {}
    if ai_config.get("learningEnabled"):
        try:
            retention_days = min(730, max(7, int(ai_config.get("memoryRetentionDays") or 180)))
        except (TypeError, ValueError):
            retention_days = 180
        cutoff = now - timedelta(days=retention_days)
        memories = []
        for memory in ai_config.get("memories", []):
            if not isinstance(memory, dict):
                continue
            memory_at = timestamp(memory.get("at"))
            if memory_at is not None and memory_at >= cutoff.timestamp():
                memories.append(memory)
        memories.append({
            "id": analysis_id,
            "leadId": str(current_lead["id"]),
            "leadName": str(current_lead.get("name") or "Contato")[:160],
            "summary": result.get("summary", ""),
            "signals": result.get("signals", []),
            "at": now.isoformat(),
            "source": "openai-continuous",
        })
        ai_config["memories"] = memories[-500:]
        ai_config["lastLearnedAt"] = now.isoformat()
        current["ai"] = ai_config

    action = result.get("recommended_next_action")
    if (current_policy["operator_enabled"] and not result.get("observation_only")
            and action in {"call", "message", "meeting"}):
        approvals = current.setdefault("manualApprovals", [])
        approvals.insert(0, _approval_from_analysis(analysis_id, current_lead, result, job, now))
        current["manualApprovals"] = approvals[:2000]

    if result.get("observation_only"):
        alert_title = f"IA observadora atualizou {str(current_lead.get('name') or 'o cliente')[:120]}"
    elif job["trigger"] == "reply":
        alert_title = f"Nova resposta analisada · {str(current_lead.get('name') or 'Contato')[:120]}"
    else:
        alert_title = f"Próximo passo sugerido · {str(current_lead.get('name') or 'Contato')[:120]}"
    persist_alert(
        db, job["organization_id"], current,
        dedupe_key=f"ai:{job['id']}", lead_id=current_lead["id"], kind="ai_analysis",
        title=alert_title, body=result.get("follow_up_reason") or result.get("summary") or "",
        at=now, payload={"analysisId": analysis_id, "trigger": job["trigger"],
                         "observationOnly": bool(result.get("observation_only"))})
    db.execute("""UPDATE tenant_workspaces SET state=%s::jsonb,revision=revision+1,updated_at=NOW()
        WHERE organization_id=%s""", (json.dumps(current, ensure_ascii=False), job["organization_id"]))
    db.execute("""INSERT INTO audit_logs(actor_user_id,organization_id,action,metadata)
        VALUES(NULL,%s,'ai.analysis.continuous',%s::jsonb)""",
        (job["organization_id"], json.dumps({"analysis_id": analysis_id,
          "lead_id": str(current_lead["id"]), "trigger": job["trigger"],
          "model": request_payload["model"]})))
    db.execute("""UPDATE ai_observation_jobs SET status='completed',completed_at=NOW(),
        error_code=NULL,updated_at=NOW() WHERE id=%s""", (job["id"],))
    db.commit()
    return "completed"


def process_ai_jobs(db, now, limit=MAX_AI_ANALYSES_PER_RUN):
    stats = {"completed": 0, "failed": 0, "deferred": 0, "skipped": 0}
    for _ in range(max(0, min(int(limit), 5))):
        job = claim_ai_job(db, now)
        if not job:
            break
        try:
            status = process_ai_job(db, job, now)
        except Exception:
            db.rollback()
            status = _retry_ai_job(db, job, "analysis_failed", now)
        if status == "retry":
            stats["failed"] += 1
        elif status in stats:
            stats[status] += 1
        elif status == "failed":
            stats["failed"] += 1
    return stats


def run_batch(db, now=None, limit=MAX_TENANTS_PER_RUN):
    now = now or utcnow()
    ensure_schema(db)
    ensure_worker_schema(db)
    ai_service.ensure_schema(db)
    ensure_runtime_schema(db, os.getenv("DATABASE_URL") or os.getenv("STORAGE_URL"))
    db.commit()
    scheduler_lock = db.execute(
        "SELECT pg_try_advisory_lock(817405207) AS acquired").fetchone()
    if not scheduler_lock or not scheduler_lock.get("acquired"):
        db.rollback()
        return {"ok": True, "alreadyRunning": True, "tenantsScanned": 0,
                "actionsCreated": 0, "aiJobsQueued": 0,
                "aiAnalysesCompleted": 0, "aiAnalysesFailed": 0,
                "aiAnalysesDeferred": 0, "webhookDeliveriesClaimed": 0,
                "webhookDeliveriesDelivered": 0, "webhookDeliveriesRetried": 0,
                "webhookDeliveriesDead": 0, "webhookEndpointsPaused": 0}
    run = db.execute("INSERT INTO worker_runs(started_at,status) VALUES(%s,'running') RETURNING id", (now,)).fetchone()
    run_id = run["id"]
    db.commit()
    scanned = created = queued = 0
    try:
        # Bounded retention keeps the scheduler tables from growing forever.
        db.execute("""DELETE FROM ai_observation_jobs WHERE id IN (
            SELECT id FROM ai_observation_jobs
            WHERE status IN ('completed','skipped','failed') AND updated_at < %s
            ORDER BY updated_at LIMIT 1000)""", (now - timedelta(days=90),))
        db.execute("""DELETE FROM platform_alerts WHERE id IN (
            SELECT id FROM platform_alerts
            WHERE (read_at IS NOT NULL AND created_at < %s) OR created_at < %s
            ORDER BY created_at LIMIT 1000)""",
            (now - timedelta(days=90), now - timedelta(days=365)))
        db.execute("DELETE FROM worker_runs WHERE finished_at < %s",
                   (now - timedelta(days=180),))
        db.commit()
        candidates = db.execute("""
            SELECT w.organization_id FROM tenant_workspaces w
            JOIN organizations o ON o.id=w.organization_id
            WHERE o.status='active'
              AND COALESCE(o.permissions->'workspace_write','true'::jsonb)='true'::jsonb
            ORDER BY w.last_worker_at ASC NULLS FIRST,w.updated_at ASC
            LIMIT %s
        """, (max(1, min(int(limit), 500)),)).fetchall()
        db.commit()
        for candidate in candidates:
            row = db.execute("""SELECT w.organization_id,w.state,w.revision,w.last_worker_at
                FROM tenant_workspaces w JOIN organizations o ON o.id=w.organization_id
                WHERE w.organization_id=%s AND o.status='active'
                  AND COALESCE(o.permissions->'workspace_write','true'::jsonb)='true'::jsonb
                FOR UPDATE OF w SKIP LOCKED""",
                (candidate["organization_id"],)).fetchone()
            if not row:
                db.rollback()
                continue
            scanned += 1
            workspace = row.get("state") if isinstance(row.get("state"), dict) else {}
            ai_config = workspace.get("ai") if isinstance(workspace.get("ai"), dict) else {}
            try:
                retention_days = min(730, max(7, int(ai_config.get("memoryRetentionDays") or 180)))
            except (TypeError, ValueError):
                retention_days = 180
            db.execute("""DELETE FROM ai_analyses WHERE organization_id=%s
                AND created_at < %s""",
                (row["organization_id"], now - timedelta(days=retention_days)))
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
            queued += queue_ai_observations(db, row["organization_id"], workspace, now)
            db.execute("UPDATE tenant_workspaces SET last_worker_at=%s WHERE organization_id=%s",
                       (now, row["organization_id"]))
            # Release this tenant before moving to the next one so normal saves
            # and webhooks are not blocked by the whole batch.
            db.commit()
        db.execute("""UPDATE worker_runs SET tenants_scanned=%s,actions_created=%s,
            ai_jobs_queued=%s WHERE id=%s""", (scanned, created, queued, run_id))
        db.commit()
        # Tenant workspace rows have all been committed at this point.  Webhook
        # delivery performs customer-controlled network I/O, so it must never
        # run while a workspace row lock is held.
        webhook_stats = integration_events.process_deliveries(db, limit=20)
        integration_events.cleanup_history(db, now, limit=500)
        ai_stats = process_ai_jobs(db, now, MAX_AI_ANALYSES_PER_RUN)
        db.execute("""
            UPDATE worker_runs SET finished_at=NOW(),tenants_scanned=%s,actions_created=%s,
                ai_jobs_queued=%s,ai_analyses_completed=%s,ai_analyses_failed=%s,
                webhook_deliveries_claimed=%s,webhook_deliveries_delivered=%s,
                webhook_deliveries_retried=%s,webhook_deliveries_dead=%s,
                webhook_endpoints_paused=%s,status='completed'
            WHERE id=%s
        """, (scanned, created, queued, ai_stats["completed"], ai_stats["failed"],
              webhook_stats["claimed"], webhook_stats["delivered"],
              webhook_stats["retry"], webhook_stats["dead"],
              webhook_stats["paused"], run_id))
        db.commit()
        return {"ok": True, "tenantsScanned": scanned, "actionsCreated": created,
                "aiJobsQueued": queued, "aiAnalysesCompleted": ai_stats["completed"],
                "aiAnalysesFailed": ai_stats["failed"], "aiAnalysesDeferred": ai_stats["deferred"],
                "webhookDeliveriesClaimed": webhook_stats["claimed"],
                "webhookDeliveriesDelivered": webhook_stats["delivered"],
                "webhookDeliveriesRetried": webhook_stats["retry"],
                "webhookDeliveriesDead": webhook_stats["dead"],
                "webhookEndpointsPaused": webhook_stats["paused"]}
    except Exception:
        db.rollback()
        # Keep production responses free of database/contact details.
        try:
            ensure_worker_schema(db)
            db.execute("""UPDATE worker_runs SET finished_at=NOW(),tenants_scanned=%s,
                actions_created=%s,ai_jobs_queued=%s,status='failed',error_code='worker_failed'
                WHERE id=%s""", (scanned, created, queued, run_id))
            db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        try:
            db.execute("SELECT pg_advisory_unlock(817405207)")
            db.commit()
        except Exception:
            db.rollback()


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
