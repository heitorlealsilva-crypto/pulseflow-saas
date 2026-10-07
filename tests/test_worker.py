import json
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

try:
    import psycopg  # noqa: F401
except ImportError:
    stub = types.ModuleType("psycopg")
    stub.errors = types.SimpleNamespace(
        UniqueViolation=type("UniqueViolation", (Exception,), {}))
    stub.rows = types.ModuleType("psycopg.rows")
    stub.rows.dict_row = None
    sys.modules["psycopg"] = stub
    sys.modules["psycopg.rows"] = stub.rows

from api import worker


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 19, 12, 0, tzinfo=timezone.utc)
        self.past = (self.now - timedelta(hours=3)).isoformat()
        self.call = {"id": "call-1", "at": self.past, "outcome": "Não atendeu"}

    def workspace(self, lead):
        return {
            "leads": [lead],
            "columns": [{"id": "new", "limit": 1}],
            "cadence": [{"delay": 2, "unit": "horas", "text": "Oi, {nome}!"}],
            "automations": [],
            "ai": {"enabled": False},
        }

    def lead(self, **extra):
        value = {
            "id": "lead-1", "name": "Ana Silva", "board": "Principal",
            "stage": "new", "entered": self.past, "messages": [], "calls": [],
        }
        value.update(extra)
        return value

    def test_first_action_is_call_and_never_message(self):
        actions = worker.collect_due_actions(self.workspace(self.lead()), self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "call")
        self.assertEqual(actions[0]["text"], "")

    def test_due_cadence_creates_review_with_context(self):
        lead = self.lead(calls=[self.call], cadenceEnabled=True,
                         cadenceStarted=self.past, cadenceIndex=0)
        actions = worker.collect_due_actions(self.workspace(lead), self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "cadence")
        self.assertEqual(actions[0]["text"], "Oi, Ana!")
        self.assertIn("cadence:lead-1:0", actions[0]["dedupe_key"])

    def test_inactive_principal_lead_is_reviewed_without_ai(self):
        last_contact = (self.now - timedelta(days=31)).isoformat()
        lead = self.lead(calls=[self.call], lastContactAt=last_contact)
        workspace = self.workspace(lead)
        workspace["settings"] = {"inactiveDays": 30}
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action["kind"], "followup")
        self.assertEqual(action["title"], "Retomar contato")
        self.assertEqual(action["dedupe_key"],
                         f"task:lead-1:Retomar contato:{int((self.now - timedelta(days=1)).timestamp())}")
        self.assertTrue(action["requires_approval"])

    def test_inactive_reminder_respects_recent_contact_board_pause_and_cadence(self):
        old = (self.now - timedelta(days=31)).isoformat()
        due_cadence = {"delay": 40, "unit": "dias", "text": "Aguarde a etapa"}
        cases = [
            self.lead(calls=[self.call], lastContactAt=self.past),
            self.lead(calls=[self.call], lastContactAt=old, board="Remarketing"),
            self.lead(calls=[self.call], lastContactAt=old, board="Abandonados"),
            self.lead(calls=[self.call], lastContactAt=old, automationPaused=True),
            self.lead(calls=[self.call], lastContactAt=old, opt_out=True),
            self.lead(calls=[self.call], lastContactAt=old, cadenceEnabled=True,
                      cadenceStarted=old, cadenceIndex=0),
        ]
        for lead in cases:
            with self.subTest(lead=lead):
                workspace = self.workspace(lead)
                workspace["settings"] = {"inactiveDays": 30}
                workspace["cadence"] = [due_cadence]
                workspace["columns"][0]["limit"] = 0
                self.assertEqual(worker.collect_due_actions(workspace, self.now), [])

    def test_waiting_deadline_prepares_idempotent_followup_without_ai(self):
        lead = self.lead(calls=[self.call], stage="waiting")
        workspace = self.workspace(lead)
        workspace["columns"] = [{"id": "waiting", "name": "Aguardando resposta",
                                 "limit": 1}]
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        due = self.now - timedelta(hours=2)
        self.assertEqual(actions[0]["dedupe_key"],
                         f"task:lead-1:Follow-up:{int(due.timestamp())}")
        self.assertEqual(actions[0]["kind"], "followup")
        self.assertTrue(actions[0]["requires_approval"])
        lead["lastTaskCompletedAt"] = (self.now - timedelta(minutes=30)).isoformat()
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])

    def test_other_column_deadline_only_notifies_including_post_sale(self):
        lead = self.lead(calls=[self.call])
        workspace = self.workspace(lead)
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "column_timeout")
        self.assertFalse(actions[0]["requires_approval"])
        self.assertEqual(actions[0]["text"], "")
        lead.update(board="Pós-venda", stage="renewal", calls=[])
        workspace["postSaleColumns"] = [{"id": "renewal", "name": "Renovação", "limit": 1}]
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "column_timeout")
        self.assertFalse(actions[0]["requires_approval"])
        self.assertEqual(actions[0]["text"], "")

    def test_opt_out_and_paused_leads_never_queue(self):
        for extra in ({"optOut": True}, {"doNotContact": True},
                      {"opt_out": True}, {"automationPaused": True},
                      {"stage": "closed"}):
            actions = worker.collect_due_actions(self.workspace(self.lead(**extra)), self.now)
            self.assertEqual(actions, [])

    def test_explicit_appointment_survives_automation_pause(self):
        lead = self.lead(automationPaused=True, nextAction="Reunião", nextDate=self.past)
        actions = worker.collect_due_actions(self.workspace(lead), self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "appointment")

    def test_abandoned_recovery_requires_reason_and_due_date(self):
        lead = self.lead(board="Abandonados", discardReason="Sem orçamento",
                         recoveryAt=self.past, calls=[self.call])
        actions = worker.collect_due_actions(self.workspace(lead), self.now)
        self.assertEqual(actions[0]["kind"], "recovery")
        self.assertIn("Sem orçamento", actions[0]["summary"])
        lead.pop("discardReason")
        self.assertEqual(worker.collect_due_actions(self.workspace(lead), self.now), [])

    def test_abandoned_lead_does_not_run_ordinary_column_cadence(self):
        lead = self.lead(board="Abandonados", calls=[self.call],
                         discardReason="Agora não",
                         recoveryAt=(self.now + timedelta(days=1)).isoformat())
        workspace = self.workspace(lead)
        workspace["columns"][0]["automations"] = {
            "enabled": True, "cadence": [{"id": "entry", "trigger": "entry",
              "delay": 0, "unit": "horas", "action": "message", "text": "Oi"}],
        }
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])

    def test_ai_rule_only_runs_for_enabled_tenant_agent(self):
        lead = self.lead(calls=[self.call])
        workspace = self.workspace(lead)
        workspace["columns"][0]["limit"] = 0
        workspace["automations"] = [{
            "id": "rule-1", "name": "Etapa parada", "enabled": True,
            "trigger": "stage_timeout", "board": "Principal", "delay": 1,
            "action": "prepare_followup", "instructions": "Retomar com contexto",
        }]
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])
        workspace["ai"]["enabled"] = True
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "automation")
        self.assertEqual(actions[0]["dedupe_key"],
                         f"rule-1:lead-1:stage_timeout:{int(worker.timestamp(self.past))}")
        workspace["automationRuns"] = [{"key": actions[0]["dedupe_key"]}]
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])
        self.assertEqual(worker.collect_due_actions(workspace, self.now + timedelta(days=1)), [])

    def test_legacy_pending_rule_prevents_duplicate_after_key_migration(self):
        lead = self.lead(calls=[self.call])
        workspace = self.workspace(lead)
        workspace["ai"]["enabled"] = True
        workspace["automations"] = [{
            "id": "rule-1", "name": "Etapa parada", "enabled": True,
            "trigger": "stage_timeout", "board": "Principal", "delay": 1,
            "action": "prepare_followup",
        }]
        workspace["manualApprovals"] = [{"ruleId": "rule-1", "leadId": "lead-1",
                                         "status": "pending"}]
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])
        workspace["manualApprovals"][0]["status"] = "dismissed"
        workspace["automationRuns"] = [{"key": "rule-1:lead-1:2026-09-19",
                                        "at": self.now.isoformat()}]
        self.assertEqual(worker.collect_due_actions(workspace, self.now + timedelta(days=1)), [])

    def test_due_custom_inactivity_rule_replaces_generic_review(self):
        old = (self.now - timedelta(days=31)).isoformat()
        lead = self.lead(calls=[self.call], lastContactAt=old)
        workspace = self.workspace(lead)
        workspace["settings"] = {"inactiveDays": 30}
        workspace["columns"][0]["limit"] = 0
        workspace["ai"]["enabled"] = True
        workspace["automations"] = [{
            "id": "inactive-1", "name": "Reabrir conversa", "enabled": True,
            "trigger": "inactive_lead", "board": "Principal", "delay": 720,
            "action": "prepare_followup",
        }]
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "automation")
        self.assertEqual(actions[0]["dedupe_key"],
                         f"inactive-1:lead-1:inactive_lead:{int(worker.timestamp(old))}")
        workspace["manualApprovals"] = [{"ruleId": "inactive-1", "leadId": "lead-1",
                                         "status": "pending"}]
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])

    def test_column_message_becomes_call_until_call_is_recorded(self):
        lead = self.lead(product="Plano Premium")
        workspace = self.workspace(lead)
        workspace["columns"][0]["automations"] = {
            "enabled": True, "callFirst": True,
            "cadence": [{"id": "step-1", "trigger": "entry", "delay": 0,
                         "unit": "horas", "action": "message",
                         "text": "Oi, {nome}. Falamos do {produto}?"}],
        }
        actions = worker.collect_due_actions(workspace, self.now)
        column_action = next(item for item in actions if item["dedupe_key"].startswith("call-first:"))
        self.assertEqual(column_action["kind"], "call")
        self.assertEqual(column_action["text"], "")
        self.assertEqual(len(actions), 1)
        lead["calls"] = [self.call]
        actions = worker.collect_due_actions(workspace, self.now)
        column_action = next(item for item in actions if item["dedupe_key"].startswith("column:"))
        self.assertEqual(column_action["kind"], "column_cadence")
        self.assertEqual(column_action["text"], "Oi, Ana. Falamos do Plano Premium?")

    def test_reply_step_ignores_response_from_previous_stage_stay(self):
        lead = self.lead(calls=[self.call], entered=self.now.isoformat(),
                         lastReplyAt=(self.now - timedelta(hours=1)).isoformat())
        workspace = self.workspace(lead)
        workspace["columns"][0]["automations"] = {
            "enabled": True,
            "cadence": [{"id": "reply", "trigger": "reply", "delay": 0,
                         "unit": "horas", "action": "notify", "text": "Revisar"}],
        }
        self.assertEqual(worker.collect_due_actions(workspace, self.now), [])

    def test_post_sale_column_is_observation_only(self):
        lead = self.lead(board="Pós-venda", stage="renewal", calls=[self.call])
        workspace = self.workspace(lead)
        workspace["postSaleColumns"] = [{
            "id": "renewal", "name": "Renovação", "limit": 1,
            "automations": {"enabled": True, "cadence": [
                {"id": "bad", "trigger": "entry", "delay": 0, "unit": "horas",
                 "action": "message", "text": "Não pode"},
                {"id": "observe", "trigger": "entry", "delay": 0, "unit": "horas",
                 "action": "observe", "text": "Revisar saúde"},
            ]},
        }]
        actions = worker.collect_due_actions(workspace, self.now)
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["kind"], "column_observation")
        self.assertFalse(actions[0]["requires_approval"])

    def test_materialize_adopts_browser_action_without_duplicate_approval(self):
        action = {
            "dedupe_key": "column:Principal:new:step-1:lead-1:1",
            "lead_id": "lead-1", "lead_name": "Ana", "rule_id": "step-1",
            "kind": "column_cadence", "title": "Mensagem",
            "summary": "Revisar", "text": "Oi", "due_at": self.now,
            "requires_approval": True,
        }
        workspace = {"manualApprovals": [{"dedupeKey": action["dedupe_key"]}]}

        class Result:
            def fetchone(self):
                return {"id": "job-1"}

        class DB:
            def __init__(self):
                self.calls = []

            def execute(self, statement, params=()):
                self.calls.append((statement, params))
                return Result()

        db = DB()
        self.assertTrue(worker.materialize_action(db, "org-1", workspace, action, self.now))
        self.assertEqual(len(workspace["manualApprovals"]), 1)
        self.assertIn("pending_approval", db.calls[0][1])

    def test_learning_flag_prevents_continuous_policy(self):
        lead = self.lead(calls=[self.call])
        workspace = self.workspace(lead)
        workspace["ai"] = {"enabled": True, "learningEnabled": False}
        self.assertFalse(worker.ai_service.observation_policy(workspace, lead)["enabled"])

    def test_ai_memories_expire_and_exclude_opted_out_or_removed_leads(self):
        recent = (self.now - timedelta(days=10)).isoformat()
        old = (self.now - timedelta(days=181)).isoformat()
        workspace = self.workspace(self.lead())
        workspace["leads"].extend([
            self.lead(id="opted", optOut=True),
            self.lead(id="no-contact", doNotContact=True),
            self.lead(id="legacy-opt-out", opt_out=True),
        ])
        workspace["ai"] = {"memoryRetentionDays": 180, "memories": [
            {"id": "keep", "leadId": "lead-1", "at": recent},
            {"id": "expired", "leadId": "lead-1", "at": old},
            {"id": "undated", "leadId": "lead-1"},
            {"id": "invalid", "leadId": "lead-1", "at": "not-a-date"},
            {"id": "future", "leadId": "lead-1", "at":
             (self.now + timedelta(days=30)).isoformat()},
            {"id": "opted", "leadId": "opted", "at": recent},
            {"id": "no-contact", "leadId": "no-contact", "at": recent},
            {"id": "legacy-opt-out", "leadId": "legacy-opt-out", "at": recent},
            {"id": "removed", "leadId": "missing", "at": recent},
        ]}
        self.assertTrue(worker.prune_ai_memories(workspace, self.now))
        self.assertEqual([m["id"] for m in workspace["ai"]["memories"]], ["keep"])
        self.assertFalse(worker.prune_ai_memories(workspace, self.now))

    def test_ai_memory_retention_is_bounded(self):
        self.assertEqual(worker.memory_retention_days({"ai": {"memoryRetentionDays": 1}}), 7)
        self.assertEqual(worker.memory_retention_days({"ai": {"memoryRetentionDays": 9999}}), 730)
        self.assertEqual(worker.memory_retention_days({"ai": {"memoryRetentionDays": "bad"}}), 180)

    def test_ai_memory_pruning_handles_legacy_malformed_leads(self):
        for bad_leads in (None, {}, "invalid"):
            workspace = {"leads": bad_leads, "ai": {"memories": [{
                "leadId": "lead-1", "at": self.now.isoformat()}]}}
            self.assertTrue(worker.prune_ai_memories(workspace, self.now))
            self.assertEqual(workspace["ai"]["memories"], [])
        self.assertEqual(worker.timestamp("2026-09-19T12:00:00"), self.now.timestamp())

    def test_scheduler_persists_memory_pruning_without_due_actions(self):
        workspace = self.workspace(self.lead())
        workspace["ai"] = {"enabled": False, "memories": [{"id": "old",
            "leadId": "lead-1", "at": (self.now - timedelta(days=200)).isoformat()}]}

        class Result:
            def __init__(self, row=None, rows=None):
                self.row, self.rows = row, rows or []

            def fetchone(self):
                return self.row

            def fetchall(self):
                return self.rows

        class DB:
            def __init__(self):
                self.saved = None
                self.saved_org = None
                self.analysis_cleanup_org = None

            def execute(self, query, params=()):
                if "pg_try_advisory_lock" in query:
                    return Result({"acquired": True})
                if "INSERT INTO worker_runs" in query:
                    return Result({"id": 1})
                if "SELECT w.organization_id FROM tenant_workspaces w" in query:
                    return Result(rows=[{"organization_id": "org-1"}])
                if "SELECT w.organization_id,w.state,w.revision" in query:
                    return Result({"organization_id": "org-1", "state": workspace,
                                   "revision": 1, "last_worker_at": None})
                if "UPDATE tenant_workspaces SET state=%s::jsonb" in query:
                    self.saved = json.loads(params[0])
                    self.saved_org = params[1]
                if "DELETE FROM ai_analyses WHERE organization_id=%s" in query:
                    self.analysis_cleanup_org = params[0]
                return Result()

            def commit(self):
                pass

            def rollback(self):
                pass

        db = DB()
        with patch.object(worker, "ensure_schema"), \
                patch.object(worker, "ensure_worker_schema"), \
                patch.object(worker.ai_service, "ensure_schema"), \
                patch.object(worker, "ensure_runtime_schema"), \
                patch.object(worker, "collect_due_actions", return_value=[]), \
                patch.object(worker, "queue_ai_observations", return_value=0), \
                patch.object(worker, "process_ai_jobs", return_value={
                    "completed": 0, "failed": 0, "deferred": 0, "skipped": 0}), \
                patch.object(worker.integration_events, "process_deliveries", return_value={
                    "claimed": 0, "delivered": 0, "retry": 0, "dead": 0, "paused": 0}), \
                patch.object(worker.integration_events, "cleanup_history"):
            result = worker.run_batch(db, self.now)
        self.assertEqual(result["actionsCreated"], 0)
        self.assertEqual(db.saved["ai"]["memories"], [])
        self.assertEqual(db.saved_org, "org-1")
        self.assertEqual(db.analysis_cleanup_org, "org-1")

    def test_observation_queue_reaches_unseen_leads_beyond_first_200(self):
        leads = [self.lead(
            id=f"lead-{index}",
            entered=(self.now - timedelta(hours=index + 1)).isoformat(),
            calls=[self.call],
        ) for index in range(250)]
        workspace = {
            "leads": leads,
            "columns": [{"id": "new", "limit": 0, "aiObserver": {"enabled": True},
                         "aiOperator": {"enabled": True}}],
            "ai": {"enabled": True, "learningEnabled": True},
            "businessProfile": {},
        }
        previous = [{
            "lead_id": lead["id"], "status": "completed",
            "source_meta": worker.ai_service.observation_source_meta(workspace, lead),
            "created_at": self.now - timedelta(minutes=index + 1),
        } for index, lead in enumerate(leads[:240])]

        class Result:
            def __init__(self, one=None, all_rows=None):
                self.one, self.all_rows = one, all_rows

            def fetchone(self):
                return self.one

            def fetchall(self):
                return self.all_rows or []

        class DB:
            def __init__(self):
                self.inserted = []

            def execute(self, query, params=()):
                if "COUNT(*)::int" in query:
                    return Result({"count": 0})
                if "SELECT DISTINCT ON" in query:
                    return Result(all_rows=previous)
                if "to_regclass('public.whatsapp_messages')" in query:
                    return Result({"table_name": None})
                if "FROM ai_analyses" in query:
                    return Result(all_rows=[])
                if "INSERT INTO ai_observation_jobs" in query:
                    self.inserted.append(params[2])
                    return Result({"id": f"job-{len(self.inserted)}"})
                raise AssertionError(query)

        db = DB()
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-only"}, clear=False):
            queued = worker.queue_ai_observations(db, "org-1", workspace, self.now, limit=10)
        self.assertEqual(queued, 10)
        self.assertEqual(set(db.inserted), {f"lead-{index}" for index in range(240, 250)})

    def test_claim_uses_tenant_round_robin_and_locks_one_workspace(self):
        job = {"id": "job-1", "organization_id": "org-1", "attempts": 0}

        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class DB:
            def __init__(self):
                self.queries = []
                self.commits = 0

            def execute(self, query, params=()):
                self.queries.append(query)
                if "SELECT j.*" in query:
                    return Result(dict(job))
                return Result()

            def commit(self):
                self.commits += 1

        db = DB()
        claimed = worker.claim_ai_job(db, self.now)
        select = next(query for query in db.queries if "SELECT j.*" in query)
        self.assertEqual(claimed["attempts"], 1)
        self.assertIn("w.last_ai_worker_at", select)
        self.assertIn("FOR UPDATE OF j,w SKIP LOCKED", select)
        self.assertTrue(any("SET last_ai_worker_at" in query for query in db.queries))
        self.assertEqual(db.commits, 1)

    def test_failed_continuous_analysis_refunds_both_quota_counters(self):
        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

        class DB:
            def __init__(self):
                self.requests = 0
                self.continuous_requests = 0
                self.input_tokens = 0
                self.output_tokens = 0
                self.audits = []
                self.reservation_sql = ""

            def execute(self, query, params=()):
                if "SELECT plan,status,permissions FROM organizations" in query:
                    return Result({"plan": "Base", "status": "active", "permissions": {}})
                if "SELECT state FROM tenant_workspaces" in query:
                    return Result({"state": {"leads": [{"id": "lead-1"}]}})
                if "INSERT INTO ai_usage_daily" in query:
                    self.reservation_sql = query
                    self.requests += 1
                    self.continuous_requests += 1
                    return Result({"requests": self.requests,
                                   "continuous_requests": self.continuous_requests})
                if "SET requests=GREATEST(requests-1,0)" in query:
                    self.requests = max(0, self.requests - 1)
                    self.continuous_requests = max(0, self.continuous_requests - 1)
                    self.input_tokens += params[0]
                    self.output_tokens += params[1]
                if "ai.analysis.continuous_failed" in query:
                    self.audits.append(json.loads(params[1]))
                return Result()

            def commit(self):
                pass

            def rollback(self):
                pass

        cases = [
            ("provider", worker.ai_service.AIError("Indisponível", "provider_unavailable", 502), 0, 0),
            ("invalid_output", {"usage": {"input_tokens": 13, "output_tokens": 5}, "output": []}, 13, 5),
            ("unexpected", RuntimeError("Falha interna"), 0, 0),
        ]
        for name, outcome, input_tokens, output_tokens in cases:
            with self.subTest(name=name):
                db = DB()
                job = {"id": "job-1", "organization_id": "org-1", "lead_id": "lead-1",
                       "trigger": "entry", "input_hash": "hash", "attempts": 1}

                def provider(_request):
                    self.assertEqual((db.requests, db.continuous_requests), (1, 1))
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                with patch.object(worker.ai_service, "observation_policy",
                                  return_value={"enabled": True, "column": {}}), \
                     patch.object(worker.ai_service, "build_context", return_value={"lead": {}}), \
                     patch.object(worker.ai_service, "context_hash", return_value="hash"), \
                     patch.object(worker.ai_service, "provider_request", return_value={"model": "test"}), \
                     patch.object(worker.ai_service, "call_provider", side_effect=provider):
                    if name == "unexpected":
                        with self.assertRaises(RuntimeError):
                            worker.process_ai_job(db, job, self.now)
                    else:
                        self.assertEqual(worker.process_ai_job(db, job, self.now), "retry")
                self.assertIn("WHERE ai_usage_daily.requests < %s", db.reservation_sql)
                self.assertIn("ai_usage_daily.continuous_requests < %s", db.reservation_sql)
                self.assertEqual((db.requests, db.continuous_requests), (0, 0))
                self.assertEqual((db.input_tokens, db.output_tokens), (input_tokens, output_tokens))
                self.assertEqual(len(db.audits), 1)
                self.assertEqual(db.audits[0]["job_id"], "job-1")

    def test_batch_returns_cleanly_when_another_scheduler_holds_lock(self):
        class Result:
            def fetchone(self):
                return {"acquired": False}

        class DB:
            def __init__(self):
                self.queries = []

            def execute(self, query, params=()):
                self.queries.append(query)
                return Result()

            def commit(self):
                pass

            def rollback(self):
                pass

        db = DB()
        with patch.object(worker, "ensure_schema"), \
                patch.object(worker, "ensure_worker_schema"), \
                patch.object(worker.ai_service, "ensure_schema"), \
                patch.object(worker, "ensure_runtime_schema"):
            result = worker.run_batch(db, self.now)
        self.assertTrue(result["alreadyRunning"])
        self.assertFalse(any("INSERT INTO worker_runs" in query for query in db.queries))

    def test_batch_processes_webhooks_after_committing_tenant_work(self):
        events = []

        class Result:
            def __init__(self, row=None, rows=None):
                self.row, self.rows = row, rows or []

            def fetchone(self):
                return self.row

            def fetchall(self):
                return self.rows

        class DB:
            def __init__(self):
                self.queries = []

            def execute(self, query, params=()):
                self.queries.append((query, params))
                events.append("execute")
                if "pg_try_advisory_lock" in query:
                    return Result({"acquired": True})
                if "INSERT INTO worker_runs" in query:
                    return Result({"id": 8})
                if "SELECT w.organization_id FROM" in query:
                    return Result(rows=[])
                return Result()

            def commit(self):
                events.append("commit")

            def rollback(self):
                events.append("rollback")

        def deliver(_db, limit):
            self.assertEqual(limit, 20)
            self.assertEqual(events[-1], "commit")
            events.append("webhooks")
            return {"claimed": 5, "delivered": 3, "retry": 1,
                    "dead": 1, "paused": 1}

        db = DB()
        with patch.object(worker, "ensure_schema"), \
                patch.object(worker, "ensure_worker_schema"), \
                patch.object(worker.ai_service, "ensure_schema"), \
                patch.object(worker, "ensure_runtime_schema"), \
                patch.object(worker.integration_events, "process_deliveries",
                             side_effect=deliver), \
                patch.object(worker.integration_events, "cleanup_history",
                             return_value={"deliveries": 0, "events": 0}), \
                patch.object(worker, "process_ai_jobs", return_value={
                    "completed": 2, "failed": 0, "deferred": 0, "skipped": 0}):
            result = worker.run_batch(db, self.now)

        self.assertEqual(result["webhookDeliveriesClaimed"], 5)
        self.assertEqual(result["webhookDeliveriesDelivered"], 3)
        self.assertEqual(result["webhookDeliveriesRetried"], 1)
        self.assertEqual(result["webhookDeliveriesDead"], 1)
        self.assertEqual(result["webhookEndpointsPaused"], 1)
        final_update = next(
            (params for query, params in db.queries
             if "webhook_deliveries_claimed=%s" in query), None)
        self.assertIsNotNone(final_update)
        self.assertEqual(final_update[-6:-1], (5, 3, 1, 1, 1))

    def test_failed_batch_keeps_a_failed_worker_run(self):
        class Result:
            def __init__(self, row=None):
                self.row = row

            def fetchone(self):
                return self.row

            def fetchall(self):
                return []

        class DB:
            def __init__(self):
                self.queries = []
                self.commits = 0
                self.rollbacks = 0

            def execute(self, query, params=()):
                self.queries.append(query)
                if "pg_try_advisory_lock" in query:
                    return Result({"acquired": True})
                if "INSERT INTO worker_runs" in query:
                    return Result({"id": 7})
                if "SELECT w.organization_id FROM" in query:
                    raise RuntimeError("database unavailable")
                return Result()

            def commit(self):
                self.commits += 1

            def rollback(self):
                self.rollbacks += 1

        db = DB()
        with patch.object(worker, "ensure_schema"), \
                patch.object(worker, "ensure_worker_schema"), \
                patch.object(worker.ai_service, "ensure_schema"), \
                patch.object(worker, "ensure_runtime_schema"):
            with self.assertRaises(RuntimeError):
                worker.run_batch(db, self.now)
        self.assertTrue(any("status='failed'" in query for query in db.queries))
        self.assertTrue(any("pg_advisory_unlock" in query for query in db.queries))
        self.assertGreaterEqual(db.commits, 3)

    def test_cron_requires_a_long_server_secret(self):
        with patch.dict(os.environ, {"CRON_SECRET": "short"}, clear=False):
            self.assertFalse(worker.authorized({"Authorization": "Bearer short"}))
        with patch.dict(os.environ, {"CRON_SECRET": "a-secure-worker-secret"}, clear=False):
            self.assertTrue(worker.authorized({"Authorization": "Bearer a-secure-worker-secret"}))
            self.assertFalse(worker.authorized({"Authorization": "Bearer another-secret"}))


if __name__ == "__main__":
    unittest.main()
