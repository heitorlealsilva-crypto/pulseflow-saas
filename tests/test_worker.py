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

    def test_opt_out_and_paused_leads_never_queue(self):
        for extra in ({"optOut": True}, {"automationPaused": True}, {"stage": "closed"}):
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
        self.assertEqual(actions[0]["dedupe_key"], "rule-1:lead-1:2026-09-19")
        workspace["automationRuns"] = [{"key": actions[0]["dedupe_key"]}]
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
                if "SELECT result FROM ai_analyses" in query:
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
