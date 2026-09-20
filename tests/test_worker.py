import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

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

    def test_abandoned_recovery_requires_reason_and_due_date(self):
        lead = self.lead(board="Abandonados", discardReason="Sem orçamento",
                         recoveryAt=self.past, calls=[self.call])
        actions = worker.collect_due_actions(self.workspace(lead), self.now)
        self.assertEqual(actions[0]["kind"], "recovery")
        self.assertIn("Sem orçamento", actions[0]["summary"])
        lead.pop("discardReason")
        self.assertEqual(worker.collect_due_actions(self.workspace(lead), self.now), [])

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

    def test_cron_requires_a_long_server_secret(self):
        with patch.dict(os.environ, {"CRON_SECRET": "short"}, clear=False):
            self.assertFalse(worker.authorized({"Authorization": "Bearer short"}))
        with patch.dict(os.environ, {"CRON_SECRET": "a-secure-worker-secret"}, clear=False):
            self.assertTrue(worker.authorized({"Authorization": "Bearer a-secure-worker-secret"}))
            self.assertFalse(worker.authorized({"Authorization": "Bearer another-secret"}))


if __name__ == "__main__":
    unittest.main()
