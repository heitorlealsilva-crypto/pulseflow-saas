import json
import os
import unittest
from unittest.mock import patch

from api import ai


class FakeDB:
    def execute(self, query, params=None):
        self.query = query
        self.params = params
        return self

    def fetchone(self):
        if "to_regclass" in self.query:
            return {"table_name": None}
        return None

    def fetchall(self):
        return []


def sample_analysis(**changes):
    value = {
        "summary": "Cliente avaliando a solução.",
        "stage": "Em atendimento",
        "intent": "Entender o prazo",
        "awareness": "Conhece o problema",
        "objections": ["Prazo"],
        "signals": ["Pediu uma reunião"],
        "recommended_next_action": "message",
        "suggested_message": "Podemos marcar 15 minutos amanhã?",
        "follow_up_reason": "Confirmar o próximo passo",
        "follow_up_after_hours": 24,
        "confidence": 0.82,
        "memory_facts": ["Prefere contato à tarde"],
    }
    value.update(changes)
    return value


class AITests(unittest.TestCase):
    def test_plan_limits_protect_entry_cost(self):
        self.assertEqual(ai.plan_limit("Base"), 10)
        self.assertEqual(ai.plan_limit("Equipe"), 100)
        self.assertEqual(ai.plan_limit("desconhecido"), 10)
        self.assertEqual(ai.continuous_limit("Base"), 3)
        self.assertEqual(ai.continuous_limit("Equipe"), 30)

    def test_provider_request_is_private_and_structured(self):
        context = {"lead": {"notes": ai.redact("Ligue 11999999999 ou ana@example.com", 500)}}
        request = ai.provider_request(context, "org-a", "user-a")
        self.assertFalse(request["store"])
        self.assertNotIn("11999999999", json.dumps(request))
        self.assertNotIn("ana@example.com", json.dumps(request))
        self.assertEqual(request["text"]["format"]["type"], "json_schema")
        self.assertEqual(len(request["safety_identifier"]), 64)
        self.assertNotIn("org-a", request["safety_identifier"])

    def test_context_is_bounded_and_does_not_send_phone(self):
        lead = {"name": "Ana Silva", "phone": "11999999999", "messages": [
            {"direction": "in", "body": "x" * 3000 + " 11999999999"} for _ in range(30)
        ], "notes": "ana@example.com"}
        context = ai.build_context(FakeDB(), "org", {"ai": {}, "businessProfile": {}}, lead)
        self.assertLessEqual(len(context["recent_conversation"]), 20)
        raw = json.dumps(context)
        self.assertNotIn("11999999999", raw)
        self.assertNotIn("ana@example.com", raw)
        self.assertNotIn("Silva", raw)

    def test_context_respects_configured_memory_retention(self):
        db = FakeDB()
        ai.build_context(db, "org", {
            "ai": {"memoryRetentionDays": 21}, "businessProfile": {},
        }, {"name": "Ana", "messages": []})
        self.assertIn("created_at >=", db.query)
        self.assertEqual(db.params, ("org", 21))

    def test_column_instructions_and_calls_are_in_context(self):
        lead = {"name": "Ana", "stage": "new", "calls": [{
            "id": "c1", "at": "2026-09-20T10:00:00+00:00",
            "outcome": "Conversa realizada", "note": "Quer decidir amanhã",
        }]}
        column = {"aiObserver": {"instructions": "Observe urgência"},
                  "aiOperator": {"instructions": "Sugira uma pergunta"}}
        context = ai.build_context(FakeDB(), "org", {"ai": {}, "businessProfile": {}},
                                   lead, "context_changed", column)
        self.assertEqual(context["business"]["column_observer_instructions"], "Observe urgência")
        self.assertEqual(context["lead"]["analysis_trigger"], "context_changed")
        self.assertEqual(context["recent_calls"][0]["note"], "Quer decidir amanhã")

    def test_continuous_policy_requires_learning_and_respects_column(self):
        lead = {"stage": "new", "board": "Principal"}
        workspace = {"ai": {"enabled": True, "learningEnabled": False},
                     "columns": [{"id": "new", "aiObserver": {"enabled": True},
                                  "aiOperator": {"enabled": True}}]}
        self.assertFalse(ai.observation_policy(workspace, lead)["enabled"])
        workspace["ai"]["learningEnabled"] = True
        self.assertTrue(ai.observation_policy(workspace, lead)["enabled"])
        workspace["columns"][0]["aiObserver"]["enabled"] = False
        self.assertFalse(ai.observation_policy(workspace, lead)["enabled"])
        post_sale = {"stage": "renewal", "board": "Pós-venda"}
        workspace["postSaleColumns"] = [{"id": "renewal", "aiObserver": {"enabled": True},
                                          "aiOperator": {"enabled": True}}]
        self.assertFalse(ai.observation_policy(workspace, post_sale)["operator_enabled"])

    def test_observation_trigger_changes_and_deadline(self):
        from datetime import datetime, timedelta, timezone
        now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        lead = {"id": "l1", "stage": "new", "board": "Principal",
                "entered": (now - timedelta(hours=2)).isoformat(), "notes": ""}
        workspace = {"ai": {"enabled": True, "learningEnabled": True},
                     "columns": [{"id": "new", "limit": 1}]}
        policy = ai.observation_policy(workspace, lead)
        current = ai.observation_source_meta(workspace, lead)
        self.assertEqual(ai.classify_observation(None, current, policy, lead, now), "entry")
        self.assertEqual(ai.classify_observation(current, current, policy, lead, now), "deadline")
        changed = dict(current, notes_hash="changed")
        self.assertEqual(ai.classify_observation(current, changed, policy, lead, now), "context_changed")

    def test_disabled_reply_trigger_does_not_block_enabled_deadline(self):
        from datetime import datetime, timedelta, timezone
        now = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)
        lead = {"stage": "new", "board": "Principal",
                "entered": (now - timedelta(hours=2)).isoformat(), "notes": ""}
        policy = {"triggers": {"entry": False, "deadline": True, "reply": False},
                  "column": {"limit": 1}}
        previous = {"stage": "new", "board": "Principal", "entered": lead["entered"],
                    "reply_id": "old", "notes_hash": "same", "calls_hash": "same",
                    "messages_hash": "same", "config_hash": "same"}
        current = dict(previous, reply_id="new")
        self.assertEqual(ai.classify_observation(previous, current, policy, lead, now), "deadline")

    def test_global_memories_do_not_requeue_every_lead(self):
        base = {"business": {}, "lead": {"stage": "new"}, "recent_conversation": [],
                "approved_business_memories": ["A"]}
        changed = {**base, "approved_business_memories": ["B"]}
        self.assertEqual(ai.context_hash(base), ai.context_hash(changed))

    def test_call_first_rule_overrides_model_message(self):
        result = ai.enforce_safety(sample_analysis(), {"board": "Principal", "calls": []})
        self.assertEqual(result["recommended_next_action"], "call")
        self.assertEqual(result["suggested_message"], "")
        self.assertTrue(result["requires_seller_approval"])

    def test_post_sale_is_strictly_observation_only(self):
        lead = {"board": "Pós-venda", "calls": [{"id": "c1", "outcome": "Atendeu"}]}
        result = ai.enforce_safety(sample_analysis(), lead)
        self.assertTrue(result["observation_only"])
        self.assertEqual(result["recommended_next_action"], "none")
        self.assertEqual(result["suggested_message"], "")

    def test_opt_out_cannot_receive_model_suggestion(self):
        lead = {"board": "Principal", "optOut": True, "calls": [{"id": "c1", "outcome": "Atendeu"}]}
        result = ai.enforce_safety(sample_analysis(), lead)
        self.assertEqual(result["recommended_next_action"], "none")
        self.assertEqual(result["suggested_message"], "")

    def test_missing_provider_key_fails_closed(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": ""}):
            with self.assertRaises(ai.AIError) as caught:
                ai.call_provider({})
        self.assertEqual(caught.exception.code, "ai_not_configured")

    def test_invalid_provider_output_is_rejected(self):
        with self.assertRaises(ai.AIError):
            ai.extract_analysis({"output": [{"content": [{"type": "output_text", "text": "{}"}]}]})
        valid = {"output": [{"content": [{"type": "output_text", "text": json.dumps(sample_analysis())}]}]}
        self.assertEqual(ai.extract_analysis(valid)["intent"], "Entender o prazo")


if __name__ == "__main__":
    unittest.main()
