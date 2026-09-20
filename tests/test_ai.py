import json
import os
import unittest
from unittest.mock import patch

from api import ai


class FakeDB:
    def execute(self, query, params=None):
        self.query = query
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
