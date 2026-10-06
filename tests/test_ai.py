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


class SmokeDB:
    def __init__(self, available=True):
        self.available = available
        self.queries = []
        self.audits = []
        self.commits = 0
        self.row = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, params=None):
        self.queries.append(query)
        if "INSERT INTO auth_rate_limits" in query:
            self.row = {"attempts": 1} if self.available else None
            self.reservation_params = params
        elif "INSERT INTO audit_logs" in query:
            self.audits.append(json.loads(params[1]))
            self.row = None
        else:
            raise AssertionError("The smoke test must not read or write tenant data: " + query)
        return self

    def fetchone(self):
        return self.row

    def commit(self):
        self.commits += 1


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
    @staticmethod
    def smoke_endpoint(payload=None):
        endpoint = ai.handler.__new__(ai.handler)
        endpoint.headers = {"Cookie": "pulseflow_session=test"}
        endpoint.query = lambda: {"action": "smoke-test"}
        endpoint.body = lambda: {} if payload is None else payload
        endpoint.reply = lambda status, value: (status, value)
        return endpoint

    def test_smoke_test_uses_only_synthetic_input_and_returns_usage(self):
        db = SmokeDB()
        response = {"usage": {"input_tokens": 42, "output_tokens": 19},
                    "output": [{"content": [{"type": "output_text", "text": json.dumps(sample_analysis())}]}]}

        def provider(request):
            self.assertFalse(request["store"])
            self.assertEqual(request["text"]["format"]["type"], "json_schema")
            self.assertEqual(json.loads(request["input"][0]["content"][0]["text"]), ai.SMOKE_TEST_CONTEXT)
            self.assertNotIn("admin-user-id", json.dumps(request))
            return response

        with patch.object(ai, "request_origin_allowed", return_value=True), \
             patch.object(ai, "connect", return_value=db), \
             patch.object(ai, "session_user", return_value={"id": "admin-user-id", "role": "super_admin"}), \
             patch.object(ai, "call_provider", side_effect=provider) as call_provider, \
             patch.object(ai, "ensure_schema") as ensure_schema, \
             patch.object(ai, "build_context") as build_context:
            status, payload = self.smoke_endpoint().do_POST()
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"ok": True, "model": ai.DEFAULT_MODEL,
                                   "input_tokens": 42, "output_tokens": 19})
        self.assertEqual(call_provider.call_count, 1)
        self.assertEqual(db.audits, [{"model": ai.DEFAULT_MODEL, "code": "ok"}])
        self.assertEqual(db.commits, 2)
        self.assertEqual(len(db.queries), 2)
        self.assertIn("auth_rate_limits.attempts<%s", db.queries[0])
        self.assertEqual(db.reservation_params[1], ai.SMOKE_TEST_HOURLY_LIMIT)
        ensure_schema.assert_not_called()
        build_context.assert_not_called()

    def test_smoke_test_requires_global_admin(self):
        for user, expected in ((None, 401), ({"id": "owner", "role": "owner"}, 403),
                               ({"id": "member", "role": "member"}, 403)):
            with self.subTest(user=user):
                db = SmokeDB()
                with patch.object(ai, "request_origin_allowed", return_value=True), \
                     patch.object(ai, "connect", return_value=db), \
                     patch.object(ai, "session_user", return_value=user), \
                     patch.object(ai, "call_provider") as call_provider:
                    status, payload = self.smoke_endpoint().do_POST()
                self.assertEqual(status, expected)
                self.assertFalse(payload["ok"])
                self.assertEqual(db.queries, [])
                call_provider.assert_not_called()

    def test_smoke_test_rejects_other_origins_and_client_data(self):
        with patch.object(ai, "request_origin_allowed", return_value=False), \
             patch.object(ai, "connect") as connect:
            status, payload = self.smoke_endpoint().do_POST()
        self.assertEqual((status, payload["code"]), (403, "invalid_origin"))
        connect.assert_not_called()

        db = SmokeDB()
        with patch.object(ai, "request_origin_allowed", return_value=True), \
             patch.object(ai, "connect", return_value=db), \
             patch.object(ai, "session_user", return_value={"id": "admin", "role": "super_admin"}), \
             patch.object(ai, "call_provider") as call_provider:
            status, payload = self.smoke_endpoint({"organization_id": "real-org"}).do_POST()
        self.assertEqual((status, payload["code"]), (400, "invalid_body"))
        self.assertEqual(db.queries, [])
        call_provider.assert_not_called()

    def test_smoke_test_rate_limit_precedes_provider(self):
        db = SmokeDB(available=False)
        with patch.object(ai, "request_origin_allowed", return_value=True), \
             patch.object(ai, "connect", return_value=db), \
             patch.object(ai, "session_user", return_value={"id": "admin", "role": "super_admin"}), \
             patch.object(ai, "call_provider") as call_provider:
            status, payload = self.smoke_endpoint().do_POST()
        self.assertEqual((status, payload["code"]), (429, "smoke_test_rate_limited"))
        self.assertEqual(db.commits, 0)
        self.assertEqual(db.audits, [])
        call_provider.assert_not_called()

    def test_smoke_test_failure_is_sanitized_and_audited(self):
        cases = [
            (ai.AIError("Provider secret", "provider_rejected", 502), 502, "provider_rejected"),
            ({"output": []}, 502, "provider_invalid"),
            (RuntimeError("Provider secret"), 503, "ai_unavailable"),
        ]
        for result, expected_status, expected_code in cases:
            with self.subTest(result=result):
                db = SmokeDB()
                with patch.object(ai, "request_origin_allowed", return_value=True), \
                     patch.object(ai, "connect", return_value=db), \
                     patch.object(ai, "session_user", return_value={"id": "admin", "role": "super_admin"}), \
                     patch.object(ai, "call_provider", side_effect=result if isinstance(result, Exception) else None,
                                  return_value=result if not isinstance(result, Exception) else None):
                    status, payload = self.smoke_endpoint().do_POST()
                self.assertEqual((status, payload["code"]), (expected_status, expected_code))
                self.assertNotIn("Provider secret", json.dumps(payload))
                self.assertEqual(db.audits, [{"model": ai.DEFAULT_MODEL, "code": expected_code}])
                self.assertEqual(db.commits, 2)

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
            "ai": {"memoryRetentionDays": 21, "learningEnabled": True},
            "businessProfile": {}, "leads": [{"id": "lead-1"}],
        }, {"id": "lead-1", "name": "Ana", "messages": []})
        self.assertIn("created_at >=", db.query)
        self.assertEqual(db.params, ("org", 21))

    def test_context_excludes_memories_from_opted_out_or_removed_leads(self):
        class MemoryDB(FakeDB):
            def fetchall(self):
                if "SELECT lead_id,result FROM ai_analyses" in self.query:
                    return [
                        {"lead_id": "active", "result": {"memory_facts": ["Prefere terça"]}},
                        {"lead_id": "opted-out", "result": {"memory_facts": ["Não reutilizar"]}},
                        {"lead_id": "removed", "result": {"memory_facts": ["Apagado"]}},
                    ]
                return []

        workspace = {"ai": {"learningEnabled": True}, "leads": [
            {"id": "active"}, {"id": "opted-out", "optOut": True},
        ]}
        lead = {"id": "active", "name": "Ana"}
        memories = ai.build_context(MemoryDB(), "org", workspace, lead)["prior_unverified_observations"]
        self.assertEqual(memories, ["Prefere terça"])
        workspace["ai"]["learningEnabled"] = False
        self.assertEqual(ai.build_context(MemoryDB(), "org", workspace, lead)["prior_unverified_observations"], [])

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
                "prior_unverified_observations": ["A"]}
        changed = {**base, "prior_unverified_observations": ["B"]}
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

    def test_manual_analysis_rejects_opted_out_before_provider_call(self):
        for preference in ("optOut", "doNotContact"):
            with self.subTest(preference=preference):
                class EndpointDB:
                    def __enter__(self):
                        return self

                    def __exit__(self, *_args):
                        return False

                    def execute(self, query, _params=None):
                        self.query = query
                        return self

                    def fetchone(self):
                        if "SELECT plan FROM organizations" in self.query:
                            return {"plan": "Base"}
                        if "SELECT state FROM tenant_workspaces" in self.query:
                            return {"state": {"ai": {"enabled": True}, "leads": [
                                {"id": "lead-1", preference: True, "notes": "Dados privados"}
                            ]}}
                        raise AssertionError("A análise não deve reservar uso nem alcançar o provedor.")

                endpoint = ai.handler.__new__(ai.handler)
                endpoint.headers = {}
                endpoint.query = lambda: {"action": "analyze"}
                endpoint.body = lambda: {"organization_id": "org-1", "lead_id": "lead-1"}
                endpoint.authenticated_org = lambda *_args: ({"id": "user-1"}, "org-1")
                endpoint.reply = lambda status, value: (status, value)
                with patch.object(ai, "request_origin_allowed", return_value=True), \
                     patch.object(ai, "ensure_schema"), \
                     patch.object(ai, "connect", return_value=EndpointDB()), \
                     patch.object(ai, "build_context") as build_context, \
                     patch.object(ai, "call_provider") as call_provider:
                    status, payload = endpoint.do_POST()
                self.assertEqual(status, 409)
                self.assertEqual(payload["code"], "contact_opted_out")
                build_context.assert_not_called()
                call_provider.assert_not_called()

    def test_failed_manual_analysis_releases_reserved_daily_slot(self):
        class QuotaDB:
            def __init__(self):
                self.requests = 0
                self.input_tokens = 0
                self.output_tokens = 0
                self.audits = []
                self.analyses = 0
                self.commits = 0
                self.reservation_query = ""

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def execute(self, query, params=None):
                self.query = query
                self.params = params
                if "INSERT INTO ai_usage_daily" in query:
                    self.reservation_query = query
                    self.requests += 1
                elif "SET requests=GREATEST(requests-1,0)" in query:
                    self.requests = max(0, self.requests - 1)
                    self.input_tokens += params[0]
                    self.output_tokens += params[1]
                elif "SET input_tokens=input_tokens+" in query:
                    self.input_tokens += params[0]
                    self.output_tokens += params[1]
                elif "INSERT INTO ai_analyses" in query:
                    self.analyses += 1
                elif "INSERT INTO audit_logs" in query:
                    self.audits.append(query)
                return self

            def fetchone(self):
                if "SELECT plan FROM organizations" in self.query:
                    return {"plan": "Base"}
                if "SELECT state FROM tenant_workspaces" in self.query:
                    return {"state": {"ai": {"enabled": True}, "leads": [{"id": "lead-1"}]}}
                if "INSERT INTO ai_usage_daily" in self.query:
                    return {"requests": self.requests}
                raise AssertionError(self.query)

            def commit(self):
                self.commits += 1

            def rollback(self):
                pass

        cases = [
            ("provider", ai.AIError("Indisponível", "provider_unavailable", 502), 0, 0),
            ("invalid_output", {"usage": {"input_tokens": 17, "output_tokens": 4}, "output": []}, 17, 4),
            ("internal", RuntimeError("Falha interna"), 0, 0),
        ]
        for name, outcome, input_tokens, output_tokens in cases:
            with self.subTest(name=name):
                db = QuotaDB()
                endpoint = ai.handler.__new__(ai.handler)
                endpoint.headers = {}
                endpoint.query = lambda: {"action": "analyze"}
                endpoint.body = lambda: {"organization_id": "org-1", "lead_id": "lead-1"}
                endpoint.authenticated_org = lambda *_args: ({"id": "user-1"}, "org-1")
                endpoint.reply = lambda status, value: (status, value)

                def provider(_request):
                    self.assertEqual(db.requests, 1, "The concurrent cap must reserve before the model call")
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                with patch.object(ai, "request_origin_allowed", return_value=True), \
                     patch.object(ai, "ensure_schema"), \
                     patch.object(ai, "connect", return_value=db), \
                     patch.object(ai, "build_context", return_value={"lead": {"id": "lead-1"}}), \
                     patch.object(ai, "call_provider", side_effect=provider):
                    status, payload = endpoint.do_POST()
                self.assertIn("WHERE ai_usage_daily.requests < %s", db.reservation_query)
                self.assertEqual(status, 502 if name != "internal" else 503)
                self.assertFalse(payload["ok"])
                self.assertEqual(db.requests, 0)
                self.assertEqual((db.input_tokens, db.output_tokens), (input_tokens, output_tokens))
                self.assertEqual(db.analyses, 0)
                self.assertEqual(len(db.audits), 1)
                self.assertIn("ai.analysis.failed", db.audits[0])

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
