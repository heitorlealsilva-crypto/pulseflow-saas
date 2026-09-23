"""Deterministic tests for the tenant webhook event log and delivery outbox."""
import json
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from api import integration_events as events
from api import outbound_webhooks


TEST_KEY = "test-only-integration-encryption-key-2026"
NOW = datetime(2026, 9, 23, 12, 0, tzinfo=timezone.utc)


class Result:
    def __init__(self, one=None, many=None):
        self.one = one
        self.many = many or []

    def fetchone(self):
        return self.one

    def fetchall(self):
        return self.many


class SchemaDB:
    def __init__(self):
        self.calls = []
        self.commits = 0

    def execute(self, query, params=None):
        self.calls.append((" ".join(query.split()), params))
        return Result()

    def commit(self):
        self.commits += 1


class EndpointDB:
    def __init__(self, organization_id, count=0, recent_count=0):
        self.organization_id = organization_id
        self.count = count
        self.recent_count = recent_count
        self.calls = []
        self.insert_params = None
        self.commits = 0

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        if "SELECT id,status FROM organizations" in compact:
            return Result({"id": self.organization_id, "status": "active"})
        if "created_at>NOW() - INTERVAL '1 hour'" in compact:
            return Result({"count": self.recent_count})
        if "SELECT COUNT(*)::int AS count" in compact:
            return Result({"count": self.count})
        if "INSERT INTO integration_webhook_endpoints" in compact:
            self.insert_params = params
            return Result({
                "id": params[0], "name": params[3], "url_host": params[5],
                "event_types": json.loads(params[8]), "status": "active",
                "created_at": NOW, "updated_at": NOW,
                "last_delivery_at": None, "last_status_code": None,
                "last_error": None,
            })
        return Result()

    def commit(self):
        self.commits += 1


class EmitDB:
    def __init__(self, endpoint_ids):
        self.endpoint_ids = endpoint_ids
        self.calls = []
        self.delivery_params = []
        self.commits = 0

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        if "FROM integration_webhook_endpoints e" in compact and "SELECT e.id" in compact:
            return Result(many=[{"id": value} for value in self.endpoint_ids])
        if "INSERT INTO integration_webhook_deliveries" in compact:
            self.delivery_params.append(params)
            return Result({"id": params[0], "status": "pending", "created_at": params[6]})
        return Result()

    def commit(self):
        self.commits += 1


class TestDeliveryDB:
    def __init__(self, endpoint_id=None, recent_test=False):
        self.endpoint_id = endpoint_id
        self.recent_test = recent_test
        self.calls = []
        self.raw_body = None

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        if "SELECT id FROM integration_webhook_endpoints" in compact:
            return Result({"id": self.endpoint_id}) if self.endpoint_id else Result()
        if "event_type='pulseflow.webhook_test'" in compact:
            return Result({"exists": 1}) if self.recent_test else Result()
        if "INSERT INTO integration_webhook_deliveries" in compact:
            self.raw_body = params[5]
            return Result({"id": params[0], "status": "pending", "created_at": params[6]})
        return Result()


class DeliveryDB:
    def __init__(self, delivery, endpoint):
        self.delivery = dict(delivery)
        self.endpoint = endpoint
        self.claimed = False
        self.calls = []
        self.commits = 0
        self.final_status = None
        self.final_next_attempt = None
        self.endpoint_status = "active"

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        if compact.startswith("WITH candidate AS"):
            if self.claimed:
                return Result()
            self.claimed = True
            claimed = {**self.delivery, "claimed_lease": params[1],
                       "lease_token": params[1]}
            return Result(claimed)
        if "SELECT url_enc,secret_enc,status FROM integration_webhook_endpoints" in compact:
            return Result({**self.endpoint, "status": self.endpoint_status})
        if compact.startswith("UPDATE integration_webhook_deliveries SET status=%s,"):
            self.final_status = params[0]
            self.final_next_attempt = params[1]
        if "SET status='paused'" in compact and "lease_expired_max_attempts" not in compact:
            self.endpoint_status = "paused"
        return Result()

    def commit(self):
        self.commits += 1


def target():
    return outbound_webhooks.ValidatedTarget(
        hostname="hooks.example.com", addresses=("93.184.216.34",), path="/pulseflow")


class SchemaAndConfigurationTests(unittest.TestCase):
    def test_schema_upgrades_existing_event_log_and_uses_composite_tenant_keys(self):
        db = SchemaDB()
        events.ensure_schema(db)
        sql = "\n".join(query for query, _ in db.calls)
        self.assertIn("ALTER TABLE integration_events ADD COLUMN IF NOT EXISTS event_id UUID", sql)
        self.assertIn("integration_events_org_event_id_idx", sql)
        self.assertIn("UNIQUE(organization_id,id)", sql)
        self.assertIn("UNIQUE(organization_id,endpoint_id,event_id)", sql)
        self.assertIn("FOREIGN KEY(organization_id,event_id)", sql)
        self.assertEqual(db.commits, 0)

    def test_private_values_round_trip_and_fail_closed_without_key(self):
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": TEST_KEY}):
            encrypted = events.encrypt_private_value("https://hooks.example.com/pulseflow")
            self.assertNotIn("hooks.example.com", encrypted)
            self.assertEqual(events.decrypt_private_value(encrypted),
                             "https://hooks.example.com/pulseflow")
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": ""}):
            with self.assertRaises(events.IntegrationEventError) as caught:
                events.encrypt_private_value("secret")
        self.assertEqual(caught.exception.code, "encryption_not_configured")

    def test_create_encrypts_url_and_secret_and_returns_secret_only_once(self):
        organization_id = str(uuid.uuid4())
        actor_id = str(uuid.uuid4())
        db = EndpointDB(organization_id)
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": TEST_KEY}), \
                patch.object(outbound_webhooks, "validate_target", return_value=target()), \
                patch.object(events.secrets, "token_urlsafe", return_value="A" * 43):
            result = events.create_endpoint(
                db, organization_id, name="CRM principal",
                url="https://hooks.example.com/pulseflow",
                event_types=["contact.updated", "contact.created"],
                created_by=actor_id)
        self.assertEqual(result["secret"], "whsec_" + "A" * 43)
        self.assertEqual(result["url"], "https://hooks.example.com/••••")
        self.assertEqual(result["host"], "hooks.example.com")
        self.assertEqual(result["event_types"], ["contact.created", "contact.updated"])
        self.assertNotIn("secret_enc", result)
        self.assertNotIn("url_enc", result)
        self.assertNotIn("hooks.example.com", db.insert_params[4])
        self.assertNotIn(result["secret"], db.insert_params[6])
        self.assertEqual(db.commits, 0)

    def test_create_enforces_three_endpoint_limit_without_committing(self):
        organization_id = str(uuid.uuid4())
        db = EndpointDB(organization_id, count=3)
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": TEST_KEY}), \
                patch.object(outbound_webhooks, "validate_target", return_value=target()), \
                self.assertRaises(events.IntegrationEventError) as caught:
            events.create_endpoint(
                db, organization_id, name="Quarto",
                url="https://hooks.example.com/pulseflow",
                event_types=["contact.updated"])
        self.assertEqual((caught.exception.code, caught.exception.status),
                         ("webhook_limit", 409))
        self.assertEqual(db.commits, 0)

    def test_create_rate_limits_configuration_churn(self):
        organization_id = str(uuid.uuid4())
        db = EndpointDB(
            organization_id,
            recent_count=events.MAX_ENDPOINT_CREATIONS_PER_HOUR)
        with patch.object(outbound_webhooks, "validate_target", return_value=target()), \
                self.assertRaises(events.IntegrationEventError) as caught:
            events.create_endpoint(
                db, organization_id, name="Outro destino",
                url="https://hooks.example.com/pulseflow",
                event_types=["contact.updated"])
        self.assertEqual((caught.exception.code, caught.exception.status),
                         ("rate_limited", 429))
        self.assertIsNone(db.insert_params)

    def test_shared_transport_validates_destination_at_creation(self):
        organization_id = str(uuid.uuid4())
        error = outbound_webhooks.TargetValidationError(
            "address_not_public", "destino de webhook inválido")
        with patch.object(outbound_webhooks, "validate_target", side_effect=error), \
                self.assertRaises(events.IntegrationEventError) as caught:
            events.create_endpoint(
                EndpointDB(organization_id), organization_id, name="Interno",
                url="https://internal.example/hook",
                event_types=["contact.updated"])
        self.assertEqual(caught.exception.code, "invalid_target")


class EventOutboxTests(unittest.TestCase):
    def test_contact_payload_schema_is_stable_and_omits_external_pii(self):
        workspace_contact = {
            "id": "lead-1", "integrationExternalId": "cliente@example.com",
            "board": "Principal", "stage": "new", "optOut": True,
            "automationPaused": True,
        }
        api_contact = {
            "id": "lead-1", "external_id": "cliente@example.com",
            "board": "Principal", "stage": "new", "opt_out": True,
            "automation_paused": True,
        }
        expected = {
            "contact": {"id": "lead-1", "board": "Principal", "stage": "new",
                        "opt_out": True, "automation_paused": True},
            "workspace_revision": 7,
        }
        self.assertEqual(events.contact_event_payload(
            workspace_contact, workspace_revision=7), expected)
        self.assertEqual(events.contact_event_payload(
            api_contact, workspace_revision=7), expected)
        self.assertNotIn("cliente@example.com", json.dumps(expected))
        changed = events.stage_changed_payload(
            workspace_contact, {"board": "Principal", "stage": "old"},
            workspace_revision=7)
        self.assertEqual(changed["from"], {"board": "Principal", "stage": "old"})
        self.assertEqual(changed["to"], {"board": "Principal", "stage": "new"})

    def test_emit_event_has_stable_canonical_body_and_one_delivery_per_subscriber(self):
        organization_id = str(uuid.uuid4())
        endpoints = [str(uuid.uuid4()), str(uuid.uuid4())]
        db = EmitDB(endpoints)
        result = events.emit_event(
            db, organization_id, "contact.stage_changed", "lead-1",
            {"to": "waiting", "from": "new"}, now=NOW)
        self.assertEqual(len(result["deliveries"]), 2)
        self.assertEqual(db.commits, 0)
        self.assertEqual({params[3] for params in db.delivery_params}, {result["id"]})
        self.assertEqual({params[5] for params in db.delivery_params}, {result["raw_body"]})
        body = json.loads(result["raw_body"])
        self.assertEqual(body["id"], result["id"])
        self.assertEqual(body["organization_id"], organization_id)
        self.assertEqual(body["schema_version"], "1")
        self.assertEqual(body["occurred_at"], "2026-09-23T12:00:00Z")
        self.assertEqual(result["raw_body"], json.dumps(
            body, ensure_ascii=False, sort_keys=True, separators=(",", ":")))

    def test_emit_event_validates_payload_before_writing(self):
        db = EmitDB([])
        with self.assertRaises(events.IntegrationEventError):
            events.emit_event(db, str(uuid.uuid4()), "contact.updated", "lead-1",
                              {"bad": float("nan")}, now=NOW)
        self.assertEqual(db.calls, [])

    def test_test_delivery_contains_only_synthetic_data_and_requires_active_endpoint(self):
        organization_id = str(uuid.uuid4())
        endpoint_id = str(uuid.uuid4())
        db = TestDeliveryDB(endpoint_id)
        result = events.enqueue_test_delivery(
            db, organization_id, endpoint_id, now=NOW)
        self.assertEqual(result["delivery"]["status"], "pending")
        body = json.loads(db.raw_body)
        self.assertEqual(body["type"], "pulseflow.webhook_test")
        self.assertEqual(body["data"], {
            "test": True, "message": "Teste de entrega do PulseFlow"})
        self.assertNotIn("contact", db.raw_body.lower())

        with self.assertRaises(events.IntegrationEventError) as caught:
            events.enqueue_test_delivery(
                TestDeliveryDB(), organization_id, endpoint_id, now=NOW)
        self.assertEqual((caught.exception.code, caught.exception.status),
                         ("not_found", 404))

        with self.assertRaises(events.IntegrationEventError) as caught:
            events.enqueue_test_delivery(
                TestDeliveryDB(endpoint_id, recent_test=True),
                organization_id, endpoint_id, now=NOW)
        self.assertEqual((caught.exception.code, caught.exception.status),
                         ("rate_limited", 429))


class DeliveryProcessingTests(unittest.TestCase):
    def setUp(self):
        self.organization_id = str(uuid.uuid4())
        self.endpoint_id = str(uuid.uuid4())
        self.event_id = str(uuid.uuid4())
        self.delivery_id = str(uuid.uuid4())
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": TEST_KEY}):
            self.endpoint = {
                "url_enc": events.encrypt_private_value("https://hooks.example.com/pulseflow"),
                "secret_enc": events.encrypt_private_value("whsec_" + "S" * 43),
            }
        self.delivery = {
            "id": self.delivery_id,
            "organization_id": self.organization_id,
            "endpoint_id": self.endpoint_id,
            "event_id": self.event_id,
            "event_type": "contact.updated",
            "raw_body": '{"id":"' + self.event_id + '"}',
            "attempts": 1,
        }

    def run_delivery(self, sender):
        db = DeliveryDB(self.delivery, self.endpoint)
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": TEST_KEY}):
            result = events.process_deliveries(
                db, now=NOW, limit=1, sender=sender, delivery_clock=lambda: NOW,
                monotonic_clock=lambda: 0)
        return db, result

    def test_claim_is_committed_before_network_and_success_is_recorded(self):
        observed = {}

        def sender(url, secret, event_id, delivery_id, event_type, body, now=None):
            observed.update(url=url, secret=secret, event_id=event_id,
                            delivery_id=delivery_id, event_type=event_type,
                            body=body, now=now)
            self.assertGreaterEqual(db.commits, 2)
            return outbound_webhooks.DeliveryResult(204, 0)

        db = DeliveryDB(self.delivery, self.endpoint)
        with patch.dict(os.environ, {"PULSEFLOW_ENCRYPTION_KEY": TEST_KEY}):
            result = events.process_deliveries(
                db, now=NOW, limit=1, sender=sender, delivery_clock=lambda: NOW,
                monotonic_clock=lambda: 0)
        self.assertEqual(result, {"claimed": 1, "delivered": 1, "retry": 0,
                                  "dead": 0, "paused": 0})
        self.assertEqual(db.final_status, "delivered")
        self.assertEqual(observed["event_id"], self.event_id)
        self.assertEqual(observed["delivery_id"], self.delivery_id)
        self.assertEqual(observed["now"], NOW)

    def test_retryable_status_uses_bounded_backoff(self):
        db, result = self.run_delivery(lambda *_args, **_kwargs: 500)
        self.assertEqual((result["retry"], db.final_status), (1, "retry"))
        self.assertEqual(db.final_next_attempt, NOW + timedelta(seconds=60))

    def test_nonretryable_status_is_dead_and_410_pauses_endpoint(self):
        db, result = self.run_delivery(lambda *_args, **_kwargs: 400)
        self.assertEqual((result["dead"], db.final_status, db.endpoint_status),
                         (1, "dead", "active"))
        db, result = self.run_delivery(lambda *_args, **_kwargs: 410)
        self.assertEqual((result["dead"], result["paused"], db.final_status,
                          db.endpoint_status), (1, 1, "dead", "paused"))
        self.assertTrue(any("status='cancelled'" in query
                            and "endpoint_id=%s" in query
                            for query, _params in db.calls))

    def test_network_delivery_error_retries_but_invalid_target_is_dead(self):
        def network(*_args, **_kwargs):
            raise outbound_webhooks.DeliveryError(
                "delivery_failed", "não foi possível entregar o webhook")

        db, result = self.run_delivery(network)
        self.assertEqual((result["retry"], db.final_status), (1, "retry"))

        def invalid(*_args, **_kwargs):
            raise outbound_webhooks.TargetValidationError(
                "address_not_public", "destino de webhook inválido")

        db, result = self.run_delivery(invalid)
        self.assertEqual((result["dead"], result["paused"], db.final_status,
                          db.endpoint_status), (1, 1, "dead", "paused"))

    def test_temporary_dns_and_encryption_availability_errors_are_retried(self):
        for error in (
                outbound_webhooks.TargetValidationError(
                    "dns_failed", "não foi possível validar o destino"),
                events.IntegrationEventError(
                    "A criptografia das integrações não está configurada.",
                    "encryption_not_configured", 503)):
            with self.subTest(code=error.code):
                def unavailable(*_args, **_kwargs):
                    raise error

                db, result = self.run_delivery(unavailable)
                self.assertEqual((result["retry"], result["dead"], db.final_status,
                                  db.endpoint_status), (1, 0, "retry", "active"))

    def test_base_webhook_error_is_contained_and_pauses_bad_configuration(self):
        def invalid_secret(*_args, **_kwargs):
            raise outbound_webhooks.WebhookError(
                "invalid_secret", "segredo de webhook inválido")

        db, result = self.run_delivery(invalid_secret)
        self.assertEqual((result["dead"], result["paused"], db.final_status,
                          db.endpoint_status), (1, 1, "dead", "paused"))

    def test_unexpected_sender_failure_is_sanitized_and_does_not_abort_batch(self):
        def broken_sender(*_args, **_kwargs):
            raise RuntimeError("https://secret.example/private?token=do-not-log")

        db, result = self.run_delivery(broken_sender)
        self.assertEqual((result["retry"], db.final_status, db.endpoint_status),
                         (1, "retry", "active"))
        final_update = next(params for query, params in db.calls
                            if query.startswith("UPDATE integration_webhook_deliveries SET status=%s,"))
        self.assertEqual(final_update[3], "delivery_exception")
        self.assertNotIn("secret.example", str(db.calls))

    def test_expired_running_leases_are_recovered_before_claim(self):
        db, _ = self.run_delivery(lambda *_args, **_kwargs: 204)
        recovery = next(call for call in db.calls
                        if "WHERE status='running' AND leased_at<%s" in call[0])
        self.assertIn("WHERE status='running' AND leased_at<%s", recovery[0])
        self.assertEqual(recovery[1][2], NOW - events.LEASE_TIMEOUT)
        self.assertTrue(any("lease_expired_max_attempts" in query
                            for query, _params in db.calls))
        claim = next(query for query, _params in db.calls
                     if query.startswith("WITH candidate AS"))
        self.assertIn("o.status='active' AND o.plan='Equipe'", claim)
        self.assertIn("o.permissions->'workspace_read'", claim)

    def test_cleanup_history_is_bounded_and_committed(self):
        class CleanupDB:
            def __init__(self):
                self.calls, self.commits = [], 0

            def execute(self, query, params=None):
                compact = " ".join(query.split())
                self.calls.append((compact, params))
                count = 2 if "DELETE FROM integration_webhook_deliveries" in compact else 1
                return Result(many=[{"id": index} for index in range(count)])

            def commit(self):
                self.commits += 1

        db = CleanupDB()
        result = events.cleanup_history(db, now=NOW, limit=250)
        self.assertEqual(result, {"deliveries": 2, "events": 1, "endpoints": 1})
        self.assertEqual(db.commits, 1)
        self.assertTrue(all(params[1] == 250 for _query, params in db.calls))
        self.assertTrue(any("NOT EXISTS" in query for query, _params in db.calls))

    def test_batch_budget_is_checked_before_claiming_another_delivery(self):
        db = DeliveryDB(self.delivery, self.endpoint)
        ticks = iter((100.0, 121.0))
        result = events.process_deliveries(
            db, now=NOW, limit=20, sender=lambda *_args, **_kwargs: 204,
            delivery_clock=lambda: NOW, monotonic_clock=lambda: next(ticks),
            batch_budget_seconds=20)
        self.assertEqual(result, {"claimed": 0, "delivered": 0, "retry": 0,
                                  "dead": 0, "paused": 0})
        self.assertFalse(db.claimed)


if __name__ == "__main__":
    unittest.main()
