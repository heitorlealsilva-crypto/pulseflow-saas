"""Deterministic tests for the tenant-scoped CRM integration API.

These tests exercise validation and data-plane guarantees without opening a
database connection or making a network request.
"""
import hashlib
import json
import sys
import types
import unittest
import uuid
from copy import deepcopy
from unittest.mock import patch

try:
    import psycopg  # noqa: F401
except ImportError:
    stub = types.ModuleType("psycopg")
    stub.errors = types.SimpleNamespace(UniqueViolation=type("UniqueViolation", (Exception,), {}))
    stub.rows = types.ModuleType("psycopg.rows")
    stub.rows.dict_row = None
    sys.modules["psycopg"] = stub
    sys.modules["psycopg.rows"] = stub.rows
from api import integrations


class ScriptedDB:
    """Small query-aware fake for ``handler.upsert_contact``."""

    def __init__(self, *, cached=None, workspace=None, organization_status="active"):
        self.cached = cached
        self.workspace = deepcopy(workspace) if workspace is not None else None
        self.organization_status = organization_status
        self.calls = []
        self.current = None
        self.commits = 0
        self.saved_workspace = None

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        self.current = None
        if "SELECT request_hash,response FROM integration_requests" in compact:
            self.current = self.cached
        elif "SELECT status FROM organizations" in compact:
            self.current = {"status": self.organization_status}
        elif "SELECT state,revision FROM tenant_workspaces" in compact:
            self.current = self.workspace
        elif "INSERT INTO tenant_workspaces" in compact:
            self.saved_workspace = json.loads(params[1])
        elif "INSERT INTO integration_events" in compact:
            self.current = {"id": 41, "created_at": "2026-09-20T12:00:00+00:00"}
        return self

    def fetchone(self):
        return self.current

    def commit(self):
        self.commits += 1


class KeyDB:
    def __init__(self, row):
        self.row = row
        self.calls = []

    def execute(self, query, params=None):
        self.calls.append((" ".join(query.split()), params))
        return self

    def fetchone(self):
        return self.row


class CreateKeyDB:
    def __init__(self):
        self.calls = []
        self.current = None
        self.insert_params = None
        self.commits = 0

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        if "SELECT COUNT(*)::int AS count" in compact:
            self.current = {"count": 0}
        elif "INSERT INTO integration_api_keys" in compact:
            self.insert_params = params
            self.current = {
                "id": params[0],
                "name": params[3],
                "token_prefix": params[5],
                "scopes": json.loads(params[6]),
                "last_used_at": None,
                "created_at": "2026-09-20T12:00:00+00:00",
                # A database RETURNING change must not make these public.
                "token_hash": params[4],
                "organization_id": params[1],
                "revoked_at": None,
            }
        else:
            self.current = None
        return self

    def fetchone(self):
        return self.current

    def commit(self):
        self.commits += 1


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.handler = integrations.handler.__new__(integrations.handler)
        self.handler.reply = lambda status, value: (status, value)
        self.organization_id = str(uuid.uuid4())
        self.api_key = {"id": str(uuid.uuid4()), "organization_id": self.organization_id}

    def valid_contact(self, **changes):
        value = {
            "request_id": str(uuid.uuid4()),
            "external_id": "crm-42",
            "name": "Ana Silva",
        }
        value.update(changes)
        return value

    def test_phone_normalization_accepts_local_and_international_formats(self):
        self.assertEqual(integrations.normalize_phone("(11) 99999-9999"), "5511999999999")
        self.assertEqual(integrations.normalize_phone("+55 (11) 99999-9999"), "5511999999999")
        self.assertEqual(integrations.normalize_phone(" 351 912 345 678 "), "351912345678")
        self.assertEqual(integrations.normalize_phone(None), "")
        self.assertEqual(integrations.normalize_phone(""), "")

    def test_phone_normalization_rejects_unsafe_or_impossible_values(self):
        for value in ("1199999", "0011999999999", "+55 11 CALL-ME", "1" * 16, [], True):
            with self.subTest(value=value), self.assertRaises(integrations.IntegrationAPIError) as caught:
                integrations.normalize_phone(value)
            self.assertEqual(caught.exception.code, "invalid_contact")

    def test_contact_validation_normalizes_and_bounds_all_supported_fields(self):
        request_id = str(uuid.uuid4())
        result = self.handler.validate_contact({
            "request_id": request_id,
            "external_id": "  crm-42  ",
            "name": "  Ana Silva  ",
            "phone": "(11) 99999-9999",
            "email": " ANA@Example.COM ",
            "source": " Indicação ",
            "interest": "media",
            "tags": ["VIP", "VIP", "Retorno"],
            "notes": " Prefere contato à tarde. ",
            "board": "Remarketing",
            "stage": "waiting:reply",
            "contract_value": 1490.5,
            "product": " Plano premium ",
            "niche": " Clínica ",
            "revenue": 250000,
            "discard_reason": " Sem orçamento neste mês ",
            "recovery_at": "2099-01-10T09:00:00-03:00",
        })
        self.assertEqual(result, {
            "request_id": request_id,
            "external_id": "crm-42",
            "name": "Ana Silva",
            "phone": "5511999999999",
            "email": "ana@example.com",
            "source": "Indicação",
            "interest": "Média",
            "tags": ["VIP", "Retorno"],
            "notes": "Prefere contato à tarde.",
            "board": "Remarketing",
            "stage": "waiting:reply",
            "contract_value": 1490.5,
            "product": "Plano premium",
            "niche": "Clínica",
            "revenue": 250000,
            "discard_reason": "Sem orçamento neste mês",
            "recovery_at": "2099-01-10T12:00:00+00:00",
        })

    def test_contact_validation_rejects_bad_field_shapes_and_limits(self):
        invalid_changes = (
            {"request_id": "not-a-uuid"},
            {"external_id": ""},
            {"name": "x" * 161},
            {"email": "not-an-email"},
            {"interest": "urgente"},
            {"tags": "vip"},
            {"tags": ["x"] * 21},
            {"board": "Funil secreto"},
            {"stage": "nome com espaços"},
            {"contract_value": -1},
            {"contract_value": True},
            {"revenue": 1_000_000_000_001},
            {"recovery_at": "2099-01-10T09:00:00"},
            {"recovery_at": "amanhã"},
            {"notes": "bad\x00value"},
        )
        for changes in invalid_changes:
            with self.subTest(changes=changes), self.assertRaises(integrations.IntegrationAPIError) as caught:
                self.handler.validate_contact(self.valid_contact(**changes))
            self.assertIn(caught.exception.code, ("invalid_contact", "invalid_request"))

    def test_unexpected_fields_are_reported_and_security_flags_cannot_be_written(self):
        payload = self.valid_contact(
            organization_id=self.organization_id,
            consent_confirmed=True,
            automation_paused=False,
        )
        with self.assertRaises(integrations.IntegrationAPIError) as caught:
            self.handler.validate_contact(payload)
        self.assertEqual(caught.exception.code, "unexpected_fields")
        self.assertEqual(
            caught.exception.details["fields"],
            ["automation_paused", "consent_confirmed", "organization_id"],
        )

    def test_public_key_has_scopes_but_never_hash_or_tenant_metadata(self):
        row = {
            "id": "key-1",
            "name": "ERP",
            "token_prefix": "pfk_abcdefgh",
            "token_hash": "top-secret-hash",
            "organization_id": self.organization_id,
            "created_by": "owner-1",
            "scopes": ["contacts:read"],
            "last_used_at": None,
            "created_at": "today",
            "revoked_at": None,
        }
        value = integrations.public_key(row)
        self.assertEqual(value["scopes"], ["contacts:read"])
        self.assertEqual(set(value), {"id", "name", "token_prefix", "scopes", "last_used_at", "created_at"})
        self.assertNotIn("top-secret-hash", json.dumps(value))
        self.assertNotIn(self.organization_id, json.dumps(value))

    def test_create_key_sorts_scopes_and_persists_only_token_digest(self):
        db = CreateKeyDB()
        owner = {"id": str(uuid.uuid4()), "role": "owner", "organization_id": self.organization_id}
        self.handler.management_org = lambda *_args, **_kwargs: self.organization_id
        self.handler.audit = lambda *_args, **_kwargs: None
        token_body = "A" * 43
        with patch.object(integrations.secrets, "token_urlsafe", return_value=token_body):
            status, response = self.handler.create_key(db, owner, {
                "name": "CRM principal",
                "scopes": ["events:read", "contacts:read", "contacts:read"],
            })
        raw_token = "pfk_" + token_body
        self.assertEqual(status, 201)
        self.assertEqual(response["key"]["token"], raw_token)
        self.assertEqual(response["key"]["scopes"], ["contacts:read", "events:read"])
        self.assertNotIn("token_hash", response["key"])
        self.assertEqual(db.insert_params[4], hashlib.sha256(raw_token.encode()).hexdigest())
        self.assertNotIn(raw_token, json.dumps(db.insert_params, default=str))
        self.assertEqual(db.commits, 1)

    def test_create_key_rejects_invalid_or_empty_scopes(self):
        owner = {"id": str(uuid.uuid4()), "role": "owner", "organization_id": self.organization_id}
        self.handler.management_org = lambda *_args, **_kwargs: self.organization_id
        for scopes in ([], "contacts:read", ["admin:all"], ["contacts:read"] * 4):
            with self.subTest(scopes=scopes), self.assertRaises(integrations.IntegrationAPIError) as caught:
                self.handler.create_key(CreateKeyDB(), owner, {"name": "ERP", "scopes": scopes})
            self.assertEqual(caught.exception.code, "invalid_scopes")

    def test_create_key_defaults_to_read_only(self):
        db = CreateKeyDB()
        owner = {"id": str(uuid.uuid4()), "role": "owner", "organization_id": self.organization_id}
        self.handler.management_org = lambda *_args, **_kwargs: self.organization_id
        self.handler.audit = lambda *_args, **_kwargs: None
        status, response = self.handler.create_key(db, owner, {"name": "Consulta externa"})
        self.assertEqual(status, 201)
        self.assertEqual(response["key"]["scopes"], ["contacts:read"])

    def test_api_key_authentication_derives_tenant_and_checks_scope(self):
        token = "pfk_" + "B" * 43
        row = {
            "id": "key-1",
            "organization_id": self.organization_id,
            "organization_status": "active",
            "scopes": ["contacts:write"],
        }
        db = KeyDB(row)
        self.handler.headers = {"Authorization": "Bearer " + token}
        authenticated = self.handler.api_key(db, "contacts:write")
        self.assertEqual(authenticated["organization_id"], self.organization_id)
        select_call = next(call for call in db.calls if "WHERE k.token_hash=%s" in call[0])
        self.assertEqual(select_call[1], (hashlib.sha256(token.encode()).hexdigest(),))
        self.assertTrue(any("SET last_used_at=NOW()" in query for query, _ in db.calls))

        with self.assertRaises(integrations.IntegrationAPIError) as caught:
            self.handler.api_key(KeyDB(row), "contacts:read")
        self.assertEqual((caught.exception.code, caught.exception.status), ("insufficient_scope", 403))

        blocked = {**row, "organization_permissions": {"workspace_write": False}}
        with self.assertRaises(integrations.IntegrationAPIError) as caught:
            self.handler.api_key(KeyDB(blocked), "contacts:write")
        self.assertEqual((caught.exception.code, caught.exception.status), ("permission_denied", 403))

    def test_only_super_admin_can_manage_keys_on_a_suspended_account(self):
        row = {"id": self.organization_id, "status": "suspended", "permissions": {}}
        admin = {"id": str(uuid.uuid4()), "role": "super_admin", "organization_id": None}
        owner = {"id": str(uuid.uuid4()), "role": "owner", "organization_id": self.organization_id}
        self.assertEqual(
            self.handler.management_org(
                KeyDB(row), admin, self.organization_id, allow_suspended=True),
            self.organization_id,
        )
        for user, allow_suspended in ((admin, False), (owner, True)):
            with self.subTest(role=user["role"], allow_suspended=allow_suspended), self.assertRaises(
                    integrations.IntegrationAPIError) as caught:
                self.handler.management_org(
                    KeyDB(row), user, self.organization_id,
                    allow_suspended=allow_suspended,
                )
            self.assertEqual(caught.exception.code, "account_unavailable")

    def test_idempotent_replay_is_scoped_to_key_tenant(self):
        payload = self.valid_contact(phone="11999999999")
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        cached_response = {"ok": True, "created": True, "contact": {"id": "lead-1"}}
        db = ScriptedDB(cached={
            "request_hash": hashlib.sha256(canonical.encode()).hexdigest(),
            "response": cached_response,
        })
        status, response = self.handler.upsert_contact(db, self.api_key, payload)
        self.assertEqual(status, 200)
        self.assertTrue(response["idempotent_replay"])
        request_call = next(call for call in db.calls if "FROM integration_requests" in call[0])
        self.assertEqual(request_call[1], (self.organization_id, payload["request_id"]))
        lock_call = next(call for call in db.calls if "pg_advisory_xact_lock" in call[0])
        self.assertEqual(lock_call[1], (f"integration:{self.organization_id}:{payload['request_id']}",))
        self.assertFalse(any("tenant_workspaces" in query for query, _ in db.calls))
        self.assertEqual(db.commits, 1)

    def test_reusing_request_id_with_different_body_is_a_conflict(self):
        payload = self.valid_contact(name="Primeiro valor")
        db = ScriptedDB(cached={"request_hash": "different-body-hash", "response": {"ok": True}})
        with self.assertRaises(integrations.IntegrationAPIError) as caught:
            self.handler.upsert_contact(db, self.api_key, payload)
        self.assertEqual((caught.exception.code, caught.exception.status), ("idempotency_conflict", 409))
        self.assertEqual(db.commits, 0)
        self.assertFalse(any("tenant_workspaces" in query for query, _ in db.calls))

    def test_opted_out_contact_cannot_be_reactivated_or_moved_by_integration(self):
        lead = {
            "id": "lead-1",
            "integrationKeyId": self.api_key["id"],
            "integrationExternalId": "crm-42",
            "name": "Nome antigo",
            "phone": "5511988887777",
            "board": "Abandonados",
            "stage": "discarded",
            "optOut": True,
            "automationPaused": False,
            "consentConfirmed": True,
        }
        db = ScriptedDB(workspace={"state": {"leads": [lead]}, "revision": 7})
        payload = self.valid_contact(
            name="Nome atualizado",
            board="Principal",
            stage="new",
            phone="11999999999",
        )
        status, response = self.handler.upsert_contact(db, self.api_key, payload)
        saved = db.saved_workspace["leads"][0]
        self.assertEqual(status, 200)
        self.assertFalse(response["created"])
        self.assertEqual(saved["name"], "Nome atualizado")
        self.assertEqual((saved["board"], saved["stage"]), ("Abandonados", "discarded"))
        self.assertTrue(saved["optOut"])
        self.assertTrue(saved["automationPaused"])
        self.assertTrue(saved["consentConfirmed"])
        self.assertTrue(response["contact"]["opt_out"])
        tenant_queries = [params for query, params in db.calls
                          if ("organizations WHERE id=%s" in query or "tenant_workspaces" in query)
                          and params]
        self.assertTrue(tenant_queries)
        self.assertTrue(all(params[0] == self.organization_id for params in tenant_queries))

    def test_external_id_survives_api_key_rotation(self):
        lead = {
            "id": "lead-1",
            "integrationKeyId": str(uuid.uuid4()),
            "integrationExternalId": "crm-42",
            "name": "Antes da rotação",
            "board": "Principal",
            "stage": "new",
        }
        db = ScriptedDB(workspace={"state": {"leads": [lead]}, "revision": 2})
        status, response = self.handler.upsert_contact(
            db, self.api_key, self.valid_contact(name="Depois da rotação"))
        self.assertEqual(status, 200)
        self.assertFalse(response["created"])
        self.assertEqual(len(db.saved_workspace["leads"]), 1)
        self.assertEqual(db.saved_workspace["leads"][0]["name"], "Depois da rotação")
        self.assertEqual(db.saved_workspace["leads"][0]["integrationKeyId"], self.api_key["id"])

    def test_abandoned_pipeline_requires_recovery_context(self):
        with self.assertRaises(integrations.IntegrationAPIError) as caught:
            self.handler.upsert_contact(
                ScriptedDB(), self.api_key,
                self.valid_contact(board="Abandonados", stage="new"))
        self.assertEqual(caught.exception.code, "recovery_required")

        db = ScriptedDB()
        status, response = self.handler.upsert_contact(db, self.api_key, self.valid_contact(
            board="Abandonados", stage="new", product="Consulta",
            discard_reason="Sem orçamento", recovery_at="2099-01-10T12:00:00Z",
        ))
        self.assertEqual(status, 201)
        self.assertEqual(response["contact"]["discard_reason"], "Sem orçamento")
        self.assertEqual(response["contact"]["recovery_at"], "2099-01-10T12:00:00+00:00")
        self.assertEqual(response["contact"]["product"], "Consulta")

    def test_public_contact_recognizes_all_existing_opt_out_flags(self):
        for field in ("optOut", "opt_out", "doNotContact"):
            with self.subTest(field=field):
                value = integrations.public_contact({"id": "lead-1", field: True})
                self.assertTrue(value["opt_out"])
        value = integrations.public_contact({"id": "lead-1", "messages": [{"body": "private"}]})
        self.assertNotIn("messages", value)
        self.assertNotIn("private", json.dumps(value))


if __name__ == "__main__":
    unittest.main()
