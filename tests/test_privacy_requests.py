"""Privacy request intake is real, scoped, and never deletes data automatically."""
import importlib
import sys
import types
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    import psycopg  # noqa: F401
except ImportError:
    stub = types.ModuleType("psycopg")
    stub.errors = types.SimpleNamespace(UniqueViolation=type("UniqueViolation", (Exception,), {}))
    stub.rows = types.ModuleType("psycopg.rows")
    stub.rows.dict_row = None
    sys.modules["psycopg"] = stub
    sys.modules["psycopg.rows"] = stub.rows

auth = importlib.import_module("api.auth")


class PrivacyRequestTests(unittest.TestCase):
    def setUp(self):
        self.handler = auth.handler.__new__(auth.handler)
        self.handler.reply = lambda status, body: (status, body)
        self.handler.rate_limit = MagicMock()
        self.handler.audit = MagicMock()
        self.db = MagicMock()
        self.org_id = str(uuid.uuid4())
        self.user_id = str(uuid.uuid4())
        self.owner = {"id": self.user_id, "organization_id": self.org_id,
                      "role": "owner", "email": "owner@example.test"}

    def insert_params(self):
        return next(call.args[1] for call in self.db.execute.call_args_list
                    if "INSERT INTO privacy_requests" in call.args[0])

    def test_public_request_returns_protocol_without_account_lookup(self):
        status, body = self.handler.create_privacy_request(self.db, {
            "email": "  Person@Example.test  ", "company": "Minha Empresa",
            "scope": "meta_data", "details": "Excluir dados recebidos da Meta."})
        self.assertEqual(status, 201)
        self.assertEqual(str(uuid.UUID(body["protocol"])), body["protocol"])
        self.assertIn("Nenhuma exclusão foi iniciada", body["message"])
        params = self.insert_params()
        self.assertEqual(params[1:8], (None, None, "public", "meta_data",
                                       "person@example.test", "Minha Empresa",
                                       "Excluir dados recebidos da Meta."))
        self.assertFalse(params[8])
        self.handler.rate_limit.assert_called_once_with(self.db, "privacy_request", "person@example.test")
        self.handler.audit.assert_not_called()
        self.assertFalse(any("SELECT" in call.args[0].upper() for call in self.db.execute.call_args_list))
        self.db.commit.assert_called_once()

    def test_public_request_validation_does_not_enumerate_accounts(self):
        for payload in ({"email": "bad", "scope": "meta_data"},
                        {"email": "person@example.test", "scope": []},
                        {"email": "person@example.test", "scope": "organization", "details": "x" * 2001}):
            with self.assertRaises(auth.RequestError):
                self.handler.create_privacy_request(self.db, payload)
        self.assertFalse(any("INSERT INTO privacy_requests" in call.args[0]
                             for call in self.db.execute.call_args_list))

    def test_public_rate_limit_has_ip_and_email_buckets(self):
        limited = auth.handler.__new__(auth.handler)
        limited.client_ip = lambda: "203.0.113.10"
        cursors = [MagicMock(), MagicMock(), MagicMock()]
        cursors[0].fetchone.return_value = {"attempts": 1}
        cursors[1].fetchone.return_value = {"attempts": 4}
        self.db.execute.side_effect = cursors
        with self.assertRaises(auth.RequestError) as caught:
            limited.rate_limit(self.db, "privacy_request", "person@example.test")
        self.assertEqual(caught.exception.status, 429)
        self.assertEqual(len(self.db.execute.call_args_list), 3)
        self.assertNotEqual(self.db.execute.call_args_list[0].args[1][0],
                            self.db.execute.call_args_list[1].args[1][0])
        self.db.commit.assert_called_once()

    def test_ip_ignores_generic_forwarded_header(self):
        limited = auth.handler.__new__(auth.handler)
        limited.client_address = ("127.0.0.1", 1234)
        limited.headers = {"X-Forwarded-For": "1.2.3.4",
                           "X-Vercel-Forwarded-For": "203.0.113.10"}
        with patch.dict(auth.os.environ, {"VERCEL": ""}):
            self.assertEqual(limited.client_ip(), "127.0.0.1")
        with patch.dict(auth.os.environ, {"VERCEL": "1"}):
            self.assertEqual(limited.client_ip(), "203.0.113.10")

    def test_authenticated_request_uses_session_identity_not_payload(self):
        self.handler.account = lambda db, org: {"name": "Empresa real"}
        status, _ = self.handler.create_privacy_request(self.db, {
            "scope": "organization", "details": "Quero revisar a exclusão.",
            "email": "attacker@example.test", "organization_id": str(uuid.uuid4()),
            "company": "Empresa falsa"}, self.owner)
        self.assertEqual(status, 201)
        params = self.insert_params()
        self.assertEqual(params[1:8], (self.org_id, self.user_id, "authenticated",
                                       "organization", "owner@example.test", "Empresa real",
                                       "Quero revisar a exclusão."))
        self.assertTrue(params[8])
        self.handler.audit.assert_called_once()

    def test_member_cannot_request_whole_tenant_or_meta_data(self):
        member = {**self.owner, "role": "member"}
        for scope in ("organization", "meta_data"):
            with self.assertRaises(auth.RequestError) as caught:
                self.handler.create_privacy_request(self.db, {"scope": scope}, member)
            self.assertEqual(caught.exception.status, 403)
        self.db.execute.assert_not_called()

    def test_member_may_request_own_account(self):
        self.handler.account = lambda db, org: {"name": "Empresa real"}
        member = {**self.owner, "role": "member"}
        self.assertEqual(self.handler.create_privacy_request(
            self.db, {"scope": "own_account"}, member)[0], 201)
        self.assertEqual(self.insert_params()[4], "own_account")

    def test_public_post_dispatch_does_not_require_a_session(self):
        payload = {"email": "person@example.test", "scope": "own_account"}
        self.handler.action = lambda: "privacy-request-public"
        self.handler.body = lambda: payload
        self.handler.check_origin = MagicMock()
        self.handler.current_user = MagicMock(side_effect=AssertionError("session lookup"))
        self.handler.create_privacy_request = MagicMock(return_value=(201, {"ok": True}))
        with patch.object(auth, "connect") as connect, patch.object(auth, "ensure_schema"):
            connect.return_value.__enter__.return_value = self.db
            self.assertEqual(self.handler.do_POST(), (201, {"ok": True}))
        self.handler.check_origin.assert_called_once()
        self.handler.current_user.assert_not_called()
        self.handler.create_privacy_request.assert_called_once_with(self.db, payload)

    def test_tenant_list_is_only_for_signed_in_requester(self):
        self.handler.action = lambda: "privacy-requests"
        self.handler.current_user = lambda db: self.owner
        self.db.execute.return_value.fetchall.return_value = []
        with patch.object(auth, "connect") as connect, patch.object(auth, "ensure_schema"):
            connect.return_value.__enter__.return_value = self.db
            status, body = self.handler.do_GET()
        self.assertEqual((status, body), (200, {"ok": True, "requests": []}))
        query, params = self.db.execute.call_args.args
        self.assertIn("WHERE requester_user_id=%s", query)
        self.assertEqual(params, (self.user_id,))

    def test_non_admin_cannot_list_global_queue(self):
        self.handler.action = lambda: "admin-privacy-requests"
        self.handler.current_user = lambda db: self.owner
        with patch.object(auth, "connect") as connect, patch.object(auth, "ensure_schema"):
            connect.return_value.__enter__.return_value = self.db
            status, body = self.handler.do_GET()
        self.assertEqual(status, 403)
        self.assertFalse(body["ok"])
        self.db.execute.assert_not_called()

    def test_admin_must_verify_public_request_before_resolution(self):
        request_id = str(uuid.uuid4())
        self.db.execute.return_value.fetchone.return_value = {
            "id": request_id, "organization_id": None, "scope": "meta_data",
            "status": "pending", "identity_verified_at": None}
        admin = {"id": str(uuid.uuid4()), "role": "super_admin"}
        with self.assertRaises(auth.RequestError) as caught:
            self.handler.update_privacy_request(self.db, admin, {
                "request_id": request_id, "operation": "resolve",
                "note": "Pedido atendido manualmente."})
        self.assertEqual(caught.exception.status, 409)
        self.db.commit.assert_not_called()
        self.handler.audit.assert_not_called()

    def test_explicit_reverification_cannot_be_bypassed(self):
        request_id = str(uuid.uuid4())
        self.db.execute.return_value.fetchone.return_value = {
            "id": request_id, "organization_id": self.org_id, "scope": "organization",
            "status": "needs_verification", "identity_verified_at": datetime.now(timezone.utc)}
        with self.assertRaises(auth.RequestError) as caught:
            self.handler.update_privacy_request(self.db,
                {"id": str(uuid.uuid4()), "role": "super_admin"},
                {"request_id": request_id, "operation": "resolve",
                 "note": "Tratamento manual concluído e documentado."})
        self.assertEqual(caught.exception.status, 409)
        self.db.commit.assert_not_called()

    def test_admin_verification_and_resolution_are_audited_not_purged(self):
        request_id = str(uuid.uuid4())
        admin = {"id": str(uuid.uuid4()), "role": "super_admin"}
        self.db.execute.return_value.fetchone.return_value = {
            "id": request_id, "organization_id": self.org_id, "scope": "organization",
            "status": "needs_verification", "identity_verified_at": None}
        status, body = self.handler.update_privacy_request(self.db, admin, {
            "request_id": request_id, "operation": "verify",
            "note": "Identidade conferida com a pessoa solicitante."})
        self.assertEqual((status, body["status"]), (200, "verified"))
        self.assertIn("não executou exclusão automática", body["message"])
        self.assertFalse(any("DELETE FROM" in call.args[0].upper()
                             for call in self.db.execute.call_args_list))
        self.handler.audit.assert_called_once()
        self.assertNotIn("Identidade conferida", str(self.handler.audit.call_args))

        self.db.reset_mock()
        self.handler.audit.reset_mock()
        self.db.execute.return_value.fetchone.return_value = {
            "id": request_id, "organization_id": self.org_id, "scope": "organization",
            "status": "verified", "identity_verified_at": datetime.now(timezone.utc)}
        status, body = self.handler.update_privacy_request(self.db, admin, {
            "request_id": request_id, "operation": "resolve",
            "note": "Tratamento manual registrado no protocolo."})
        self.assertEqual((status, body["status"]), (200, "resolved"))
        self.assertFalse(any("DELETE FROM" in call.args[0].upper()
                             for call in self.db.execute.call_args_list))
        self.handler.audit.assert_called_once()
        self.assertNotIn("Tratamento manual", str(self.handler.audit.call_args))

    def test_terminal_request_cannot_be_reopened(self):
        request_id = str(uuid.uuid4())
        self.db.execute.return_value.fetchone.return_value = {
            "id": request_id, "organization_id": None, "scope": "other",
            "status": "resolved", "identity_verified_at": datetime.now(timezone.utc)}
        with self.assertRaises(auth.RequestError) as caught:
            self.handler.update_privacy_request(self.db,
                {"id": str(uuid.uuid4()), "role": "super_admin"},
                {"request_id": request_id, "operation": "acknowledge"})
        self.assertEqual(caught.exception.status, 409)
        self.db.commit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
