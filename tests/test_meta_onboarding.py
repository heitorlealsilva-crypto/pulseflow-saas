"""Deterministic security tests for Meta OAuth onboarding."""
import hashlib
import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api import meta_onboarding as meta


ENV = {
    "PULSEFLOW_APP_URL": "https://app.example.test",
    "PULSEFLOW_ENCRYPTION_KEY": "test-only-encryption-key-at-least-32-chars",
    "META_APP_ID": "123456789012345",
    "META_APP_SECRET": "server-only-meta-app-secret-123456",
    "META_EMBEDDED_SIGNUP_CONFIG_ID": "987654321098765",
    "META_WEBHOOK_VERIFY_TOKEN": "server-only-webhook-token-1234567890",
    "META_GRAPH_VERSION": "v23.0",
}


class Cursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class FlowDB:
    def __init__(self):
        self.flow = None
        self.used = False
        self.calls = []
        self.commits = 0

    def execute(self, query, params=None):
        compact = " ".join(query.split())
        self.calls.append((compact, params))
        if compact.startswith("SELECT COUNT(*) AS count"):
            return Cursor({"count": 0})
        if compact.startswith("INSERT INTO meta_onboarding_flows"):
            (flow_id, organization_id, user_id, session_hash, state_hash,
             return_path, verifier_enc, expires_at) = params
            self.flow = {
                "id": flow_id, "organization_id": organization_id,
                "user_id": user_id, "session_hash": session_hash,
                "state_hash": state_hash, "return_path": return_path,
                "code_verifier_enc": verifier_enc, "expires_at": expires_at,
                "status": "pending",
            }
            return Cursor()
        if compact.startswith("UPDATE meta_onboarding_flows SET used_at=NOW()"):
            state_hash, session_hash = params
            if (self.flow and not self.used and self.flow["state_hash"] == state_hash
                    and self.flow["session_hash"] == session_hash):
                self.used = True
                self.flow.update(status="exchanging", used_at=datetime.now(timezone.utc))
                return Cursor(dict(self.flow))
            return Cursor(None)
        return Cursor()

    def commit(self):
        self.commits += 1


class MetaOnboardingTests(unittest.TestCase):
    def test_missing_server_configuration_fails_honestly(self):
        with patch.dict(os.environ, {}, clear=True):
            value = meta.public_configuration()
            self.assertFalse(value["ready"])
            self.assertEqual(value["code"], "meta_app_not_configured")
            self.assertIn("META_APP_SECRET", value["missing"])
            with self.assertRaises(meta.OnboardingError) as caught:
                meta.oauth_config()
        self.assertEqual(caught.exception.code, "meta_app_not_configured")

    def test_return_location_never_becomes_an_open_redirect(self):
        with patch.dict(os.environ, ENV, clear=True):
            self.assertEqual(meta.safe_return_path("/settings?tab=whatsapp"),
                             "/settings?tab=whatsapp")
            self.assertEqual(meta.safe_return_path(
                "https://app.example.test/?meta_onboarding=return"),
                "/?meta_onboarding=return")
            for value in ("https://evil.example/x", "//evil.example/x", "javascript:alert(1)",
                          "/ok\r\nLocation:https://evil.example"):
                self.assertEqual(meta.safe_return_path(value), "/")

    def test_start_flow_binds_hashed_state_to_tenant_user_and_session(self):
        db = FlowDB()
        organization_id, user_id = str(uuid.uuid4()), str(uuid.uuid4())
        session_hash = hashlib.sha256(b"browser-session").hexdigest()
        with patch.dict(os.environ, {**ENV, "META_OAUTH_PKCE_ENABLED": "true"}, clear=True):
            result = meta.start_flow(db, organization_id, user_id, session_hash,
                                     "/settings?tab=whatsapp")
        self.assertNotIn("authorization_url", result)
        self.assertEqual(result["app_id"], ENV["META_APP_ID"])
        self.assertEqual(result["config_id"], ENV["META_EMBEDDED_SIGNUP_CONFIG_ID"])
        self.assertEqual(result["graph_version"], ENV["META_GRAPH_VERSION"])
        self.assertNotIn(ENV["META_WEBHOOK_VERIFY_TOKEN"], json.dumps(result, default=str))
        self.assertEqual(db.flow["organization_id"], organization_id)
        self.assertEqual(db.flow["user_id"], user_id)
        self.assertEqual(db.flow["session_hash"], session_hash)
        self.assertEqual(db.flow["state_hash"], hashlib.sha256(result["state"].encode()).hexdigest())
        self.assertNotEqual(db.flow["state_hash"], result["state"])
        self.assertNotIn(result["state"], str(db.flow["code_verifier_enc"]))

    def test_state_is_single_use_and_requires_the_same_session(self):
        db = FlowDB()
        with patch.dict(os.environ, ENV, clear=True):
            started = meta.start_flow(db, str(uuid.uuid4()), str(uuid.uuid4()), "session-a")
        with self.assertRaises(meta.OnboardingError) as wrong_session:
            meta.consume_state(db, started["state"], "session-b")
        self.assertEqual(wrong_session.exception.code, "invalid_oauth_state")
        consumed = meta.consume_state(db, started["state"], "session-a")
        self.assertEqual(consumed["id"], started["flow_id"])
        with self.assertRaises(meta.OnboardingError) as replay:
            meta.consume_state(db, started["state"], "session-a")
        self.assertEqual(replay.exception.code, "invalid_oauth_state")

    def test_public_status_never_contains_any_secret(self):
        with patch.dict(os.environ, ENV, clear=True):
            value = meta.public_configuration()
        serialized = json.dumps(value)
        self.assertTrue(value["ready"])
        self.assertIn(ENV["META_APP_ID"], serialized)
        for secret in (ENV["META_APP_SECRET"], ENV["META_WEBHOOK_VERIFY_TOKEN"],
                       ENV["PULSEFLOW_ENCRYPTION_KEY"]):
            self.assertNotIn(secret, serialized)

    def test_asset_selection_is_reported_as_actionable_not_endless_pending(self):
        class StatusDB:
            def execute(self, _query, _params=None):
                return Cursor({"id": str(uuid.uuid4()), "status": "asset_selection_required",
                               "error_code": None, "expires_at": datetime.now(timezone.utc),
                               "created_at": datetime.now(timezone.utc)})
        with patch.dict(os.environ, ENV, clear=True):
            value = meta.status_payload(StatusDB(), str(uuid.uuid4()), "session")
        self.assertEqual(value["onboarding"]["status"], "failed")
        self.assertIn("mais de um ativo", value["onboarding"]["error"])


if __name__ == "__main__":
    unittest.main()
