import unittest
from datetime import datetime, timedelta, timezone

from api import runtime


class RuntimeEventTests(unittest.TestCase):
    def setUp(self):
        self.at = datetime(2026, 9, 21, 12, tzinfo=timezone.utc)

    def test_inbound_reply_pauses_existing_lead_and_is_idempotent(self):
        workspace = {"leads": [{
            "id": "l1", "name": "Ana", "phone": "(11) 91234-5678",
            "automationPaused": False,
        }], "manualApprovals": [
            {"id": "a1", "leadId": "l1", "status": "pending"},
            {"id": "a2", "leadId": "other", "status": "pending"},
            {"id": "a3", "leadId": "l1", "status": "pending", "kind": "appointment"},
        ]}
        lead, changed = runtime.apply_inbound_response(
            workspace, message_id="wamid-1", phone="5511912345678", name="Ana",
            body="Tenho interesse", occurred_at=self.at)
        self.assertTrue(changed)
        self.assertEqual(len(workspace["leads"]), 1)
        self.assertEqual(lead["id"], "l1")
        self.assertTrue(lead["automationPaused"])
        self.assertEqual(lead["lastReplyId"], "wamid-1")
        self.assertEqual(workspace["manualApprovals"][0]["status"], "superseded")
        self.assertEqual(workspace["manualApprovals"][1]["status"], "pending")
        self.assertEqual(workspace["manualApprovals"][2]["status"], "pending")
        _, changed = runtime.apply_inbound_response(
            workspace, message_id="wamid-1", phone="5511912345678", name="Ana",
            body="Tenho interesse", occurred_at=self.at)
        self.assertFalse(changed)

    def test_unknown_inbound_creates_safe_unsolicited_contact(self):
        workspace = {}
        lead, changed = runtime.apply_inbound_response(
            workspace, message_id="wamid-2", phone="5511987654321", name="Bia",
            body="Olá", occurred_at=self.at)
        self.assertTrue(changed)
        self.assertEqual(lead["origin"], "WhatsApp")
        self.assertFalse(lead["consentConfirmed"])
        self.assertTrue(lead["automationPaused"])
        self.assertEqual(lead["messages"], [])

    def test_delayed_webhook_never_regresses_latest_reply(self):
        workspace = {"leads": [{
            "id": "l1", "name": "Ana", "phone": "5511912345678",
            "lastReplyId": "newer", "lastReplyAt": self.at.isoformat(),
            "lastContactAt": self.at.isoformat(), "last": "Mensagem nova",
        }]}
        lead, changed = runtime.apply_inbound_response(
            workspace, message_id="older", phone="5511912345678", name="Ana",
            body="Mensagem antiga", occurred_at=self.at - timedelta(hours=3))
        self.assertFalse(changed)
        self.assertEqual(lead["lastReplyId"], "newer")
        self.assertEqual(lead["last"], "Mensagem nova")

    def test_column_can_keep_cadence_active_after_reply(self):
        workspace = {
            "columns": [{"id": "new", "automations": {"pauseOnReply": False}}],
            "leads": [{"id": "l1", "name": "Ana", "phone": "5511912345678",
                       "stage": "new", "board": "Principal", "automationPaused": False}],
            "manualApprovals": [{"leadId": "l1", "status": "pending"}],
        }
        lead, changed = runtime.apply_inbound_response(
            workspace, message_id="wamid-3", phone="5511912345678", name="Ana",
            body="Pode continuar", occurred_at=self.at)
        self.assertTrue(changed)
        self.assertFalse(lead["automationPaused"])
        self.assertEqual(workspace["manualApprovals"][0]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
