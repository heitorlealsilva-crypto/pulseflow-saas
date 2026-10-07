"""Plan changes keep one-owner Base access; no database or network is used."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys
import types
import unittest
import uuid

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


class Cursor:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def fetchone(self):
        return copy.deepcopy(self.rows[0]) if self.rows else None

    def fetchall(self):
        return copy.deepcopy(self.rows)


class TeamDatabase:
    """Small stateful fake supporting only the exercised account/user queries."""
    def __init__(self, accounts, users, sessions):
        self.accounts = copy.deepcopy(accounts)
        self.users = copy.deepcopy(users)
        self.sessions = dict(sessions)
        self.audits = []
        self.queries = []
        self.commits = 0

    def execute(self, query, params=()):
        sql = " ".join(query.split())
        self.queries.append((sql, params))
        if sql.startswith("SELECT id,name,plan,status,permissions FROM organizations"):
            account = self.accounts.get(str(params[0]))
            return Cursor([account] if account else [])
        if sql.startswith("UPDATE organizations SET status="):
            status, plan, permissions, org = params
            self.accounts[str(org)].update(status=status, plan=plan, permissions=json.loads(permissions))
            return Cursor()
        if sql.startswith("UPDATE users SET status='suspended'"):
            changed = []
            for person in self.users.values():
                if person["organization_id"] == str(params[0]) and person["role"] == "member" and person["status"] == "active":
                    person["status"] = "suspended"
                    changed.append({"id": person["id"]})
            return Cursor(changed)
        if sql.startswith("DELETE FROM sessions WHERE user_id IN"):
            org = str(params[0])
            member_only = "role='member'" in sql
            affected = {person["id"] for person in self.users.values()
                        if person["organization_id"] == org and (not member_only or person["role"] == "member")}
            return Cursor(self.remove_sessions(affected))
        if sql.startswith("DELETE FROM sessions WHERE user_id="):
            return Cursor(self.remove_sessions({str(params[0])}))
        if sql.startswith("UPDATE integration_webhook_"):
            return Cursor()
        if sql.startswith("INSERT INTO audit_logs"):
            actor, org, action, metadata = params
            self.audits.append({"actor": actor, "organization_id": org,
                                "action": action, "metadata": json.loads(metadata)})
            return Cursor()
        if sql.startswith("SELECT id,organization_id,role,status FROM users WHERE id="):
            person = self.users.get(str(params[0]))
            return Cursor([person] if person else [])
        if sql.startswith("SELECT COUNT(*)::int AS count FROM users"):
            org, excluded = map(str, params)
            return Cursor([{"count": sum(person["organization_id"] == org
                            and person["status"] == "active" and person["id"] != excluded
                            for person in self.users.values())}])
        if sql.startswith("UPDATE users SET status=%s"):
            self.users[str(params[1])]["status"] = params[0]
            return Cursor()
        if sql.startswith("SELECT u.* FROM sessions s JOIN users"):
            person = self.users.get(self.sessions.get(params[0]))
            if not person or person["status"] != "active":
                return Cursor()
            account = self.accounts.get(person["organization_id"])
            if person["role"] == "super_admin" or account and account["status"] == "active":
                return Cursor([person])
            return Cursor()
        raise AssertionError("Unexpected test query: " + sql)

    def remove_sessions(self, user_ids):
        removed = []
        for key, user_id in list(self.sessions.items()):
            if user_id in user_ids:
                removed.append({"user_id": user_id})
                del self.sessions[key]
        return removed

    def commit(self):
        self.commits += 1


class TeamPlanTests(unittest.TestCase):
    def setUp(self):
        self.org, self.other_org = str(uuid.uuid4()), str(uuid.uuid4())
        self.admin = {"id": str(uuid.uuid4()), "role": "super_admin"}
        self.owner, self.member, self.member2, self.paused, self.other, self.linked_admin = [str(uuid.uuid4()) for _ in range(6)]
        people = [(self.owner, self.org, "owner", "active"),
                  (self.member, self.org, "member", "active"),
                  (self.member2, self.org, "member", "active"),
                  (self.paused, self.org, "member", "suspended"),
                  (self.other, self.other_org, "member", "active"),
                  (self.linked_admin, self.org, "super_admin", "active")]
        users = {key: {"id": key, "organization_id": org, "role": role, "status": status}
                 for key, org, role, status in people}
        accounts = {org: {"id": org, "name": "Test account", "plan": "Equipe",
                           "status": "active", "permissions": {}}
                    for org in (self.org, self.other_org)}
        self.tokens = {key: "test-session-" + key for key in users}
        sessions = {hashlib.sha256(self.tokens[key].encode()).hexdigest(): key for key in users}
        sessions[hashlib.sha256(b"second-member-session").hexdigest()] = self.member
        self.db = TeamDatabase(accounts, users, sessions)
        self.handler = auth.handler.__new__(auth.handler)
        self.handler.reply = lambda status, payload: (status, payload)

    def change_plan(self, plan, **extra):
        return self.handler.update_account(self.db, self.admin,
                                          {"organization_id": self.org, "plan": plan, **extra})

    def status(self, user_id, status="active"):
        return self.handler.update_user(self.db, self.admin, {"user_id": user_id, "status": status})

    def test_downgrade_preserves_owner_and_admin_and_suspends_only_own_members(self):
        status, response = self.change_plan("Base")
        self.assertEqual((status, response["account"]["plan"]), (200, "Base"))
        self.assertEqual(self.db.users[self.owner]["status"], "active")
        self.assertEqual(self.db.users[self.linked_admin]["status"], "active")
        self.assertEqual(self.db.users[self.other]["status"], "active")
        for key in (self.member, self.member2, self.paused):
            self.assertEqual(self.db.users[key]["status"], "suspended")
        self.assertEqual(set(self.db.sessions.values()), {self.owner, self.linked_admin, self.other})
        self.assertEqual(self.db.accounts[self.other_org]["plan"], "Equipe")
        self.assertEqual(self.db.commits, 1)

    def test_audit_records_affected_members_and_session_count_without_credentials(self):
        self.change_plan("Base")
        event = next(item for item in self.db.audits if item["action"] == "team.access.restricted_to_owner")
        self.assertEqual(event["actor"], self.admin["id"])
        self.assertEqual(event["organization_id"], self.org)
        self.assertEqual(event["metadata"], {"previous_plan": "Equipe", "plan": "Base",
            "suspended_user_ids": sorted([self.member, self.member2]), "revoked_sessions": 4})
        self.assertEqual(self.db.audits[-1]["action"], "admin.account.updated")
        self.assertNotIn("test-session", json.dumps(self.db.audits))

    def test_existing_member_session_stops_working_immediately_owner_session_survives(self):
        self.handler.headers = {"Cookie": "pulseflow_session=" + self.tokens[self.member]}
        self.assertEqual(self.handler.current_user(self.db)["id"], self.member)
        self.change_plan("Base")
        self.assertIsNone(self.handler.current_user(self.db))
        self.handler.headers = {"Cookie": "pulseflow_session=" + self.tokens[self.owner]}
        self.assertEqual(self.handler.current_user(self.db)["id"], self.owner)

    def test_reapplying_base_repairs_legacy_active_members(self):
        self.db.accounts[self.org]["plan"] = "Base"
        self.change_plan("Base")
        self.assertEqual(self.db.users[self.member]["status"], "suspended")
        event = next(item for item in self.db.audits if item["action"] == "team.access.restricted_to_owner")
        self.assertEqual(event["metadata"]["previous_plan"], "Base")

    def test_upgrade_does_not_automatically_restore_suspended_members(self):
        self.change_plan("Base")
        self.change_plan("Equipe")
        self.assertEqual(self.db.users[self.member]["status"], "suspended")
        self.assertNotIn(self.member, self.db.sessions.values())

    def test_member_reactivation_cannot_bypass_base_limit_via_admin_route(self):
        self.change_plan("Base")
        before = self.db.commits
        with self.assertRaises(auth.RequestError) as caught:
            self.status(self.member)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.db.users[self.member]["status"], "suspended")
        self.assertEqual(self.db.commits, before)

    def test_owner_can_be_reactivated_on_base(self):
        self.change_plan("Base")
        self.db.users[self.owner]["status"] = "suspended"
        self.assertEqual(self.status(self.owner)[0], 200)
        self.assertEqual(self.db.users[self.owner]["status"], "active")

    def test_admin_reactivation_enforces_three_active_users_and_locks_account_first(self):
        with self.assertRaises(auth.RequestError) as caught:
            self.status(self.paused)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(self.db.users[self.paused]["status"], "suspended")
        locks = [query for query, _ in self.db.queries if "FOR UPDATE" in query]
        self.assertIn("FROM organizations", locks[0])
        self.assertIn("FROM users", locks[1])

    def test_reactivation_after_upgrade_requires_available_seat(self):
        self.change_plan("Base")
        self.change_plan("Equipe")
        self.assertEqual(self.status(self.member)[0], 200)
        self.assertEqual(self.db.users[self.member]["status"], "active")
        with self.assertRaises(auth.RequestError) as caught:
            self.status(self.member2)
        self.assertEqual(caught.exception.status, 409)

    def test_permission_edit_keeps_existing_team_access(self):
        before = dict(self.db.sessions)
        self.handler.update_account(self.db, self.admin,
            {"organization_id": self.org, "permissions": {"whatsapp_manage": False}})
        self.assertEqual(self.db.users[self.member]["status"], "active")
        self.assertEqual(self.db.sessions, before)
        self.assertFalse(any(item["action"] == "team.access.restricted_to_owner" for item in self.db.audits))

    def test_global_admin_access_cannot_be_changed_via_member_action(self):
        with self.assertRaises(auth.RequestError) as caught:
            self.status(self.linked_admin, "suspended")
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(self.db.users[self.linked_admin]["status"], "active")


if __name__ == "__main__":
    unittest.main()
