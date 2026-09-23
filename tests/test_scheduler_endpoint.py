import io
import importlib
import sys
import types
import unittest
from unittest.mock import MagicMock, patch


# This contract test does not need a database driver.  Production installs it
# from requirements.txt; lightweight CI jobs can still validate the handler.
auth_stub = types.ModuleType("api.auth")
auth_stub.connect = None
worker_stub = types.ModuleType("api.worker")
worker_stub.run_batch = None
with patch.dict(sys.modules, {"api.auth": auth_stub, "api.worker": worker_stub}):
    scheduler = importlib.import_module("api.scheduler")


class SchedulerEndpointTests(unittest.TestCase):
    def request(self, *, authorized=True, batch=None, method="POST"):
        instance = scheduler.handler.__new__(scheduler.handler)
        instance.headers = {"Authorization": "Bearer test"}
        instance.wfile = io.BytesIO()
        instance.send_response = MagicMock()
        instance.send_header = MagicMock()
        instance.end_headers = MagicMock()
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        with patch.object(scheduler, "authorized", return_value=authorized), \
                patch.object(scheduler, "connect", return_value=connection), \
                patch.object(scheduler, "run_batch", return_value=batch or {
                    "ok": True, "tenantsScanned": 2, "actionsCreated": 1
                }) as run:
            getattr(instance, "do_" + method)()
        status = instance.send_response.call_args.args[0]
        return status, instance.wfile.getvalue().decode(), run, connection

    def test_post_requires_valid_oidc_before_opening_database(self):
        status, body, run, connection = self.request(authorized=False)
        self.assertEqual(status, 401)
        self.assertIn("não autorizado", body)
        run.assert_not_called()
        connection.__enter__.assert_not_called()

    def test_valid_oidc_runs_existing_idempotent_worker(self):
        status, body, run, connection = self.request()
        self.assertEqual(status, 200)
        self.assertIn('"actionsCreated": 1', body)
        run.assert_called_once_with(connection)

    def test_get_never_runs_scheduler(self):
        status, body, run, _ = self.request(method="GET")
        self.assertEqual(status, 405)
        self.assertIn("método não permitido", body)
        run.assert_not_called()

    def test_internal_failures_are_sanitized(self):
        instance = scheduler.handler.__new__(scheduler.handler)
        instance.headers = {"Authorization": "Bearer test"}
        instance.wfile = io.BytesIO()
        instance.send_response = MagicMock()
        instance.send_header = MagicMock()
        instance.end_headers = MagicMock()
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        with patch.object(scheduler, "authorized", return_value=True), \
                patch.object(scheduler, "connect", return_value=connection), \
                patch.object(scheduler, "run_batch", side_effect=RuntimeError("private database detail")):
            instance.do_POST()
        self.assertEqual(instance.send_response.call_args.args[0], 503)
        body = instance.wfile.getvalue().decode()
        self.assertNotIn("private database detail", body)
        self.assertIn("temporariamente indisponível", body)


if __name__ == "__main__":
    unittest.main()
