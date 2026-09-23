import os
import tempfile
import unittest
from unittest.mock import patch

from scripts import invoke_scheduler


class SchedulerInvokerTests(unittest.TestCase):
    def test_oidc_url_gets_dedicated_audience(self):
        value = invoke_scheduler.oidc_request_url(
            "https://pipelines.actions.githubusercontent.com/token?id=one&audience=old")
        self.assertIn("audience=pulseflow-worker", value)
        self.assertNotIn("audience=old", value)
        for unsafe in (
            "http://pipelines.actions.githubusercontent.com/token",
            "https://actions.githubusercontent.com.evil.example/token",
            "https://example.com/token",
        ):
            with self.assertRaises(invoke_scheduler.InvocationError):
                invoke_scheduler.oidc_request_url(unsafe)

    def test_acquires_token_without_logging_or_persisting_it(self):
        token = "header.payload.signature"
        env = {
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/token?id=one",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runtime-only",
        }
        with patch.dict(os.environ, env, clear=False), \
                patch.object(invoke_scheduler, "_json_request", return_value={"value": token}) as request:
            self.assertEqual(invoke_scheduler.acquire_oidc_token(), token)
        called_url = request.call_args.args[0]
        self.assertIn("audience=pulseflow-worker", called_url)
        self.assertEqual(request.call_args.kwargs["bearer"], "runtime-only")

    def test_invocation_is_one_long_non_retried_post(self):
        success = {"ok": True, "tenantsScanned": 4, "actionsCreated": 2}
        with patch.object(invoke_scheduler, "_json_request", return_value=success) as request:
            self.assertEqual(invoke_scheduler.invoke_scheduler("jwt"), success)
        request.assert_called_once_with(
            invoke_scheduler.SCHEDULER_URL, bearer="jwt", method="POST", timeout=120)

    def test_uncertain_post_is_never_retried(self):
        with patch.object(invoke_scheduler, "_json_request",
                          side_effect=invoke_scheduler.InvocationError("temporary")) as request:
            with self.assertRaises(invoke_scheduler.InvocationError):
                invoke_scheduler.invoke_scheduler("jwt")
        self.assertEqual(request.call_count, 1)

    def test_main_summary_contains_counts_but_never_token(self):
        with tempfile.NamedTemporaryFile(delete=False) as output:
            path = output.name
        try:
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": path}, clear=False), \
                    patch.object(invoke_scheduler, "acquire_oidc_token", return_value="private.jwt.token"), \
                    patch.object(invoke_scheduler, "invoke_scheduler", return_value={
                        "ok": True, "tenantsScanned": 3, "actionsCreated": 1
                    }):
                self.assertEqual(invoke_scheduler.main(), 0)
            with open(path, encoding="utf-8") as summary:
                contents = summary.read()
            self.assertIn("3 conta(s), 1 ação(ões)", contents)
            self.assertNotIn("private.jwt.token", contents)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
