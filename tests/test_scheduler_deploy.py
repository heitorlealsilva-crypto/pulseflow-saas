from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class SchedulerDeployContractTests(unittest.TestCase):
    def test_workflow_is_frequent_oidc_only_and_never_handles_cron_secret(self):
        workflow = (ROOT / ".github/workflows/pulseflow-worker.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "*/30 * * * *"', workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("timeout-minutes: 5", workflow)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("actions/checkout@v", workflow)
        self.assertNotIn("CRON_SECRET", workflow)
        self.assertNotIn("pull_request", workflow)

    def test_vercel_daily_fallback_remains_configured(self):
        vercel = (ROOT / "vercel.json").read_text(encoding="utf-8")
        self.assertIn('"path": "/api/worker"', vercel)
        self.assertIn('"schedule": "0 10 * * *"', vercel)


if __name__ == "__main__":
    unittest.main()
