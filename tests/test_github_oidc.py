import base64
import json
import unittest
from unittest.mock import call, patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from api import github_oidc


def encoded(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class GitHubOIDCTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = self.private.public_key().public_numbers()
        b64int = lambda value: base64.urlsafe_b64encode(
            value.to_bytes((value.bit_length() + 7) // 8, "big")
        ).rstrip(b"=").decode()
        self.keys = [{"kid": "test-key", "kty": "RSA", "use": "sig",
                      "n": b64int(numbers.n), "e": b64int(numbers.e)}]
        repository = github_oidc.DEFAULT_REPOSITORY
        self.claims = {
            "iss": github_oidc.ISSUER,
            "aud": github_oidc.AUDIENCE,
            "sub": f"repo:{repository}:ref:refs/heads/main",
            "repository": repository,
            "workflow_ref": f"{repository}/{github_oidc.WORKFLOW_PATH}@refs/heads/main",
            "ref": "refs/heads/main",
            "ref_type": "branch",
            "event_name": "schedule",
            "iat": self.now - 10,
            "nbf": self.now - 10,
            "exp": self.now + 300,
        }

    def token(self, changes=None, signer=None):
        claims = {**self.claims, **(changes or {})}
        header = encoded({"alg": "RS256", "typ": "JWT", "kid": "test-key"})
        payload = encoded(claims)
        signature = (signer or self.private).sign(
            f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{payload}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"

    def test_accepts_only_the_committed_main_workflow(self):
        self.assertTrue(github_oidc.verify_token(self.token(), self.now, self.keys))
        for changes in (
            {"aud": "another-service"},
            {"repository": "someone/else"},
            {"workflow_ref": "heitorlealsilva-crypto/pulseflow-saas/.github/workflows/other.yml@refs/heads/main"},
            {"ref": "refs/heads/feature"},
            {"event_name": "pull_request"},
            {"exp": self.now - 60},
            {"iat": self.now - 901},
        ):
            self.assertFalse(github_oidc.verify_token(self.token(changes), self.now, self.keys), changes)

    def test_rejects_invalid_signature_or_algorithm(self):
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.assertFalse(github_oidc.verify_token(self.token(signer=other), self.now, self.keys))
        parts = self.token().split(".")
        parts[0] = encoded({"alg": "none", "kid": "test-key"})
        self.assertFalse(github_oidc.verify_token(".".join(parts), self.now, self.keys))

    def test_authorization_reads_only_a_bearer_token(self):
        token = self.token()
        with patch.object(github_oidc, "verify_token", return_value=True) as verify:
            self.assertTrue(github_oidc.authorized({"Authorization": "Bearer " + token}))
            verify.assert_called_once_with(token)
        self.assertFalse(github_oidc.authorized({"Authorization": "Basic anything"}))

    def test_unknown_cached_kid_forces_one_jwks_refresh(self):
        stale = [{**self.keys[0], "kid": "previous-key"}]
        with patch.object(github_oidc, "_keys", side_effect=[stale, self.keys]) as loader:
            self.assertTrue(github_oidc.verify_token(self.token(), self.now))
        self.assertEqual(loader.call_args_list, [call(self.now), call(self.now, force=True)])

    def test_forced_key_refresh_has_a_cooldown(self):
        old = dict(github_oidc._CACHE)
        try:
            github_oidc._CACHE.update(
                expires=self.now + 3600, refresh_after=self.now + 60,
                jwks_uri="https://token.actions.githubusercontent.com/.well-known/jwks",
                keys=self.keys)
            with patch.object(github_oidc, "_fetch_json") as fetch:
                self.assertIs(github_oidc._keys(self.now, force=True), self.keys)
                fetch.assert_not_called()
        finally:
            github_oidc._CACHE.clear()
            github_oidc._CACHE.update(old)

    def test_bad_claims_are_rejected_before_network_lookup(self):
        with patch.object(github_oidc, "_keys") as loader:
            self.assertFalse(github_oidc.verify_token(
                self.token({"repository": "attacker/repository"}), self.now))
            loader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
