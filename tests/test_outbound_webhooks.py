import hashlib
import hmac
import ipaddress
import json
import os
import socket
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from api import outbound_webhooks as webhooks


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


def resolver_for(*addresses):
    def resolve(hostname, port, **_kwargs):
        return list(addresses)
    return resolve


class TargetValidationTests(unittest.TestCase):
    def test_accepts_https_443_and_returns_only_resolved_public_ips(self):
        target = webhooks.validate_target(
            "https://hooks.example.com:443/pulseflow/events",
            resolver=resolver_for(PUBLIC_V4, PUBLIC_V6, PUBLIC_V4),
        )
        self.assertEqual(target.hostname, "hooks.example.com")
        self.assertEqual(target.port, 443)
        self.assertEqual(target.path, "/pulseflow/events")
        self.assertEqual(target.addresses, (PUBLIC_V4, PUBLIC_V6))

    def test_idna_hostname_is_canonicalized_before_resolution(self):
        seen = []

        def resolve(hostname, port, **_kwargs):
            seen.append((hostname, port))
            return [PUBLIC_V4]

        target = webhooks.validate_target("https://exämple.com/webhook", resolver=resolve)
        self.assertEqual(target.hostname, "xn--exmple-cua.com")
        self.assertEqual(seen, [("xn--exmple-cua.com", 443)])

    def test_rejects_unsafe_url_shapes_before_dns(self):
        unsafe = (
            "http://hooks.example.com/webhook",
            "https://hooks.example.com:8443/webhook",
            "https://user@hooks.example.com/webhook",
            "https://user:password@hooks.example.com/webhook",
            "https://hooks.example.com/webhook?token=secret",
            "https://hooks.example.com/webhook#fragment",
            "https://93.184.216.34/webhook",
            "https://[2606:2800:220:1:248:1893:25c8:1946]/webhook",
            "https://single-label/webhook",
            "https://hooks_example.com/webhook",
            "https://hooks.example.com/%0d%0aInjected:true",
        )
        for url in unsafe:
            with self.subTest(url=url), self.assertRaises(webhooks.TargetValidationError):
                webhooks.validate_target(url, resolver=lambda *_args, **_kwargs: self.fail("DNS called"))

    def test_rejects_local_metadata_and_own_application_hosts(self):
        unsafe = (
            "https://localhost.localdomain/webhook",
            "https://service.internal/webhook",
            "https://device.local/webhook",
            "https://metadata.google.internal/webhook",
            "https://metadata.example.com/webhook",
            "https://host.docker.internal/webhook",
        )
        for url in unsafe:
            with self.subTest(url=url), self.assertRaises(webhooks.TargetValidationError):
                webhooks.validate_target(url, resolver=resolver_for(PUBLIC_V4))
        with self.assertRaises(webhooks.TargetValidationError) as caught:
            webhooks.validate_target(
                "https://pulseflow.example.com/webhook",
                app_url="https://pulseflow.example.com/",
                resolver=resolver_for(PUBLIC_V4),
            )
        self.assertEqual(caught.exception.code, "self_target")

    def test_rejects_every_non_global_address_and_ipv4_mapped_private_address(self):
        unsafe = (
            "127.0.0.1", "0.0.0.0", "10.0.0.1", "172.16.0.1",
            "192.168.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.1",
            "::1", "::", "fc00::1", "fe80::1", "2001:db8::1", "::ffff:10.0.0.1",
        )
        for address in unsafe:
            with self.subTest(address=address), self.assertRaises(webhooks.TargetValidationError):
                webhooks.validate_target(
                    "https://hooks.example.com/webhook", resolver=resolver_for(address))

    def test_rejects_mixed_public_private_dns_answers(self):
        with self.assertRaises(webhooks.TargetValidationError) as caught:
            webhooks.validate_target(
                "https://hooks.example.com/webhook",
                resolver=resolver_for(PUBLIC_V4, "10.0.0.9"),
            )
        self.assertEqual(caught.exception.code, "address_not_public")

    def test_dns_errors_are_sanitized(self):
        secret_text = "https://secret.example.com/hook/sensitive"

        def broken(*_args, **_kwargs):
            raise OSError(secret_text)

        with self.assertRaises(webhooks.TargetValidationError) as caught:
            webhooks.validate_target("https://hooks.example.com/webhook", resolver=broken)
        self.assertNotIn(secret_text, str(caught.exception))

    def test_rejects_excessive_dns_fanout_after_validating_every_answer(self):
        many_public = [f"8.8.8.{value}" for value in range(1, 10)]
        with self.assertRaises(webhooks.TargetValidationError) as caught:
            webhooks.validate_target(
                "https://hooks.example.com/webhook",
                resolver=resolver_for(*many_public),
            )
        self.assertEqual(caught.exception.code, "dns_too_many_addresses")

        # A private answer must not be hidden after the connection-attempt cap.
        with self.assertRaises(webhooks.TargetValidationError) as caught:
            webhooks.validate_target(
                "https://hooks.example.com/webhook",
                resolver=resolver_for(*many_public, "10.0.0.1"),
            )
        self.assertEqual(caught.exception.code, "address_not_public")


class SignatureTests(unittest.TestCase):
    def test_hmac_sha256_signature_has_stable_versioned_vector(self):
        secret = b"a" * 32
        timestamp = "1789992000"
        body = json.dumps({"mensagem": "Olá"}, ensure_ascii=False,
                          separators=(",", ":")).encode()
        expected = hmac.new(secret, timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
        self.assertEqual(webhooks.sign_payload(secret, timestamp, body), "v1=" + expected)
        self.assertNotEqual(webhooks.sign_payload(secret, timestamp, body + b" "), "v1=" + expected)
        self.assertNotEqual(webhooks.sign_payload(secret, "1789992001", body), "v1=" + expected)

    def test_signature_rejects_empty_secrets_bad_timestamps_and_non_bytes_body(self):
        invalid = (
            (b"", "1", b"{}"),
            (b"secret", "1.2", b"{}"),
            (b"secret", "-1", b"{}"),
            (b"secret", "1", "{}"),
        )
        for secret, timestamp, body in invalid:
            with self.subTest(timestamp=timestamp, body_type=type(body)), self.assertRaises(webhooks.WebhookError):
                webhooks.sign_payload(secret, timestamp, body)


class FakeResponse:
    def __init__(self, status=204, body=b"ok", content_length=None):
        self.status = status
        self.body = body
        self.content_length = content_length

    def getheader(self, name):
        return self.content_length if name == "Content-Length" else None

    def read(self, amount):
        return self.body[:amount]


class RecordingConnection:
    instances = []
    responses = []
    failures = []

    def __init__(self, hostname, address, timeout=webhooks.CONNECT_TIMEOUT_SECONDS):
        self.hostname = hostname
        self.address = address
        self.timeout = timeout
        self.request_value = None
        self.closed = False
        self.__class__.instances.append(self)

    def request(self, method, path, body=None, headers=None):
        self.request_value = (method, path, body, headers)
        if self.__class__.failures:
            error = self.__class__.failures.pop(0)
            if error:
                raise error

    def getresponse(self):
        return self.__class__.responses.pop(0) if self.__class__.responses else FakeResponse()

    def close(self):
        self.closed = True


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        RecordingConnection.instances = []
        RecordingConnection.responses = []
        RecordingConnection.failures = []

    def test_delivery_uses_pinned_ip_host_header_sni_identity_and_signed_headers(self):
        body = b'{"event":"contact.updated"}'
        now = datetime(2026, 9, 23, 3, 0, tzinfo=timezone.utc)
        timestamp = str(int(now.timestamp()))
        with patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                patch.dict(os.environ, {}, clear=True):
            result = webhooks.deliver(
                "https://hooks.example.com/inbound", b"s" * 32,
                "evt-123", "del-456", "contact.updated", body,
                now=now, resolver=resolver_for(PUBLIC_V4),
            )
        self.assertEqual(result, webhooks.DeliveryResult(204, 2))
        connection = RecordingConnection.instances[0]
        self.assertEqual((connection.hostname, connection.address), ("hooks.example.com", PUBLIC_V4))
        method, path, sent_body, headers = connection.request_value
        self.assertEqual((method, path, sent_body), ("POST", "/inbound", body))
        self.assertEqual(headers["Host"], "hooks.example.com")
        self.assertEqual(headers["X-PulseFlow-Event-Id"], "evt-123")
        self.assertEqual(headers["X-PulseFlow-Delivery-Id"], "del-456")
        self.assertEqual(headers["X-PulseFlow-Event-Type"], "contact.updated")
        self.assertEqual(headers["X-PulseFlow-Timestamp"], timestamp)
        self.assertEqual(headers["X-PulseFlow-Signature"],
                         webhooks.sign_payload(b"s" * 32, timestamp, body))
        self.assertTrue(connection.closed)

    def test_pinned_connection_connects_to_numeric_ip_but_uses_hostname_for_tls(self):
        calls = {}

        class FakeSocket:
            def settimeout(self, value):
                calls["timeout"] = value

            def connect(self, destination):
                calls["destination"] = destination

            def close(self):
                calls["closed"] = True

        class FakeContext:
            def wrap_socket(self, sock, server_hostname=None):
                calls["server_hostname"] = server_hostname
                calls["socket"] = sock
                return "tls-socket"

        with patch.object(webhooks.socket, "socket", return_value=FakeSocket()), \
                patch.object(webhooks.ssl, "create_default_context", return_value=FakeContext()):
            connection = webhooks._PinnedHTTPSConnection("hooks.example.com", PUBLIC_V4)
            connection.connect()
        self.assertEqual(calls["destination"], (PUBLIC_V4, 443))
        self.assertEqual(calls["server_hostname"], "hooks.example.com")
        self.assertEqual(connection.sock, "tls-socket")

    def test_redirect_is_returned_and_never_followed(self):
        RecordingConnection.responses = [FakeResponse(status=302, body=b"", content_length="0")]
        with patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                patch.dict(os.environ, {}, clear=True):
            result = webhooks.deliver(
                "https://hooks.example.com/inbound", b"s" * 32,
                "evt-1", "del-1", "contact.updated", b"{}",
                now=1, resolver=resolver_for(PUBLIC_V4),
            )
        self.assertEqual(result.status_code, 302)
        self.assertEqual(len(RecordingConnection.instances), 1)

    def test_falls_back_only_to_another_already_validated_ip(self):
        RecordingConnection.failures = [OSError("network failure"), None]
        with patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                patch.dict(os.environ, {}, clear=True):
            result = webhooks.deliver(
                "https://hooks.example.com/inbound", b"s" * 32,
                "evt-1", "del-1", "contact.updated", b"{}",
                now=1, resolver=resolver_for(PUBLIC_V4, PUBLIC_V6),
            )
        self.assertEqual(result.status_code, 204)
        self.assertEqual([item.address for item in RecordingConnection.instances], [PUBLIC_V4, PUBLIC_V6])

    def test_all_pinned_addresses_share_one_delivery_time_budget(self):
        RecordingConnection.failures = [OSError("network failure"), None]
        with patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                patch.object(webhooks.time, "monotonic", side_effect=[100, 100.1, 113]), \
                patch.dict(os.environ, {}, clear=True), \
                self.assertRaises(webhooks.DeliveryError) as caught:
            webhooks.deliver(
                "https://hooks.example.com/inbound", b"s" * 32,
                "evt-1", "del-1", "contact.updated", b"{}",
                now=1, resolver=resolver_for(PUBLIC_V4, PUBLIC_V6),
            )
        self.assertEqual(caught.exception.code, "delivery_failed")
        self.assertEqual([item.address for item in RecordingConnection.instances], [PUBLIC_V4])
        self.assertLessEqual(RecordingConnection.instances[0].timeout,
                             webhooks.DELIVERY_ATTEMPT_BUDGET_SECONDS)

    def test_response_size_is_bounded_without_returning_the_response_body(self):
        RecordingConnection.responses = [FakeResponse(
            status=200, body=b"secret response", content_length=str(webhooks.MAX_RESPONSE_BYTES + 1))]
        with patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                patch.dict(os.environ, {}, clear=True), \
                self.assertRaises(webhooks.DeliveryError) as caught:
            webhooks.deliver(
                "https://hooks.example.com/inbound", b"s" * 32,
                "evt-1", "del-1", "contact.updated", b"{}",
                now=1, resolver=resolver_for(PUBLIC_V4),
            )
        self.assertEqual(caught.exception.code, "response_too_large")
        self.assertNotIn("secret response", str(caught.exception))

    def test_delivery_errors_never_echo_url_secret_body_or_low_level_exception(self):
        sensitive = "TOP-SECRET-CONTENT"
        RecordingConnection.failures = [OSError(sensitive)]
        with patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                patch.dict(os.environ, {}, clear=True), \
                self.assertRaises(webhooks.DeliveryError) as caught:
            webhooks.deliver(
                "https://hooks.example.com/sensitive-path", sensitive,
                "evt-1", "del-1", "contact.updated", sensitive.encode(),
                now=1, resolver=resolver_for(PUBLIC_V4),
            )
        self.assertEqual(caught.exception.code, "delivery_failed")
        self.assertNotIn(sensitive, str(caught.exception))
        self.assertNotIn("sensitive-path", str(caught.exception))

    def test_environment_application_url_blocks_self_delivery(self):
        with patch.dict(os.environ, {"PULSEFLOW_APP_URL": "https://pulseflow.example.com"}, clear=True), \
                patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                self.assertRaises(webhooks.TargetValidationError) as caught:
            webhooks.deliver(
                "https://pulseflow.example.com/hook", b"s" * 32,
                "evt-1", "del-1", "contact.updated", b"{}",
                now=1, resolver=resolver_for(PUBLIC_V4),
            )
        self.assertEqual(caught.exception.code, "self_target")
        self.assertEqual(RecordingConnection.instances, [])

    def test_header_injection_and_oversized_body_are_rejected_before_network(self):
        cases = (
            {"event_id": "evt\r\nInjected:true", "raw_body": b"{}"},
            {"event_id": "evt-1", "raw_body": b"x" * (webhooks.MAX_PAYLOAD_BYTES + 1)},
        )
        for values in cases:
            with self.subTest(values={"event_id": values["event_id"], "size": len(values["raw_body"])}), \
                    patch.object(webhooks, "_PinnedHTTPSConnection", RecordingConnection), \
                    self.assertRaises(webhooks.WebhookError):
                webhooks.deliver(
                    "https://hooks.example.com/hook", b"s" * 32,
                    values["event_id"], "del-1", "contact.updated", values["raw_body"],
                    now=1, resolver=lambda *_args, **_kwargs: self.fail("DNS called"),
                )


if __name__ == "__main__":
    unittest.main()
