"""Small, SSRF-resistant transport for outbound PulseFlow webhooks.

This module deliberately owns only destination validation, signing and one
HTTP delivery attempt. Persistence, retries and delivery policy belong to the
worker. No function logs request URLs, secrets, payloads or response bodies.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import quote, unquote_to_bytes, urlsplit


CONNECT_TIMEOUT_SECONDS = 8
DELIVERY_ATTEMPT_BUDGET_SECONDS = 12
MAX_RESPONSE_BYTES = 16_384
MAX_PAYLOAD_BYTES = 262_144
MAX_URL_LENGTH = 2_048
MAX_RESOLVED_ADDRESSES = 8
_HEADER_VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_BLOCKED_HOSTS = frozenset({
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "instance-data.ec2.internal",
    "kubernetes.default",
    "host.docker.internal",
    "gateway.docker.internal",
})
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home", ".lan")


class WebhookError(ValueError):
    """Safe error that never includes destinations, credentials or bodies."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class TargetValidationError(WebhookError):
    pass


class DeliveryError(WebhookError):
    pass


@dataclass(frozen=True)
class ValidatedTarget:
    hostname: str
    addresses: tuple[str, ...]
    path: str = field(repr=False)
    port: int = 443


@dataclass(frozen=True)
class DeliveryResult:
    status_code: int
    response_bytes: int


def _invalid_target(code="invalid_target"):
    raise TargetValidationError(code, "destino de webhook inválido")


def _canonical_hostname(hostname):
    if not isinstance(hostname, str) or not hostname or hostname.endswith("."):
        _invalid_target()
    try:
        canonical = hostname.encode("idna").decode("ascii").lower()
    except (UnicodeError, UnicodeDecodeError):
        _invalid_target()
    if len(canonical) > 253 or "." not in canonical:
        _invalid_target()
    labels = canonical.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        _invalid_target()
    # Reject malformed/non-canonical punycode instead of allowing different
    # components to interpret the host differently.
    try:
        if canonical.encode("ascii").decode("idna").encode("idna").decode("ascii").lower() != canonical:
            _invalid_target()
    except UnicodeError:
        _invalid_target()
    return canonical


def _host_from_app_url(app_url):
    if not app_url:
        return None
    try:
        parsed = urlsplit(str(app_url))
        return _canonical_hostname(parsed.hostname)
    except (TargetValidationError, TypeError, ValueError):
        # A supplied but malformed application URL is a deployment
        # configuration error. Fail closed rather than lose the self-call guard.
        raise TargetValidationError("invalid_app_url", "URL pública da aplicação inválida") from None


def _resolved_addresses(hostname, resolver):
    try:
        answers = (resolver or socket.getaddrinfo)(
            hostname, 443, type=socket.SOCK_STREAM)
    except TypeError:
        # Simple deterministic resolvers used by callers/tests may accept only
        # host and port.
        try:
            answers = resolver(hostname, 443)
        except Exception:
            raise TargetValidationError("dns_failed", "não foi possível validar o destino") from None
    except Exception:
        raise TargetValidationError("dns_failed", "não foi possível validar o destino") from None

    addresses = []
    try:
        for answer in answers:
            if isinstance(answer, (str, ipaddress.IPv4Address, ipaddress.IPv6Address)):
                raw = str(answer)
            elif isinstance(answer, tuple) and len(answer) >= 5 and isinstance(answer[4], tuple):
                raw = str(answer[4][0])
            elif isinstance(answer, tuple) and answer and isinstance(answer[0], str):
                raw = answer[0]
            else:
                _invalid_target("dns_invalid")
            candidate = ipaddress.ip_address(raw.split("%", 1)[0])
            effective = ((candidate.ipv4_mapped or candidate)
                         if isinstance(candidate, ipaddress.IPv6Address) else candidate)
            if (not effective.is_global or effective.is_multicast
                    or effective.is_unspecified or effective.is_reserved
                    or effective.is_loopback or effective.is_link_local
                    or effective.is_private):
                _invalid_target("address_not_public")
            canonical = candidate.compressed
            if canonical not in addresses:
                addresses.append(canonical)
    except TargetValidationError:
        raise
    except (ValueError, TypeError):
        _invalid_target("dns_invalid")
    if not addresses:
        raise TargetValidationError("dns_empty", "destino sem endereço público")
    # A hostile DNS zone could otherwise make one delivery occupy the worker
    # for one connection timeout per address. Validate every answer first so a
    # private address cannot be hidden after the limit, then fail closed.
    if len(addresses) > MAX_RESOLVED_ADDRESSES:
        raise TargetValidationError(
            "dns_too_many_addresses", "destino retornou endereços demais")
    return tuple(addresses)


def validate_target(url, app_url=None, resolver=None):
    """Validate and resolve an HTTPS endpoint, returning only pinned IPs.

    All DNS answers must be globally routable. Mixed public/private answers are
    rejected because selecting only the public answer would leave room for
    rebinding and resolver-dependent behavior.
    """
    if not isinstance(url, str) or not url or len(url) > MAX_URL_LENGTH:
        _invalid_target()
    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        _invalid_target()
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError):
        _invalid_target()
    if (parsed.scheme.lower() != "https" or not parsed.netloc or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or port not in (None, 443)):
        _invalid_target()
    try:
        ipaddress.ip_address(parsed.hostname.strip("[]"))
    except ValueError:
        pass
    else:
        _invalid_target("ip_literal")

    hostname = _canonical_hostname(parsed.hostname)
    if (hostname in _BLOCKED_HOSTS or hostname.endswith(_BLOCKED_SUFFIXES)
            or hostname.split(".", 1)[0] in {"localhost", "metadata", "instance-data"}):
        _invalid_target("blocked_hostname")
    own_hostname = _host_from_app_url(app_url)
    if own_hostname and hmac.compare_digest(hostname, own_hostname):
        _invalid_target("self_target")

    raw_path = parsed.path or "/"
    try:
        decoded_path = unquote_to_bytes(raw_path)
    except (ValueError, UnicodeEncodeError):
        _invalid_target()
    if any(byte < 32 or byte == 127 for byte in decoded_path):
        _invalid_target()
    # Keep existing escapes and encode non-ASCII path characters consistently.
    path = quote(raw_path, safe="/%:@!$&'()*+,;=-._~")
    addresses = _resolved_addresses(hostname, resolver)
    return ValidatedTarget(hostname=hostname, path=path, addresses=addresses)


def sign_payload(secret, timestamp, raw_body):
    """Return the versioned HMAC for ``timestamp + '.' + raw_body``."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    if not isinstance(secret, bytes) or not secret or len(secret) > 4096:
        raise WebhookError("invalid_secret", "segredo de webhook inválido")
    if not isinstance(raw_body, bytes):
        raise WebhookError("invalid_body", "corpo de webhook inválido")
    timestamp = str(timestamp)
    if not timestamp.isascii() or not re.fullmatch(r"[0-9]{1,20}", timestamp):
        raise WebhookError("invalid_timestamp", "timestamp de webhook inválido")
    digest = hmac.new(secret, timestamp.encode("ascii") + b"." + raw_body, hashlib.sha256).hexdigest()
    return "v1=" + digest


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that never resolves the hostname a second time."""

    def __init__(self, hostname, address, timeout=CONNECT_TIMEOUT_SECONDS):
        super().__init__(hostname, port=443, timeout=timeout, context=ssl.create_default_context())
        self._validated_address = address

    def connect(self):
        candidate = ipaddress.ip_address(self._validated_address)
        family = socket.AF_INET6 if candidate.version == 6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout)
            destination = ((self._validated_address, 443, 0, 0)
                           if family == socket.AF_INET6 else (self._validated_address, 443))
            sock.connect(destination)
            # The certificate is still verified for the original hostname and
            # SNI/Host continue to identify the intended virtual host.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


def _timestamp(now):
    if now is None:
        return str(int(time.time()))
    if isinstance(now, datetime):
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return str(int(now.timestamp()))
    if isinstance(now, bool) or not isinstance(now, (int, float)) or now < 0:
        raise DeliveryError("invalid_time", "horário de entrega inválido")
    return str(int(now))


def _safe_header(value, label):
    value = str(value)
    if not _HEADER_VALUE.fullmatch(value):
        raise DeliveryError("invalid_header", f"{label} inválido")
    return value


def _application_url():
    configured = os.getenv("PULSEFLOW_APP_URL", "").strip()
    if configured:
        return configured
    hostname = (os.getenv("VERCEL_PROJECT_PRODUCTION_URL", "").strip()
                or os.getenv("VERCEL_URL", "").strip())
    return "https://" + hostname if hostname else None


def _refresh_socket_deadline(connection, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    timeout = max(0.1, min(CONNECT_TIMEOUT_SECONDS, remaining))
    connection.timeout = timeout
    sock = getattr(connection, "sock", None)
    if sock is not None and hasattr(sock, "settimeout"):
        sock.settimeout(timeout)


def deliver(url, secret, event_id, delivery_id, event_type, raw_body,
            now=None, resolver=None):
    """Perform one bounded, signed POST without following redirects."""
    if not isinstance(raw_body, bytes) or len(raw_body) > MAX_PAYLOAD_BYTES:
        raise DeliveryError("invalid_body", "corpo de webhook inválido")
    event_id = _safe_header(event_id, "event_id")
    delivery_id = _safe_header(delivery_id, "delivery_id")
    event_type = _safe_header(event_type, "event_type")
    timestamp = _timestamp(now)
    signature = sign_payload(secret, timestamp, raw_body)
    target = validate_target(url, app_url=_application_url(), resolver=resolver)
    headers = {
        "Host": target.hostname,
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "PulseFlow-Webhooks/1.0",
        "X-PulseFlow-Event-Id": event_id,
        "X-PulseFlow-Delivery-Id": delivery_id,
        "X-PulseFlow-Event-Type": event_type,
        "X-PulseFlow-Timestamp": timestamp,
        "X-PulseFlow-Signature": signature,
    }

    # The timeout is shared by all pinned addresses. Without a total budget, a
    # multi-address DNS answer could multiply the per-socket timeout and exceed
    # a serverless worker invocation.
    deadline = time.monotonic() + DELIVERY_ATTEMPT_BUDGET_SECONDS
    for address in target.addresses:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection = None
        try:
            connection = _PinnedHTTPSConnection(
                target.hostname, address,
                timeout=max(0.1, min(CONNECT_TIMEOUT_SECONDS, remaining)))
            connection.request("POST", target.path, body=raw_body, headers=headers)
            _refresh_socket_deadline(connection, deadline)
            response = connection.getresponse()
            declared = response.getheader("Content-Length")
            if declared and declared.isdecimal() and int(declared) > MAX_RESPONSE_BYTES:
                raise DeliveryError("response_too_large", "resposta do webhook excedeu o limite")
            _refresh_socket_deadline(connection, deadline)
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                raise DeliveryError("response_too_large", "resposta do webhook excedeu o limite")
            return DeliveryResult(status_code=int(response.status), response_bytes=len(response_body))
        except DeliveryError:
            raise
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError):
            # Try another already validated address. Never include the original
            # exception because it may contain a secret URL or request content.
            continue
        finally:
            if connection is not None:
                connection.close()
    raise DeliveryError("delivery_failed", "não foi possível entregar o webhook")
