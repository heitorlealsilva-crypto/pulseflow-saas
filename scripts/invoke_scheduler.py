"""Invoke PulseFlow's scheduler with a short-lived GitHub Actions OIDC token.

The runtime request token is provided by GitHub and is never printed, written
to disk or stored as a repository secret.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


AUDIENCE = "pulseflow-worker"
SCHEDULER_URL = "https://pulseflow-saas-alpha.vercel.app/api/scheduler"
MAX_RESPONSE_BYTES = 65_536


class InvocationError(RuntimeError):
    """A sanitized scheduler invocation failure safe to show in CI logs."""


def _json_request(url: str, *, bearer: str, method: str = "GET",
                  timeout: int = 20) -> dict:
    request = urllib.request.Request(
        url,
        method=method,
        data=b"{}" if method == "POST" else None,
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer " + bearer,
            "Content-Type": "application/json",
            "User-Agent": "pulseflow-scheduler/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        # Do not include response bodies or request headers in CI output.
        raise InvocationError(f"endpoint retornou HTTP {error.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError):
        raise InvocationError("endpoint temporariamente indisponível") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise InvocationError("resposta maior que o limite")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise InvocationError("endpoint retornou JSON inválido") from None
    if not isinstance(value, dict):
        raise InvocationError("endpoint retornou formato inválido")
    return value


def oidc_request_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host.endswith(".actions.githubusercontent.com"):
        raise InvocationError("URL OIDC do executor é inválida")
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, item) for key, item in query if key != "audience"]
    query.append(("audience", AUDIENCE))
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                    urllib.parse.urlencode(query), ""))


def acquire_oidc_token() -> str:
    request_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    request_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    if not request_url or not request_token:
        raise InvocationError("permissão OIDC não foi disponibilizada pelo GitHub")
    value = _json_request(oidc_request_url(request_url), bearer=request_token)
    token = value.get("value")
    if not isinstance(token, str) or token.count(".") != 2 or len(token) > 16_384:
        raise InvocationError("GitHub retornou um token OIDC inválido")
    return token


def invoke_scheduler(token: str) -> dict:
    # One invocation can include provider analysis and legitimately take longer
    # than a regular API request. Never retry an uncertain POST: the next
    # scheduled run safely resumes persistent jobs.
    value = _json_request(SCHEDULER_URL, bearer=token, method="POST", timeout=120)
    if value.get("ok") is not True:
        raise InvocationError("agendador não confirmou a execução")
    return value


def main() -> int:
    try:
        result = invoke_scheduler(acquire_oidc_token())
        tenants = int(result.get("tenantsScanned", 0))
        actions = int(result.get("actionsCreated", 0))
        message = f"Agendador concluído: {tenants} conta(s), {actions} ação(ões) preparada(s)."
        print(message)
        summary = os.getenv("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as output:
                output.write("### PulseFlow Scheduler\n\n" + message + "\n")
        return 0
    except (InvocationError, ValueError, TypeError) as error:
        print(f"Agendador não concluído: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
