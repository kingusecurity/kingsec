"""The HTTP client for AI providers — the only module that imports httpx.

Responsibilities: connection pooling, timeouts, TLS verification, retry with
exponential back-off on transient failures, structured logging, and translating
every httpx failure into an ``AIError`` so no ``httpx`` exception escapes
infrastructure. It logs metadata only — never the API key (it lives in caller
headers) and never the prompt body (which may echo scanner data).

KSEC-85-01: this client also OWNS SSRF DNS-rebinding protection for every
request it sends. It used to trust an upfront ``URLValidationPort.validate()``
check performed by its caller (``AIProviderAdapter``/``AIProviderTester``) and
then resolve the URL's hostname a SECOND, independent time when httpx actually
opened the connection - the exact TOCTOU window Phase 79 closed for the
urllib-based integrations (webhook/SIEM/ticketing/email) via
``open_validated()``'s resolve-once-and-pin design, but which this httpx-based
client never adopted. Reusing ``open_validated()`` itself is not possible
without dropping this client's connection pooling, retries, and configurable
TLS verification (rebuilding all of that on top of ``urllib`` would be a far
larger, riskier change than the smallest fix that actually closes the gap).
Instead, ``_build_pinned_request()`` reuses Phase 79's OWN validation/
resolution function (``_resolve_and_validate`` - the single source of truth
for "which IP is this hostname allowed to resolve to", imported directly
rather than reimplemented) and pins the connection via httpx/httpcore's own
built-in ``sni_hostname`` request extension: the request URL's host becomes
the one validated IP, while an explicit ``Host`` header and the
``sni_hostname`` extension both keep the ORIGINAL hostname for the HTTP
request line and, for HTTPS, TLS SNI/certificate hostname verification
(httpcore's ``_sync/_async/connection.py`` reads exactly this extension for
``server_hostname`` at ``start_tls()`` time - confirmed by direct inspection
of the installed httpcore package, not assumed). No new pinning mechanism was
invented; only the httpx-specific glue to invoke Phase 79's existing decision
was added.
"""

from __future__ import annotations

import json
import time
from typing import Any, cast

import httpx

from kingsec.infrastructure.logging import get_logger
from kingsec.infrastructure.notifications.url_validator import SSRFError, _resolve_and_validate

from .errors import RETRYABLE_STATUS_CODES, AIResponseError, AIUnsafeURLError, ErrorTranslator

_logger = get_logger("kingsec.infrastructure.ai")


class AIClient:
    """A pooled, retrying, TLS-verifying JSON-over-HTTP client for AI providers."""

    def __init__(
        self,
        *,
        timeout: float,
        retry_count: int,
        retry_delay: float,
        verify_ssl: bool = True,
        allow_private: bool = False,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        """Initialise the client.

        Args:
            timeout: Per-request timeout in seconds.
            retry_count: Number of retries after the initial attempt (>= 0).
            retry_delay: Base back-off delay in seconds (exponential per attempt).
            verify_ssl: Whether to verify TLS certificates. Secure by default;
                only an explicit False disables verification.
            allow_private: SSRF guard opt-in (KSEC-85-01), mirroring
                ``SSRFURLValidator(allow_private=...)``'s own flag exactly -
                permits loopback/RFC 1918 destinations (a local model
                server) while cloud-metadata/link-local/multicast/reserved
                addresses remain blocked unconditionally either way.
            transport: Optional transport override (tests inject a mock).
        """
        self._retry_count = max(0, retry_count)
        self._retry_delay = max(0.0, retry_delay)
        self._allow_private = allow_private
        # A single pooled client is reused for all requests (keep-alive).
        # follow_redirects=False is httpx's own default already, but is
        # restated explicitly here and at every .send() call below: an
        # unvalidated redirect target would bypass the pinning this class
        # exists to enforce (KSEC-85-01's redirect-safety requirement).
        #
        # Proxy config comes from the process environment (httpx's
        # trust_env default). A malformed proxy entry (e.g. a bare IPv6
        # address in no_proxy, which httpx cannot parse as a URL pattern)
        # must never prevent the application from starting: fall back to
        # ignoring ambient proxy config rather than crashing.
        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(timeout),
            "limits": httpx.Limits(max_connections=10, max_keepalive_connections=5),
            "verify": verify_ssl,
            "transport": transport,
            "follow_redirects": False,
        }
        try:
            self._client = httpx.Client(**client_kwargs)
        except httpx.InvalidURL:
            _logger.warning(
                "proxy_env_unparseable",
                detail="ignoring ambient proxy configuration (trust_env=False)",
            )
            self._client = httpx.Client(**client_kwargs, trust_env=False)

    def _build_pinned_request(
        self, url: str, headers: dict[str, str], payload: dict[str, Any], *, allow_private: bool | None
    ) -> httpx.Request:
        """Resolve, validate, and pin *url* to a single IP (KSEC-85-01),
        then build the httpx ``Request`` to send.

        Args:
            allow_private: Per-call override of the client's own configured
                default (``None`` uses the client's default). Needed because
                a single ``AIClient`` instance is shared across requests
                whose *source* the client itself cannot see - e.g.
                ``AIProviderAdapter`` calls this with ``True`` for
                environment-sourced ``base_url`` (trusted deployment
                configuration that was never subject to a private-address
                policy check, before or after KSEC-85-01: see
                ``adapter.py``'s ``_validate_base_url()``), while leaving it
                unset (client default) for database-sourced base_url, whose
                policy the client's own constructor already carries.
                Resolve-once-and-pin (the actual TOCTOU fix) always runs
                either way; only the private/reserved-range policy differs.

        Raises:
            SSRFError: The hostname cannot be resolved, or every resolved
                address (or the only one on an allowlist-free path) falls in
                a blocked range - identical conditions to
                ``SSRFURLValidator.validate()``, since this calls the exact
                same underlying function.
        """
        effective_allow_private = self._allow_private if allow_private is None else allow_private
        pinned_ip = _resolve_and_validate(url, allowlist=None, allow_private=effective_allow_private)
        if pinned_ip is None:  # pragma: no cover - AI has no allowlist concept today
            return self._client.build_request("POST", url, headers=headers, json=payload)

        original = httpx.URL(url)
        pinned_url = original.copy_with(host=pinned_ip)
        # original.netloc already omits the port when it's the scheme
        # default (matches httpx's own auto-Host-header logic exactly) -
        # reused rather than reimplemented so this can never drift from
        # what an unpinned request would have sent as its Host header.
        pinned_headers = {**headers, "Host": original.netloc.decode("ascii")}
        return self._client.build_request(
            "POST",
            pinned_url,
            headers=pinned_headers,
            json=payload,
            extensions={"sni_hostname": original.host},
        )

    def post_json(
        self, url: str, headers: dict[str, str], payload: dict[str, Any], *, allow_private: bool | None = None
    ) -> dict[str, Any]:
        """POST a JSON payload and return the parsed JSON response.

        Retries transient transport errors and retryable status codes with
        exponential back-off, then translates any remaining failure. Every
        attempt independently re-resolves and re-validates the destination
        (KSEC-85-01) immediately before connecting - there is no separate
        "validate now, connect later" step for an attacker to race.

        Args:
            url: The endpoint URL.
            headers: Request headers (including auth — never logged).
            payload: The JSON request body.
            allow_private: Per-call override of this client's configured
                default private-address policy (see
                ``_build_pinned_request``'s docstring). ``None`` (the
                default) uses the client's own configured policy.

        Returns:
            The parsed JSON response body.

        Raises:
            AIError: On timeout, transport failure, error status, or unparseable
                body. (One of its subtypes.)
            AIUnsafeURLError: If the destination is blocked by SSRF validation.
        """
        attempts = self._retry_count + 1
        for attempt in range(1, attempts + 1):
            try:
                request = self._build_pinned_request(url, headers, payload, allow_private=allow_private)
                response = self._client.send(request, follow_redirects=False)
            except SSRFError as exc:
                # Not a transient failure - never retried, regardless of
                # attempts remaining.
                raise AIUnsafeURLError(f"AI request blocked by SSRF protection: {exc}") from exc
            except httpx.HTTPError as exc:
                if attempt <= self._retry_count:
                    _logger.warning("ai request retry", attempt=attempt, reason=type(exc).__name__)
                    self._backoff(attempt)
                    continue
                raise ErrorTranslator.from_exception(exc) from exc

            if response.status_code >= 400:
                if response.status_code in RETRYABLE_STATUS_CODES and attempt <= self._retry_count:
                    _logger.warning("ai request retry", attempt=attempt, status=response.status_code)
                    self._backoff(attempt)
                    continue
                raise ErrorTranslator.from_status(response.status_code, response.text)

            try:
                return cast(dict[str, Any], response.json())
            except (json.JSONDecodeError, ValueError) as exc:
                raise AIResponseError("AI response body was not valid JSON", cause=exc) from exc

        # Unreachable: the loop always returns or raises.
        raise AIResponseError("AI request exhausted retries")  # pragma: no cover

    def _backoff(self, attempt: int) -> None:
        """Sleep with exponential back-off before the next attempt."""
        if self._retry_delay > 0:
            time.sleep(self._retry_delay * (2 ** (attempt - 1)))

    def close(self) -> None:
        """Close the underlying connection pool (registered as a shutdown hook)."""
        self._client.close()
