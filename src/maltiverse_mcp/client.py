"""Async HTTP client wrapper around the Maltiverse API.

One shared :class:`httpx2.AsyncClient` (httpx2 is the HTTP stack the mcp SDK
already depends on — we do not add a second one). The wrapper:

* sends ``Authorization: Bearer <key>`` and a versioned ``User-Agent``;
* retries idempotent GETs on 429/5xx with bounded exponential backoff;
* maps HTTP failures onto typed exceptions whose messages are safe to show the
  model and tell it what to do next;
* never lets the API key appear in any error text.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from typing import Any

import httpx2

from maltiverse_mcp import __version__
from maltiverse_mcp.config import Config

USER_AGENT = f"maltiverse-mcp/{__version__}"

_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES: int = 2
_BACKOFF_BASE: float = 0.5


class MaltiverseError(Exception):
    """Base class. ``str(self)`` is a model-safe, actionable message."""


class MissingApiKeyError(MaltiverseError):
    """No API key configured."""


class AuthError(MaltiverseError):
    """401/403 — the key was rejected."""


class NotFoundError(MaltiverseError):
    """404 — the indicator is not in Maltiverse."""


class RateLimitError(MaltiverseError):
    """429 — too many requests."""


class UpstreamError(MaltiverseError):
    """5xx or a transport-level failure."""


class InvalidRequestError(MaltiverseError):
    """400/422 — the request was malformed."""


def url_checksum(url: str) -> str:
    """Maltiverse's URL id is the SHA-256 hex digest of the raw URL string."""
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _redact(text: str, api_key: str | None) -> str:
    if api_key and api_key in text:
        text = text.replace(api_key, "***")
    return text


def build_async_client(
    config: Config,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> httpx2.AsyncClient:
    """Create the shared AsyncClient. ``transport`` is injected by tests."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    return httpx2.AsyncClient(
        base_url=config.base_url,
        headers=headers,
        timeout=config.timeout,
        follow_redirects=True,
        transport=transport,
    )


class MaltiverseClient:
    """Thin async wrapper that turns API responses into dicts or typed errors."""

    def __init__(
        self,
        http: httpx2.AsyncClient,
        config: Config,
        *,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._http = http
        self._config = config
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._http.aclose()

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET a JSON object from ``path``, with retry + typed error mapping."""
        if not self._config.has_api_key:
            raise MissingApiKeyError(_missing_key_message())

        last_exc: MaltiverseError | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = await self._http.get(path, params=params)
            except httpx2.RequestError as exc:
                last_exc = UpstreamError(
                    f"Could not reach Maltiverse ({type(exc).__name__}). "
                    "Check network connectivity and MALTIVERSE_BASE_URL, then retry."
                )
                if attempt < _MAX_RETRIES:
                    await self._sleep(_BACKOFF_BASE * (2.0**attempt))
                    continue
                raise last_exc from exc

            if response.status_code in _RETRYABLE_STATUS and attempt < _MAX_RETRIES:
                await self._sleep(self._retry_delay(response, attempt))
                continue

            return self._handle(response)

        # Exhausted retries on a retryable status: surface the last response error.
        assert last_exc is not None  # pragma: no cover - defensive
        raise last_exc

    def _retry_delay(self, response: httpx2.Response, attempt: int) -> float:
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                return min(float(retry_after), 10.0)
        return _BACKOFF_BASE * (2.0**attempt)

    def _handle(self, response: httpx2.Response) -> dict[str, Any]:
        status = response.status_code
        if status == 200:
            data = response.json()
            if not isinstance(data, dict):
                raise UpstreamError("Maltiverse returned an unexpected (non-object) response.")
            return data
        if status in (401, 403):
            raise AuthError(
                f"Maltiverse rejected the API key (HTTP {status}). Check that MALTIVERSE_API_KEY "
                "is a valid key for your Maltiverse account (Profile -> Generate API Key)."
            )
        if status == 404:
            raise NotFoundError("not found")
        if status in (400, 422):
            detail = _redact(response.text[:200], self._config.api_key)
            raise InvalidRequestError(f"Maltiverse rejected the request (HTTP {status}): {detail}")
        if status == 429:
            retry_after = response.headers.get("Retry-After")
            hint = f" Retry after {retry_after}s." if retry_after else ""
            raise RateLimitError(
                "Maltiverse rate limit hit (HTTP 429)." + hint + " Wait and try again, "
                "or reduce the request rate."
            )
        if status >= 500:
            raise UpstreamError(
                f"Maltiverse service error (HTTP {status}). This is a server-side problem; "
                "retry in a few seconds."
            )
        raise UpstreamError(f"Unexpected Maltiverse response (HTTP {status}).")


def _missing_key_message() -> str:
    return (
        "MALTIVERSE_API_KEY is not set. Ask the user to run: "
        "claude mcp remove maltiverse && "
        "claude mcp add --scope user --transport stdio maltiverse "
        "--env MALTIVERSE_API_KEY=<key> -- maltiverse-mcp"
    )
