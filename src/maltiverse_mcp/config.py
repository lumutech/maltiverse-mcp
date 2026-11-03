"""Configuration read from environment variables.

The API key is supplied **only** via the ``MALTIVERSE_API_KEY`` environment
variable that ``claude mcp add --env`` injects. There are deliberately no config
files, no interactive prompts, and no ``--api-key`` CLI flag (it would leak into
shell history and ``ps``).

Validation is lazy: a missing key must NOT crash startup, so ``claude mcp list``
still shows the server connected and its tools remain discoverable. The key is
only required when a tool is actually called.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_API_KEY = "MALTIVERSE_API_KEY"
ENV_BASE_URL = "MALTIVERSE_BASE_URL"
ENV_TIMEOUT = "MALTIVERSE_TIMEOUT"
ENV_LOG_LEVEL = "MALTIVERSE_LOG_LEVEL"

DEFAULT_BASE_URL = "https://api.maltiverse.com"
DEFAULT_TIMEOUT = 30.0
DEFAULT_LOG_LEVEL = "WARNING"

# Used verbatim in the actionable error we hand back to the model.
SERVER_NAME = "maltiverse"
PACKAGE_SCRIPT = "maltiverse-mcp"


@dataclass(frozen=True)
class Config:
    """Resolved server configuration. Cheap to build; never does I/O."""

    api_key: str | None
    base_url: str
    timeout: float
    log_level: str

    @property
    def has_api_key(self) -> bool:
        return bool(self.api_key)


def _clean(value: str | None) -> str | None:
    """Strip whitespace (pasted keys often carry a trailing newline)."""
    if value is None:
        return None
    value = value.strip()
    return value or None


def _read_timeout(raw: str | None) -> float:
    if not raw:
        return DEFAULT_TIMEOUT
    try:
        parsed = float(raw)
    except ValueError:
        return DEFAULT_TIMEOUT
    # Guard against 0/negative timeouts that would make every request fail.
    return parsed if parsed > 0 else DEFAULT_TIMEOUT


def load_config(env: dict[str, str] | None = None) -> Config:
    """Build a :class:`Config` from the environment (or an explicit mapping)."""
    source = os.environ if env is None else env
    base_url = _clean(source.get(ENV_BASE_URL)) or DEFAULT_BASE_URL
    return Config(
        api_key=_clean(source.get(ENV_API_KEY)),
        base_url=base_url.rstrip("/"),
        timeout=_read_timeout(_clean(source.get(ENV_TIMEOUT))),
        log_level=(_clean(source.get(ENV_LOG_LEVEL)) or DEFAULT_LOG_LEVEL).upper(),
    )
