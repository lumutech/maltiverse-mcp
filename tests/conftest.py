"""Test fixtures: an in-memory MCP client backed by a mocked Maltiverse API.

The API is mocked with ``httpx2.MockTransport`` injected into the server's HTTP
client — no network, no HTTP-mocking dependency. Backoff is zeroed so retry
paths run instantly.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager

import httpx2
import pytest
from mcp.client import Client

import maltiverse_mcp.client as client_mod
from maltiverse_mcp.config import Config
from maltiverse_mcp.server import build_server

Handler = Callable[[httpx2.Request], httpx2.Response]


@pytest.fixture(autouse=True)
def _fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make retry backoff instant so 429/5xx tests don't actually sleep."""
    monkeypatch.setattr(client_mod, "_BACKOFF_BASE", 0.0)


def make_config(api_key: str | None = "test-key") -> Config:
    return Config(
        api_key=api_key,
        base_url="https://api.maltiverse.com",
        timeout=5.0,
        log_level="WARNING",
    )


@asynccontextmanager
async def connect(handler: Handler, api_key: str | None = "test-key") -> AsyncIterator[Client]:
    """Yield a connected in-memory Client whose HTTP layer runs ``handler``."""
    transport = httpx2.MockTransport(handler)
    server = build_server(make_config(api_key), transport=transport)
    async with Client(server) as client:
        yield client


@pytest.fixture
def connect_client() -> Callable[..., object]:
    return connect


# ---- canned Maltiverse responses -------------------------------------------

MALICIOUS_IP = {
    "type": "ip",
    "ip_addr": "1.2.3.4",
    "classification": "malicious",
    "as_name": "AS15169 Google LLC",
    "country_code": "US",
    "is_cnc": True,
    "is_known_attacker": True,
    "tag": ["cobaltstrike", "apt"],
    "blacklist": [
        {
            "description": "Cobalt Strike",
            "source": "ThreatFox Abuse.ch",
            "labels": ["malicious-activity"],
            "first_seen": "2023-04-12 13:17:44",
            "last_seen": "2023-09-11 07:26:12",
            "count": 2,
        },
        {
            "description": "AsyncRAT",
            "source": "Maltiverse Research Team",
            "labels": ["malicious-activity"],
            "first_seen": "2023-09-10 22:18:48",
            "last_seen": "2023-09-11 07:26:12",
            "count": 1,
        },
    ],
}

UNKNOWN_URL = {"classification": "unknown", "type": "url", "urlchecksum": "deadbeef"}

MALWARE_SAMPLE = {
    "type": "sample",
    "sha256": "a" * 64,
    "classification": "malicious",
    "filetype": "PE32 executable",
    "av_ratio": "0.82",
    "blacklist": [
        {"description": "Emotet", "source": "VirusTotal", "last_seen": "2024-01-01 00:00:00"}
    ],
}

SEARCH_RESPONSE = {
    "hits": {
        "total": {"value": 57, "relation": "eq"},
        "hits": [
            {
                "_id": "ip-1",
                "_source": {
                    "type": "ip",
                    "ip_addr": "9.9.9.9",
                    "classification": "malicious",
                    "blacklist": [
                        {"description": "Mirai", "source": "feed", "last_seen": "2024-02-02"}
                    ],
                },
            },
            {
                "_id": "host-1",
                "_source": {
                    "type": "hostname",
                    "hostname": "evil.example",
                    "classification": "suspicious",
                    "blacklist": [],
                },
            },
        ],
    }
}
