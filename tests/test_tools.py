"""Tests driving every tool through the in-memory MCP client with mocked HTTP."""

from __future__ import annotations

import hashlib

import httpx2
import pytest

from conftest import (
    MALICIOUS_IP,
    MALWARE_SAMPLE,
    SEARCH_RESPONSE,
    UNKNOWN_URL,
    connect,
)

pytestmark = pytest.mark.asyncio


def _json(data: dict, status: int = 200) -> httpx2.Response:
    return httpx2.Response(status, json=data)


def static(data: dict, status: int = 200):
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return _json(data, status)

    return handler


# ---- discovery --------------------------------------------------------------


async def test_list_tools_schemas_and_annotations() -> None:
    async with connect(static(MALICIOUS_IP)) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}

    expected = {
        "maltiverse_check_ip",
        "maltiverse_check_hostname",
        "maltiverse_check_url",
        "maltiverse_check_sample",
        "maltiverse_check_indicator",
        "maltiverse_search",
    }
    assert expected == set(tools)

    for name, tool in tools.items():
        assert name.startswith("maltiverse_"), name
        assert tool.output_schema is not None, f"{name} missing output schema"
        assert tool.description and len(tool.description) > 60, f"{name} description too thin"
        ann = tool.annotations
        assert ann is not None and ann.read_only_hint is True
        assert ann.destructive_hint is False
        assert ann.idempotent_hint is True
        assert ann.open_world_hint is True
        assert tool.title  # human-readable title set via @mcp.tool(title=...)

    # Search exposes constrained pagination inputs.
    props = tools["maltiverse_search"].input_schema["properties"]
    assert props["limit"]["maximum"] == 100
    assert props["limit"]["minimum"] == 1
    assert props["offset"]["minimum"] == 0


# ---- happy paths ------------------------------------------------------------


async def test_check_ip_malicious_concise() -> None:
    async with connect(static(MALICIOUS_IP)) as client:
        result = await client.call_tool("maltiverse_check_ip", {"ip": "1.2.3.4"})

    assert result.is_error is False
    sc = result.structured_content
    assert sc["classification"] == "malicious"
    assert sc["is_malicious"] is True
    assert set(sc["threat_names"]) == {"Cobalt Strike", "AsyncRAT"}
    assert "is_cnc" in sc["active_flags"]
    assert sc["as_name"] == "AS15169 Google LLC"
    assert sc["blacklist"] is None  # concise omits per-feed detail
    text = result.content[0].text
    assert "MALICIOUS" in text and "Cobalt Strike" in text


async def test_check_ip_detailed_includes_blacklist() -> None:
    async with connect(static(MALICIOUS_IP)) as client:
        result = await client.call_tool(
            "maltiverse_check_ip", {"ip": "1.2.3.4", "response_format": "detailed"}
        )
    assert result.structured_content["blacklist"] is not None
    assert "Attributions" in result.content[0].text


async def test_check_sample_by_sha256_routes_correctly() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["path"] = request.url.path
        return _json(MALWARE_SAMPLE)

    async with connect(handler) as client:
        result = await client.call_tool("maltiverse_check_sample", {"file_hash": "a" * 64})

    assert seen["path"] == "/sample/" + "a" * 64
    assert result.structured_content["filetype"] == "PE32 executable"
    assert result.structured_content["av_ratio"] == "0.82"


async def test_check_sample_md5_uses_algo_endpoint() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["path"] = request.url.path
        return _json(MALWARE_SAMPLE)

    async with connect(handler) as client:
        await client.call_tool("maltiverse_check_sample", {"file_hash": "d" * 32})

    assert seen["path"] == "/sample/md5/" + "d" * 32


async def test_check_url_hashes_the_url() -> None:
    url = "http://bad.test/evil"
    expected = hashlib.sha256(url.encode()).hexdigest()
    seen: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen["path"] = request.url.path
        return _json(UNKNOWN_URL)

    async with connect(handler) as client:
        result = await client.call_tool("maltiverse_check_url", {"url": url})

    assert seen["path"] == f"/url/{expected}"
    assert result.structured_content["classification"] == "unknown"
    assert "No threat intelligence" in result.content[0].text


async def test_check_indicator_autodetects_type() -> None:
    paths: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        paths.append(request.url.path)
        return _json(UNKNOWN_URL)

    cases = {
        "8.8.8.8": "/ip/8.8.8.8",
        "evil.example.com": "/hostname/evil.example.com",
        "http://x.test/": f"/url/{hashlib.sha256(b'http://x.test/').hexdigest()}",
        "e" * 40: "/sample/sha1/" + "e" * 40,
    }
    async with connect(handler) as client:
        for value in cases:
            await client.call_tool("maltiverse_check_indicator", {"indicator": value})

    assert paths == list(cases.values())


async def test_search_pagination() -> None:
    captured: dict[str, str] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        captured.update(dict(request.url.params))
        return _json(SEARCH_RESPONSE)

    async with connect(handler) as client:
        result = await client.call_tool(
            "maltiverse_search", {"query": "classification:malicious", "limit": 20}
        )

    assert captured["query"] == "classification:malicious"
    assert captured["size"] == "20"
    sc = result.structured_content
    assert sc["total"] == 57
    assert sc["returned"] == 2
    assert sc["has_more"] is True
    assert sc["next_offset"] == 20
    assert "of 57" in result.content[0].text


# ---- error handling ---------------------------------------------------------


async def test_missing_api_key_returns_actionable_error() -> None:
    async with connect(static(MALICIOUS_IP), api_key=None) as client:
        result = await client.call_tool("maltiverse_check_ip", {"ip": "1.2.3.4"})

    assert result.is_error is True
    text = result.content[0].text
    assert "MALTIVERSE_API_KEY is not set" in text
    assert "claude mcp add" in text


async def test_auth_401_is_actionable_and_does_not_leak_key() -> None:
    async with connect(static({"error": "unauthorized"}, status=401)) as client:
        result = await client.call_tool("maltiverse_check_ip", {"ip": "1.2.3.4"})

    assert result.is_error is True
    text = result.content[0].text
    assert "rejected the API key" in text
    assert "test-key" not in text  # the key must never appear in error text


async def test_not_found_404_points_to_search() -> None:
    async with connect(static({}, status=404)) as client:
        result = await client.call_tool("maltiverse_check_hostname", {"hostname": "nope.test"})

    assert result.is_error is True
    text = result.content[0].text
    assert "No hostname record" in text
    assert "maltiverse_search" in text


async def test_rate_limit_429_includes_retry_after() -> None:
    def handler(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(429, headers={"Retry-After": "7"}, json={})

    async with connect(handler) as client:
        result = await client.call_tool("maltiverse_check_ip", {"ip": "1.2.3.4"})

    assert result.is_error is True
    text = result.content[0].text
    assert "rate limit" in text.lower()
    assert "7" in text


async def test_5xx_is_retried_then_recovers() -> None:
    calls = {"n": 0}

    def handler(_request: httpx2.Request) -> httpx2.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx2.Response(503, json={})
        return _json(MALICIOUS_IP)

    async with connect(handler) as client:
        result = await client.call_tool("maltiverse_check_ip", {"ip": "1.2.3.4"})

    assert calls["n"] == 2  # first 503 retried, second 200 succeeded
    assert result.is_error is False
    assert result.structured_content["classification"] == "malicious"


async def test_invalid_hash_is_tool_error_not_exception() -> None:
    async with connect(static(MALWARE_SAMPLE)) as client:
        result = await client.call_tool("maltiverse_check_sample", {"file_hash": "not-a-hash"})

    assert result.is_error is True
    assert "not a valid file hash" in result.content[0].text


async def test_out_of_range_limit_rejected_by_schema() -> None:
    async with connect(static(SEARCH_RESPONSE)) as client:
        result = await client.call_tool("maltiverse_search", {"query": "x", "limit": 999})

    assert result.is_error is True
    assert "less than or equal to 100" in result.content[0].text
