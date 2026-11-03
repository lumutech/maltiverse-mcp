"""Shared helpers for tool modules: the lifespan context and error mapping."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent

from maltiverse_mcp.client import (
    MaltiverseClient,
    MaltiverseError,
    NotFoundError,
)
from maltiverse_mcp.formatting import (
    parse_indicator,
    render_indicator_text,
)
from maltiverse_mcp.models import IndicatorReport, IndicatorType, ResponseFormat


@dataclass
class AppContext:
    """Yielded by the server lifespan; shared by every tool call."""

    client: MaltiverseClient


def get_client(ctx: Context[AppContext]) -> MaltiverseClient:
    return ctx.request_context.lifespan_context.client


_HEX_TO_ALGO = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


def detect_indicator_type(value: str) -> IndicatorType:
    """Best-effort classification of a raw indicator string."""
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if "://" in v or v.startswith(("http:", "https:")):
        return "url"
    if _HEX_RE.match(v) and len(v) in _HEX_TO_ALGO:
        return "sample"
    return "hostname"


def sample_path(hash_value: str) -> str:
    """Route a file hash to the right ``/sample`` endpoint by its hex length."""
    algo = _HEX_TO_ALGO.get(len(hash_value))
    if algo is None or not _HEX_RE.match(hash_value):
        raise ToolError(
            f"{hash_value!r} is not a valid file hash. Expected a hex MD5 (32), "
            "SHA-1 (40), SHA-256 (64), or SHA-512 (128) digest."
        )
    return f"/sample/{hash_value}" if algo == "sha256" else f"/sample/{algo}/{hash_value}"


async def lookup_indicator(
    client: MaltiverseClient,
    itype: IndicatorType,
    path: str,
    queried_value: str,
    response_format: ResponseFormat,
) -> CallToolResult:
    """Fetch, parse, and render one indicator as a dual-channel tool result."""
    try:
        raw = await client.get(path)
    except NotFoundError as exc:
        raise ToolError(
            f"No {itype} record for {queried_value!r} in Maltiverse. It is either not "
            "known to the platform (likely clean/unseen) or the value is malformed. "
            "Use maltiverse_search to look for related indicators."
        ) from exc
    except MaltiverseError as exc:
        # str(exc) is already a model-safe, actionable message.
        raise ToolError(str(exc)) from exc

    report: IndicatorReport = parse_indicator(raw, itype, queried_value, response_format)
    return CallToolResult(
        content=[TextContent(type="text", text=render_indicator_text(report, response_format))],
        structured_content=report.model_dump(),
    )
