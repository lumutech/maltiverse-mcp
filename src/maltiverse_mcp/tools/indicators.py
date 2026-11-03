"""Indicator-reputation tools: IP, hostname, URL, file sample, and a router."""

from __future__ import annotations

from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import Field

from maltiverse_mcp.client import url_checksum
from maltiverse_mcp.models import IndicatorReport, ResponseFormat
from maltiverse_mcp.tools._common import (
    AppContext,
    detect_indicator_type,
    get_client,
    lookup_indicator,
    sample_path,
)

_READ_ONLY = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    # Maltiverse queries live, internet-wide threat intelligence.
    open_world_hint=True,
)


def register_indicator_tools(mcp: MCPServer) -> None:
    @mcp.tool(
        title="Check IP reputation (Maltiverse)",
        annotations=_READ_ONLY,
    )
    async def maltiverse_check_ip(
        ctx: Context[AppContext],
        ip: Annotated[
            str,
            Field(description="IPv4 or IPv6 address, e.g. '8.8.8.8' or '2001:4860:4860::8888'."),
        ],
        response_format: ResponseFormat = "concise",
    ) -> Annotated[CallToolResult, IndicatorReport]:
        """Look up the threat-intel reputation of an IP address in Maltiverse.

        Use this when you have an IP and need its classification (malicious /
        suspicious / neutral / whitelist), associated threats and feeds, ASN,
        and behaviour flags (C2, scanner, TOR, VPN, proxy, etc.). For domains use
        maltiverse_check_hostname; if you don't know the indicator type, use
        maltiverse_check_indicator.
        """
        return await lookup_indicator(
            get_client(ctx), "ip", f"/ip/{ip.strip()}", ip.strip(), response_format
        )

    @mcp.tool(
        title="Check hostname/domain reputation (Maltiverse)",
        annotations=_READ_ONLY,
    )
    async def maltiverse_check_hostname(
        ctx: Context[AppContext],
        hostname: Annotated[
            str,
            Field(description="A domain or hostname, e.g. 'example.com' (no scheme, no path)."),
        ],
        response_format: ResponseFormat = "concise",
    ) -> Annotated[CallToolResult, IndicatorReport]:
        """Look up the reputation of a hostname or domain in Maltiverse.

        Use for domains/FQDNs (phishing, malware distribution, C2). Pass the bare
        hostname without a scheme or path — for a full URL use maltiverse_check_url.
        """
        host = hostname.strip().rstrip("/")
        return await lookup_indicator(
            get_client(ctx), "hostname", f"/hostname/{host}", host, response_format
        )

    @mcp.tool(
        title="Check URL reputation (Maltiverse)",
        annotations=_READ_ONLY,
    )
    async def maltiverse_check_url(
        ctx: Context[AppContext],
        url: Annotated[
            str,
            Field(
                description=(
                    "A full URL including scheme, e.g. 'http://example.com/path'. You may "
                    "instead pass the 64-char SHA-256 'urlchecksum' Maltiverse assigns a URL."
                )
            ),
        ],
        response_format: ResponseFormat = "concise",
    ) -> Annotated[CallToolResult, IndicatorReport]:
        """Look up the reputation of a specific URL in Maltiverse.

        Maltiverse keys URLs by the SHA-256 of the raw URL string; this tool
        computes that checksum for you. Pass a full URL (with scheme). To check
        just the domain, use maltiverse_check_hostname instead.
        """
        value = url.strip()
        # Accept a pre-computed checksum as-is; otherwise hash the URL.
        checksum = value if _looks_like_checksum(value) else url_checksum(value)
        return await lookup_indicator(
            get_client(ctx), "url", f"/url/{checksum}", value, response_format
        )

    @mcp.tool(
        title="Check file-hash reputation (Maltiverse)",
        annotations=_READ_ONLY,
    )
    async def maltiverse_check_sample(
        ctx: Context[AppContext],
        file_hash: Annotated[
            str,
            Field(
                description=(
                    "A malware sample hash: MD5 (32 hex), SHA-1 (40), SHA-256 (64), or "
                    "SHA-512 (128). The algorithm is detected from the length."
                )
            ),
        ],
        response_format: ResponseFormat = "concise",
    ) -> Annotated[CallToolResult, IndicatorReport]:
        """Look up a malware sample by file hash in Maltiverse.

        Returns classification, AV detection ratio, file type, and threat
        attributions. Accepts MD5/SHA-1/SHA-256/SHA-512; the right endpoint is
        chosen from the hash length.
        """
        h = file_hash.strip()
        return await lookup_indicator(get_client(ctx), "sample", sample_path(h), h, response_format)

    @mcp.tool(
        title="Check any indicator (auto-detect type, Maltiverse)",
        annotations=_READ_ONLY,
    )
    async def maltiverse_check_indicator(
        ctx: Context[AppContext],
        indicator: Annotated[
            str,
            Field(
                description=(
                    "Any IoC: an IP, domain/hostname, full URL, or file hash. The type is "
                    "auto-detected (IP by parse, URL by scheme, hash by hex length, else host)."
                )
            ),
        ],
        response_format: ResponseFormat = "concise",
    ) -> Annotated[CallToolResult, IndicatorReport]:
        """Look up any indicator when you don't know its type up front.

        This is the convenient default: pass an IP, domain, URL, or hash and the
        server routes to the correct Maltiverse endpoint. Prefer the specific
        tools (maltiverse_check_ip/_hostname/_url/_sample) when you already know
        the type and want to avoid ambiguity.
        """
        value = indicator.strip()
        itype = detect_indicator_type(value)
        client = get_client(ctx)
        if itype == "ip":
            return await lookup_indicator(client, "ip", f"/ip/{value}", value, response_format)
        if itype == "sample":
            return await lookup_indicator(
                client, "sample", sample_path(value), value, response_format
            )
        if itype == "url":
            checksum = value if _looks_like_checksum(value) else url_checksum(value)
            return await lookup_indicator(client, "url", f"/url/{checksum}", value, response_format)
        host = value.rstrip("/")
        return await lookup_indicator(
            client, "hostname", f"/hostname/{host}", host, response_format
        )


def _looks_like_checksum(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value)
