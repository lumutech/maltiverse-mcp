"""MCPServer instance, tool registration, and the synchronous ``main()`` entry point.

stdio transport rule: **nothing may write to stdout except the MCP SDK**. We
configure logging to stderr before anything else runs, and do no network I/O at
import or startup — the HTTP client is created lazily in the server lifespan.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx2

from maltiverse_mcp import __version__
from maltiverse_mcp.client import MaltiverseClient, build_async_client
from maltiverse_mcp.config import Config, load_config
from maltiverse_mcp.tools import register_indicator_tools, register_search_tools
from maltiverse_mcp.tools._common import AppContext

try:  # MCPServer is the v2 name; fail loudly if someone pins the removed v1.
    from mcp.server import MCPServer
except ImportError as exc:  # pragma: no cover - guards against an mcp<2 install
    raise ImportError(
        "maltiverse-mcp requires the official 'mcp' SDK v2 (mcp>=2,<3). "
        "FastMCP / mcp.server.fastmcp was removed in v2."
    ) from exc

logger = logging.getLogger("maltiverse_mcp")

INSTRUCTIONS = (
    "Query the Maltiverse threat-intelligence platform. Use maltiverse_check_indicator "
    "(or the type-specific maltiverse_check_ip / _hostname / _url / _sample tools) to get "
    "the reputation and threat attributions of a single IoC, and maltiverse_search to hunt "
    "across the dataset by classification, threat name, tag, ASN, or country. All tools are "
    "read-only; results are concise by default — pass response_format='detailed' for full "
    "per-feed attributions."
)


def configure_logging(level: str) -> None:
    """Send all logging to stderr. stdout is reserved for JSON-RPC."""
    numeric = getattr(logging, level.upper(), logging.WARNING)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(numeric)


def build_server(
    config: Config | None = None,
    *,
    transport: httpx2.AsyncBaseTransport | None = None,
) -> MCPServer:
    """Construct the configured MCPServer. ``transport`` is injected by tests."""
    cfg = config or load_config()

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[AppContext]:
        http = build_async_client(cfg, transport=transport)
        client = MaltiverseClient(http, cfg)
        try:
            yield AppContext(client=client)
        finally:
            # Keep teardown fast — Claude Code SIGKILLs ~500ms after SIGINT.
            await client.aclose()

    mcp = MCPServer(
        name="maltiverse",
        title="Maltiverse Threat Intelligence",
        version=__version__,
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
    )
    register_indicator_tools(mcp)
    register_search_tools(mcp)
    return mcp


def main() -> None:
    """Console-script entry point: configure logging, build server, serve over stdio."""
    cfg = load_config()
    configure_logging(cfg.log_level)
    if not cfg.has_api_key:
        # Not fatal: the server still starts and lists tools so `claude mcp list`
        # shows it connected. The key is only required when a tool is called.
        logger.warning(
            "MALTIVERSE_API_KEY is not set; tools will return an actionable error until "
            "it is configured via `claude mcp add --env`."
        )
    server = build_server(cfg)
    server.run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
