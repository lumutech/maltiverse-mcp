"""The Maltiverse search tool."""

from __future__ import annotations

from typing import Annotated

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field

from maltiverse_mcp.client import MaltiverseError
from maltiverse_mcp.formatting import parse_search, render_search_text
from maltiverse_mcp.models import SearchResult
from maltiverse_mcp.tools._common import AppContext, get_client


def register_search_tools(mcp: MCPServer) -> None:
    @mcp.tool(
        title="Search Maltiverse indicators",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=True,
        ),
    )
    async def maltiverse_search(
        ctx: Context[AppContext],
        query: Annotated[
            str,
            Field(
                description=(
                    "Elasticsearch query-string syntax over the IoC index. Examples: "
                    "'classification:malicious AND type:url', "
                    "'tag:emotet', 'as_name:\"Google LLC\"', "
                    "'blacklist.description:\"Cobalt Strike\"'."
                ),
                min_length=1,
            ),
        ],
        limit: Annotated[
            int,
            Field(ge=1, le=100, description="Max results per page (1-100)."),
        ] = 20,
        offset: Annotated[
            int,
            Field(ge=0, description="Result offset for pagination; pass the prior next_offset."),
        ] = 0,
    ) -> Annotated[CallToolResult, SearchResult]:
        """Search Maltiverse for indicators matching a query.

        Use this to hunt across the whole dataset (by threat name, tag,
        classification, ASN, country, feed, etc.) rather than looking up one
        known indicator. Results are paginated: when has_more is true, call again
        with offset set to the returned next_offset. Keep limit small (default 20)
        to stay within output limits.

        Example: query='classification:malicious AND type:ip AND country_code:RU'.
        """
        client = get_client(ctx)
        params = {"query": query, "from": offset, "size": limit}
        try:
            raw = await client.get("/search", params=params)
        except MaltiverseError as exc:
            raise ToolError(str(exc)) from exc

        result: SearchResult = parse_search(raw, query, offset, limit)
        return CallToolResult(
            content=[TextContent(type="text", text=render_search_text(result))],
            structured_content=result.model_dump(),
        )
