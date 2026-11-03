"""MCP tool registration for the Maltiverse server."""

from maltiverse_mcp.tools.indicators import register_indicator_tools
from maltiverse_mcp.tools.search import register_search_tools

__all__ = ["register_indicator_tools", "register_search_tools"]
