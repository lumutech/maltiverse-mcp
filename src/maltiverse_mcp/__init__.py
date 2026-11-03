"""maltiverse-mcp: a local stdio MCP server for the Maltiverse threat-intel API."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("maltiverse-mcp")
except PackageNotFoundError:  # pragma: no cover - only when running from a source tree
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
