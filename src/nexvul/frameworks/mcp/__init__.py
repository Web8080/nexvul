"""Model Context Protocol recognisers (research ``docs/research/protocols/mcp.md``).

* :mod:`.config` - MCP client configuration files (JSON/JSONC IR).
* :mod:`.endpoints` - literal URL classification (loopback / private / remote, cleartext).
* :mod:`.python_client` - constant-URL HTTP client calls of the Python ``mcp`` SDK.
"""

from nexvul.frameworks.mcp.config import (
    CLIENT_LABELS,
    McpClient,
    McpConfig,
    McpServer,
    Transport,
    recognise_config,
)
from nexvul.frameworks.mcp.endpoints import Endpoint, HostClass, classify_host, parse_endpoint
from nexvul.frameworks.mcp.python_client import McpHttpClientCall, find_http_client_calls

__all__ = [
    "CLIENT_LABELS",
    "Endpoint",
    "HostClass",
    "McpClient",
    "McpConfig",
    "McpHttpClientCall",
    "McpServer",
    "Transport",
    "classify_host",
    "find_http_client_calls",
    "parse_endpoint",
    "recognise_config",
]
