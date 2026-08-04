from __future__ import annotations

from mcp.server.mcpserver import MCPServer

from mcp_cyberbro.tools.analysis import register_analysis_tools
from mcp_cyberbro.tools.engines import register_engine_tools
from mcp_cyberbro.tools.web import register_web_tools
from mcp_cyberbro.utils.config import CyberbroConfig


def create_server(config: CyberbroConfig) -> MCPServer:
    mcp = MCPServer("CyberbroMCP")

    register_analysis_tools(mcp, config)
    register_engine_tools(mcp)
    register_web_tools(mcp, config)

    return mcp


def run_server(config: CyberbroConfig) -> None:
    mcp = create_server(config)

    kwargs: dict = {}
    if config.host:
        kwargs["host"] = config.host
    if config.port:
        kwargs["port"] = config.port
    if config.transport == "sse" and config.sse_path:
        kwargs["sse_path"] = config.sse_path
    if config.transport == "streamable-http" and config.streamable_http_path:
        kwargs["streamable_http_path"] = config.streamable_http_path

    mcp.run(transport=config.transport, **kwargs)
