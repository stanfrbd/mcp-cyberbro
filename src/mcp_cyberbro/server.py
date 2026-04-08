from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_cyberbro.tools.analysis import register_analysis_tools
from mcp_cyberbro.tools.engines import register_engine_tools
from mcp_cyberbro.tools.web import register_web_tools
from mcp_cyberbro.utils.config import CyberbroConfig


def create_server(config: CyberbroConfig) -> FastMCP:
    mcp = FastMCP("CyberbroMCP")

    register_analysis_tools(mcp, config)
    register_engine_tools(mcp)
    register_web_tools(mcp, config)

    if config.host:
        mcp.settings.host = config.host
    if config.port:
        mcp.settings.port = config.port
    if config.mount_path:
        mcp.settings.mount_path = config.mount_path
    if config.sse_path:
        mcp.settings.sse_path = config.sse_path
    if config.streamable_http_path:
        mcp.settings.streamable_http_path = config.streamable_http_path

    return mcp


def run_server(config: CyberbroConfig) -> None:
    mcp = create_server(config)
    mcp.run(transport=config.transport)
