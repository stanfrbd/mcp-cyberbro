from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_cyberbro.utils.config import CyberbroConfig


def register_web_tools(mcp: FastMCP, config: CyberbroConfig) -> None:
    @mcp.tool()
    async def get_web_url(analysis_id: str) -> Any:
        """
        Get the web GUI URL for a given analysis ID.
        Args:
            analysis_id: Analysis ID to get the web URL for.
        Returns:
            The web URL from Cyberbro API - Useful for the user to check the results.
        """
        return {"web_url": f"{config.cyberbro_url}/results/{analysis_id}"}
