from __future__ import annotations

from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_cyberbro.utils.config import CyberbroConfig
from mcp_cyberbro.utils.http import get_json, post_json


def register_analysis_tools(mcp: FastMCP, config: CyberbroConfig) -> None:
    @mcp.tool()
    async def analyze_observable(text: str, engines: list[str]) -> Any:
        """
        Trigger an analysis for a given observable (IP, domain, URL, hash, chrome extension id) using Cyberbro.
        It can support multiple observables at once separated by spaces.
        Args:
            text: Observable(s) to analyze.
            engines: List of engine names.
        Returns:
            The analysis response from Cyberbro API.
        """
        try:
            payload = {"text": text, "engines": engines}
            return await post_json(
                f"{config.cyberbro_api}/analyze", payload=payload, verify=config.ssl_verify
            )
        except Exception as exc:
            return {"error": f"Error executing tool analyze_observable: {exc!s}"}

    @mcp.tool()
    async def is_analysis_complete(analysis_id: str) -> Any:
        """
        Check if the analysis is complete for the given analysis_id.
        Args:
            analysis_id: Analysis ID to check.
        Returns:
            The completion status from Cyberbro API.
        """
        try:
            return await get_json(
                f"{config.cyberbro_api}/is_analysis_complete/{analysis_id}",
                verify=config.ssl_verify,
            )
        except Exception as exc:
            return {"error": f"Error executing tool is_analysis_complete: {exc!s}"}

    @mcp.tool()
    async def get_analysis_results(analysis_id: str) -> Any:
        """
        Retrieve the results of a previous analysis by analysis_id.
        Args:
            analysis_id: Analysis ID to retrieve results for.
        Returns:
            The analysis results from Cyberbro API.
        """
        try:
            return await get_json(
                f"{config.cyberbro_api}/results/{analysis_id}", verify=config.ssl_verify
            )
        except Exception as exc:
            return {"error": f"Error executing tool get_analysis_results: {exc!s}"}
