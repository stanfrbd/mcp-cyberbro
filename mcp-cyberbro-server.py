import os
from typing import Any
import httpx
import argparse
import json

from mcp.server.fastmcp import FastMCP

ENGINES = [
    {
        "name": "reverse_dns",
        "supports": ["domain", "IP", "abuse"],
        "description": "Performs a reverse DNS lookup (local DNS) for IP, domain, URL (on the Cyberbro machine)",
    },
    {
        "name": "dfir_iris",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Searches DFIR-IRIS globally across all cases for indicators, free, API key required.",
    },
    {"name": "rdap", "supports": ["abuse", "domain"], "description": "Checks RDAP (ex Whois) record for domain, URL"},
    {
        "name": "ipquery",
        "supports": ["IP", "risk", "VPN", "proxy", "geoloc"],
        "description": "Checks IPquery for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "abuseipdb",
        "supports": ["risk", "IP"],
        "description": "Checks AbuseIPDB for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "ipapi",
        "supports": ["IP", "risk", "geoloc", "VPN", "proxy"],
        "description": "Checks IPAPI for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "ipinfo",
        "supports": ["IP", "geoloc"],
        "description": "Checks IPinfo for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "virustotal",
        "supports": ["hash", "risk", "IP", "domain", "URL"],
        "description": "Checks VirusTotal for IP, domain, URL, hash",
    },
    {
        "name": "spur",
        "supports": ["VPN", "proxy", "IP"],
        "description": "Checks Spur.us for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "mde",
        "supports": ["hash", "IP", "domain", "URL"],
        "description": "Checks Microsoft Defender for Endpoint EDR API for IP, domain, URL, hash",
    },
    {
        "name": "crowdstrike",
        "supports": ["hash", "IP", "domain", "URL"],
        "description": "Checks CrowdStrike EDR for IP, domain, URL, hash using Falcon API",
    },
    {
        "name": "google_safe_browsing",
        "supports": ["risk", "domain", "IP", "URL"],
        "description": "Checks Google Safe Browsing for IP, domain, URL",
    },
    {
        "name": "shodan",
        "supports": ["ports", "IP"],
        "description": "Checks Shodan, reversed obtained IP for a given domain/URL",
    },
    {"name": "phishtank", "supports": ["risk", "domain", "URL"], "description": "Checks Phishtank for domains, URL"},
    {
        "name": "threatfox",
        "supports": ["IP", "domain", "URL"],
        "description": "Checks ThreatFox by Abuse.ch for IP, domains, URL",
    },
    {
        "name": "urlscan",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Checks URLscan for all types of observable",
    },
    {
        "name": "google",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Checks Google search results for all types of observable",
    },
    {
        "name": "github",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Get Github grep.app API search results for all types of observable",
    },
    {
        "name": "ioc_one_html",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps (can be long) Ioc.One HTML search results for all types of observable",
    },
    {
        "name": "ioc_one_pdf",
        "supports": ["domain", "URL", "IP", "hash", "chrome_extension_id", "edge_extension_id"],
        "description": "Scraps (can be long) Ioc.One PDF search results for all types of observable",
    },
    {
        "name": "opencti",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Searches OpenCTI results for all types of observable",
    },
    {
        "name": "abusix",
        "supports": ["abuse", "IP"],
        "description": "Checks abuse contact with Abusix for IP, reversed obtained IP for a given domain/URL",
    },
    {
        "name": "hudsonrock",
        "supports": ["domain", "URL", "email", "infostealers", "malware"],
        "description": "Searches Hudson Rock results for domains, URL, Email",
    },
    {
        "name": "webscout",
        "supports": ["IP", "risk", "geoloc", "VPN", "proxy"],
        "description": "Checks WebScout for IP, reversed obtained IP for a given domain / URL",
    },
    {
        "name": "criminalip",
        "supports": ["IP", "risk", "VPN", "proxy"],
        "description": "Checks CriminalIP for IP, reversed obtained IP for a given domain / URL",
    },
    {
        "name": "alienvault",
        "supports": ["IP", "domain", "URL", "hash", "risk"],
        "description": "Checks Alienvault for IP, domain, URL, hash",
    },
    {
        "name": "misp",
        "supports": ["IP", "domain", "URL", "hash"],
        "description": "Checks MISP for IP, domain, URL, hash",
    },
    {
        "name": "google_dns",
        "supports": ["IP", "domain", "URL"],
        "description": "Checks Google common DNS records (A, AAAA, CNAME, NS, MX, TXT, PTR) for IP, domain, URL",
    },
    {"name": "crtsh", "supports": ["domain", "URL"], "description": "Checks crt.sh for domain, URL"},
    {
        "name": "rl_analyze",
        "supports": ["domain", "URL", "IP", "hash"],
        "description": "Looks up observables in the Reversing Labs Spectra Analyze service",
    },
    {
        "name": "bad_asn",
        "supports": ["IP", "risk"],
        "description": "Malicious ASN detection (free). Checks if IP's ASN is listed in Spamhaus ASNDROP or Brianhama Bad ASN databases. Requires ipapi, ipinfo to be selected to get the ASN. Free, no API key",
    },
]

mcp = FastMCP("CyberbroMCP")

# --- MCP tool functions for the existing tools in list_tools ---


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
        async with httpx.AsyncClient(verify=SSL_VERIFY) as client:
            payload = {"text": text, "engines": engines}
            response = await client.post(f"{CYBERBRO_API}/analyze", json=payload)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": f"Error executing tool analyze_observable: {str(e)}"}


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
        async with httpx.AsyncClient(verify=SSL_VERIFY) as client:
            response = await client.get(f"{CYBERBRO_API}/is_analysis_complete/{analysis_id}")
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": f"Error executing tool is_analysis_complete: {str(e)}"}


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
        async with httpx.AsyncClient(verify=SSL_VERIFY) as client:
            response = await client.get(f"{CYBERBRO_API}/results/{analysis_id}")
            response.raise_for_status()
            return response.json()
    except Exception as e:
        return {"error": f"Error executing tool get_analysis_results: {str(e)}"}


@mcp.tool()
async def get_engines() -> Any:
    """
    List available Cyberbro engines.
    This is the first tool to be called to get the usable engines.
    Returns:
        The list of engines.
    """
    try:
        return {"engines": ENGINES}
    except Exception as e:
        return {"error": f"Error executing tool get_engines: {str(e)}"}


@mcp.tool()
async def get_web_url(analysis_id: str) -> Any:
    """
    Get the web GUI URL for a given analysis ID.
    Args:
        analysis_id: Analysis ID to get the web URL for.
    Returns:
        The web URL from Cyberbro API - Useful for the user to check the results.
    """
    try:
        return {"web_url": f"{CYBERBRO_URL}/results/{analysis_id}"}
    except Exception as e:
        return {"error": f"Error executing tool get_web_url: {str(e)}"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyberbro MCP Server")
    parser.add_argument(
        "--cyberbro_url", type=str, required=False, help="Base URL for Cyberbro API (env: CYBERBRO_URL)"
    )
    parser.add_argument(
        "--api_prefix", required=False, type=str, default=None, help="API prefix path (env: API_PREFIX, default: api)"
    )
    parser.add_argument(
        "--no_ssl_verify",
        required=False,
        action="store_true",
        help="Disable SSL verification (env: SSL_VERIFY), defaults to verified",
    )
    args = parser.parse_args()

    # Determine CYBERBRO_URL from args or environment, ensuring no trailing slash
    CYBERBRO_URL = (args.cyberbro_url.rstrip("/") if args.cyberbro_url else None) or (
        os.environ.get("CYBERBRO_URL", "").rstrip("/") or None
    )
    # Determine API_PREFIX from args or environment, defaulting to "api", ensuring no trailing slash
    API_PREFIX = (args.api_prefix.rstrip("/") if args.api_prefix else "api") or os.environ.get(
        "API_PREFIX", "api"
    ).rstrip("/")

    if not CYBERBRO_URL:
        raise ValueError("cyberbro_url must be provided as --cyberbro_url or CYBERBRO_URL env variable")

    CYBERBRO_API = CYBERBRO_URL + "/" + API_PREFIX
    SSL_VERIFY = (not args.no_ssl_verify if args.no_ssl_verify else True) and os.environ.get(
        "SSL_VERIFY", "true"
    ).lower() == "true"
    mcp.run(transport="stdio")
