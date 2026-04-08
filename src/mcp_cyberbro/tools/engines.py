from __future__ import annotations

from typing import Any

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
    {
        "name": "rdap",
        "supports": ["abuse", "domain"],
        "description": "Checks RDAP (ex Whois) record for domain, URL",
    },
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
    {
        "name": "phishtank",
        "supports": ["risk", "domain", "URL"],
        "description": "Checks Phishtank for domains, URL",
    },
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
    {
        "name": "crtsh",
        "supports": ["domain", "URL"],
        "description": "Checks crt.sh for domain, URL",
    },
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
    {
        "name": "rosti",
        "supports": ["domain", "URL", "IP", "email", "hash", "risk"],
        "description": "IOC search and enrichment. Searches Rosti IOC data for domains, URLs, IPs, emails, and hashes (MD5, SHA1, SHA256), API key required",
    },
]


def register_engine_tools(mcp: FastMCP) -> None:
    @mcp.tool()
    async def get_engines() -> Any:
        """
        List available Cyberbro engines.
        This is the first tool to be called to get the usable engines.
        Returns:
            The list of engines.
        """
        return {"engines": ENGINES}
