from __future__ import annotations

import argparse

from mcp_cyberbro.server import run_server
from mcp_cyberbro.utils.config import resolve_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cyberbro MCP Server")
    parser.add_argument(
        "--transport",
        required=False,
        type=str,
        choices=["stdio", "sse", "streamable-http"],
        default=None,
        help="MCP transport to use (env: MCP_TRANSPORT, default: stdio)",
    )
    parser.add_argument(
        "--host",
        required=False,
        type=str,
        default=None,
        help="Host for HTTP transports (env: MCP_HOST, default: SDK default)",
    )
    parser.add_argument(
        "--port",
        required=False,
        type=int,
        default=None,
        help="Port for HTTP transports (env: MCP_PORT, default: SDK default)",
    )
    parser.add_argument(
        "--mount_path",
        required=False,
        type=str,
        default=None,
        help="Mount path for SSE transport (env: MCP_MOUNT_PATH, default: SDK default)",
    )
    parser.add_argument(
        "--sse_path",
        required=False,
        type=str,
        default=None,
        help="SSE endpoint path for SSE transport (env: MCP_SSE_PATH, default: SDK default)",
    )
    parser.add_argument(
        "--streamable_http_path",
        required=False,
        type=str,
        default=None,
        help="Endpoint path for streamable-http transport (env: MCP_STREAMABLE_HTTP_PATH, default: SDK default)",
    )
    parser.add_argument(
        "--cyberbro_url",
        type=str,
        required=False,
        help="Base URL for Cyberbro API (env: CYBERBRO_URL)",
    )
    parser.add_argument(
        "--api_prefix",
        required=False,
        type=str,
        default=None,
        help="API prefix path (env: API_PREFIX, default: api)",
    )
    parser.add_argument(
        "--no_ssl_verify",
        required=False,
        action="store_true",
        help="Disable SSL verification, default is enabled",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config = resolve_config(args)
    run_server(config)
