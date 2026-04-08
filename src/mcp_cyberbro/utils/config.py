from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class CyberbroConfig:
    cyberbro_url: str
    api_prefix: str = "api"
    ssl_verify: bool = True
    transport: str = "stdio"
    host: str | None = None
    port: int | None = None
    mount_path: str | None = None
    sse_path: str | None = None
    streamable_http_path: str | None = None

    @property
    def cyberbro_api(self) -> str:
        return f"{self.cyberbro_url}/{self.api_prefix}"


def _as_bool(value: str, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def resolve_config(args) -> CyberbroConfig:
    cyberbro_url = (args.cyberbro_url.rstrip("/") if args.cyberbro_url else None) or (
        os.environ.get("CYBERBRO_URL", "").rstrip("/") or None
    )
    if not cyberbro_url:
        raise ValueError("CYBERBRO_URL is required (use --cyberbro_url or env var)")

    api_prefix = (args.api_prefix.rstrip("/") if args.api_prefix else None) or os.environ.get(
        "API_PREFIX", "api"
    ).rstrip("/")
    ssl_verify = (
        False if args.no_ssl_verify else _as_bool(os.environ.get("SSL_VERIFY"), default=True)
    )

    transport = args.transport or os.environ.get("MCP_TRANSPORT", "stdio")
    host = args.host or os.environ.get("MCP_HOST")
    port = args.port or (int(os.environ["MCP_PORT"]) if os.environ.get("MCP_PORT") else None)
    mount_path = args.mount_path or os.environ.get("MCP_MOUNT_PATH")
    sse_path = args.sse_path or os.environ.get("MCP_SSE_PATH")
    streamable_http_path = args.streamable_http_path or os.environ.get("MCP_STREAMABLE_HTTP_PATH")

    return CyberbroConfig(
        cyberbro_url=cyberbro_url,
        api_prefix=api_prefix,
        ssl_verify=ssl_verify,
        transport=transport,
        host=host,
        port=port,
        mount_path=mount_path,
        sse_path=sse_path,
        streamable_http_path=streamable_http_path,
    )
