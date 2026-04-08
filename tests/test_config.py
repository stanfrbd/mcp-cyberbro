from __future__ import annotations

from argparse import Namespace

import pytest

from mcp_cyberbro.utils.config import _as_bool, resolve_config


def make_args(**overrides):
    base = {
        "cyberbro_url": None,
        "api_prefix": None,
        "no_ssl_verify": False,
        "transport": None,
        "host": None,
        "port": None,
        "mount_path": None,
        "sse_path": None,
        "streamable_http_path": None,
    }
    base.update(overrides)
    return Namespace(**base)


@pytest.mark.parametrize(
    ("value", "default", "expected"),
    [
        (None, True, True),
        (None, False, False),
        ("true", False, True),
        (" YES ", False, True),
        ("0", True, False),
        ("off", True, False),
    ],
)
def test_as_bool(value, default, expected):
    assert _as_bool(value, default=default) is expected


def test_resolve_config_prefers_args_and_normalizes_values(monkeypatch):
    monkeypatch.setenv("CYBERBRO_URL", "http://env.example")
    monkeypatch.setenv("API_PREFIX", "api-env")
    monkeypatch.setenv("SSL_VERIFY", "false")

    args = make_args(
        cyberbro_url="https://cb.local/",
        api_prefix="v2/",
        transport="sse",
        host="127.0.0.1",
        port=9000,
    )

    cfg = resolve_config(args)

    assert cfg.cyberbro_url == "https://cb.local"
    assert cfg.api_prefix == "v2"
    assert cfg.cyberbro_api == "https://cb.local/v2"
    assert cfg.ssl_verify is False
    assert cfg.transport == "sse"
    assert cfg.host == "127.0.0.1"
    assert cfg.port == 9000


def test_resolve_config_uses_env_when_args_missing(monkeypatch):
    monkeypatch.setenv("CYBERBRO_URL", "https://from-env.local/")
    monkeypatch.setenv("API_PREFIX", "custom/")
    monkeypatch.setenv("SSL_VERIFY", "yes")
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_HOST", "0.0.0.0")
    monkeypatch.setenv("MCP_PORT", "8123")
    monkeypatch.setenv("MCP_MOUNT_PATH", "/mcp")
    monkeypatch.setenv("MCP_SSE_PATH", "/sse")
    monkeypatch.setenv("MCP_STREAMABLE_HTTP_PATH", "/stream")

    cfg = resolve_config(make_args())

    assert cfg.cyberbro_url == "https://from-env.local"
    assert cfg.api_prefix == "custom"
    assert cfg.ssl_verify is True
    assert cfg.transport == "streamable-http"
    assert cfg.host == "0.0.0.0"
    assert cfg.port == 8123
    assert cfg.mount_path == "/mcp"
    assert cfg.sse_path == "/sse"
    assert cfg.streamable_http_path == "/stream"


def test_resolve_config_no_ssl_verify_flag_overrides_env(monkeypatch):
    monkeypatch.setenv("CYBERBRO_URL", "https://from-env.local")
    monkeypatch.setenv("SSL_VERIFY", "true")

    cfg = resolve_config(make_args(no_ssl_verify=True))

    assert cfg.ssl_verify is False


def test_resolve_config_requires_cyberbro_url(monkeypatch):
    monkeypatch.delenv("CYBERBRO_URL", raising=False)

    with pytest.raises(ValueError, match="CYBERBRO_URL is required"):
        resolve_config(make_args())
