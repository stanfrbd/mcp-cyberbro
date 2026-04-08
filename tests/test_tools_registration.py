from __future__ import annotations

import pytest

from mcp_cyberbro.tools import analysis as analysis_tools
from mcp_cyberbro.tools.engines import ENGINES, register_engine_tools
from mcp_cyberbro.tools.web import register_web_tools
from mcp_cyberbro.utils.config import CyberbroConfig


class FakeMCP:
    def __init__(self):
        self.registered_tools = {}

    def tool(self):
        def decorator(func):
            self.registered_tools[func.__name__] = func
            return func

        return decorator


def make_config() -> CyberbroConfig:
    return CyberbroConfig(cyberbro_url="https://cb.local", api_prefix="api", ssl_verify=False)


@pytest.mark.asyncio
async def test_register_web_tools_returns_result_url():
    mcp = FakeMCP()
    register_web_tools(mcp, make_config())

    result = await mcp.registered_tools["get_web_url"]("A-123")

    assert result == {"web_url": "https://cb.local/results/A-123"}


@pytest.mark.asyncio
async def test_register_analysis_tools_calls_underlying_http_helpers(monkeypatch):
    mcp = FakeMCP()
    config = make_config()
    captured = {}

    async def fake_post_json(url, payload, verify):
        captured["post"] = (url, payload, verify)
        return {"analysis_id": "42"}

    async def fake_get_json(url, verify):
        captured.setdefault("get", []).append((url, verify))
        return {"ok": True, "url": url}

    monkeypatch.setattr(analysis_tools, "post_json", fake_post_json)
    monkeypatch.setattr(analysis_tools, "get_json", fake_get_json)

    analysis_tools.register_analysis_tools(mcp, config)

    analyze_result = await mcp.registered_tools["analyze_observable"]("example.com", ["google"])
    complete_result = await mcp.registered_tools["is_analysis_complete"]("42")
    results_result = await mcp.registered_tools["get_analysis_results"]("42")

    assert analyze_result == {"analysis_id": "42"}
    assert captured["post"] == (
        "https://cb.local/api/analyze",
        {"text": "example.com", "engines": ["google"]},
        False,
    )
    assert complete_result["ok"] is True
    assert results_result["ok"] is True
    assert captured["get"] == [
        ("https://cb.local/api/is_analysis_complete/42", False),
        ("https://cb.local/api/results/42", False),
    ]


@pytest.mark.asyncio
async def test_register_analysis_tools_handles_errors(monkeypatch):
    mcp = FakeMCP()

    async def failing_post_json(url, payload, verify):
        raise RuntimeError("network down")

    monkeypatch.setattr(analysis_tools, "post_json", failing_post_json)

    analysis_tools.register_analysis_tools(mcp, make_config())

    result = await mcp.registered_tools["analyze_observable"]("example.com", ["google"])

    assert "error" in result
    assert "analyze_observable" in result["error"]


@pytest.mark.asyncio
async def test_register_engine_tools_exposes_known_engines():
    mcp = FakeMCP()
    register_engine_tools(mcp)

    result = await mcp.registered_tools["get_engines"]()

    assert result["engines"] == ENGINES
    assert any(engine["name"] == "reverse_dns" for engine in result["engines"])
