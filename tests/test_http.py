from __future__ import annotations

import pytest

from mcp_cyberbro.utils import http


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.raise_called = False

    def raise_for_status(self):
        self.raise_called = True

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, verify, response):
        self.verify = verify
        self.response = response
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json):
        self.calls.append(("post", url, json))
        return self.response

    async def get(self, url):
        self.calls.append(("get", url))
        return self.response


@pytest.mark.asyncio
async def test_post_json_uses_payload_and_returns_json(monkeypatch):
    response = FakeResponse({"ok": True})
    created = {}

    def fake_async_client(*, verify):
        client = FakeClient(verify=verify, response=response)
        created["client"] = client
        return client

    monkeypatch.setattr(http.httpx, "AsyncClient", fake_async_client)

    result = await http.post_json("https://api.local/analyze", payload={"a": 1}, verify=False)

    assert result == {"ok": True}
    assert response.raise_called is True
    assert created["client"].verify is False
    assert created["client"].calls == [("post", "https://api.local/analyze", {"a": 1})]


@pytest.mark.asyncio
async def test_get_json_uses_url_and_returns_json(monkeypatch):
    response = FakeResponse({"status": "done"})
    created = {}

    def fake_async_client(*, verify):
        client = FakeClient(verify=verify, response=response)
        created["client"] = client
        return client

    monkeypatch.setattr(http.httpx, "AsyncClient", fake_async_client)

    result = await http.get_json("https://api.local/results/1", verify=True)

    assert result == {"status": "done"}
    assert response.raise_called is True
    assert created["client"].verify is True
    assert created["client"].calls == [("get", "https://api.local/results/1")]
