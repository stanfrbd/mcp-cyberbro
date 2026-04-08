from __future__ import annotations

import httpx


async def post_json(url: str, payload: dict, verify: bool):
    async with httpx.AsyncClient(verify=verify) as client:
        response = await client.post(url, json=payload)
        response.raise_for_status()
        return response.json()


async def get_json(url: str, verify: bool):
    async with httpx.AsyncClient(verify=verify) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()
