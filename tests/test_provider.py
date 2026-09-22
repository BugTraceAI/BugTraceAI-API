"""Tests for the Anthropic provider integration (lib.provider + lib.apex_client).

Covers:
 1. get_active_provider resolves config/providers/anthropic.json + env overrides
 2. is_available gates on api_key/base_url for the anthropic kind
 3. _call_anthropic sends x-api-key/anthropic-version and parses text content blocks
 4. _call_anthropic ignores non-text content blocks (e.g. future block types)
 5. _generate_once dispatches "anthropic" kind to _call_anthropic, not _call_openai
 6. _generate walks the failover chain when the primary Anthropic model errors
"""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest


def test_ai_endpoint_uses_target_when_scanner_stored_reference_url():
    from lib.apex_client import _finding_endpoint, build_prompt

    finding = {
        "title": "CORS headers are missing",
        "endpoint": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
        "evidence": {"status": 200},
    }
    target = "https://example.test/api/v1"

    assert _finding_endpoint(finding, target) == target
    prompt = build_prompt(finding, target)
    assert target in prompt
    assert f"- Endpoint: {target}" in prompt


def test_markdown_report_uses_target_for_reference_endpoint():
    from lib.evidence import render_scan_markdown

    target = "https://example.test/api/v1"
    markdown = render_scan_markdown(
        scan_id="scan-reference-endpoint",
        target=target,
        status={"status": "completed"},
        findings=[{
            "title": "Missing CORS header",
            "severity": "medium",
            "endpoint": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin",
        }],
        endpoints=[],
    )

    assert f"- **Endpoint:** `{target}`" in markdown
    assert "developer.mozilla.org" not in markdown
    assert "## Insufficient evidence" in markdown or "## Hardening" in markdown or "## Unclassified" in markdown


def test_markdown_report_normalizes_ai_poc_endpoint_header():
    from lib.evidence import render_scan_markdown

    target = "https://example.test/api/v1"
    markdown = render_scan_markdown(
        scan_id="scan-ai-reference-endpoint",
        target=target,
        status={"status": "completed"},
        findings=[],
        endpoints=[],
        ai_analysis={"pocs": [{
            "title": "Missing header",
            "endpoint": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
            "poc": "**Endpoint:** https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options\n\nDetails.",
        }]},
    )

    assert f"**Endpoint:** {target}" in markdown


# ────────────────────────────────────────────────────────────────────────────
# Test 1: provider resolution from config/providers/anthropic.json
# ────────────────────────────────────────────────────────────────────────────

def test_get_active_provider_resolves_anthropic(monkeypatch):
    from lib.provider import get_active_provider

    monkeypatch.setenv("APEX_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test123")

    p = get_active_provider()

    assert p.id == "anthropic"
    assert p.kind == "anthropic"
    assert p.base_url == "https://api.anthropic.com/v1/messages"
    assert p.model == "claude-haiku-4-5"
    assert p.model_failover == ["claude-sonnet-5"]
    assert p.api_key == "sk-ant-test123"


def test_get_active_provider_anthropic_missing_key(monkeypatch):
    """No ANTHROPIC_API_KEY set → api_key resolves to None, not a crash or leaked key."""
    from lib.provider import get_active_provider

    monkeypatch.setenv("APEX_PROVIDER", "anthropic")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    p = get_active_provider()

    assert p.kind == "anthropic"
    assert p.api_key is None


# ────────────────────────────────────────────────────────────────────────────
# Test 2: is_available gating for the anthropic kind
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_available_anthropic_no_key():
    from lib.apex_client import is_available
    from lib.provider import Provider

    p = Provider(id="anthropic", name="Anthropic", kind="anthropic",
                 base_url="https://api.anthropic.com/v1/messages", model="claude-haiku-4-5",
                 api_key=None)
    assert await is_available(p) is False


@pytest.mark.asyncio
async def test_is_available_anthropic_with_key():
    from lib.apex_client import is_available
    from lib.provider import Provider

    p = Provider(id="anthropic", name="Anthropic", kind="anthropic",
                 base_url="https://api.anthropic.com/v1/messages", model="claude-haiku-4-5",
                 api_key="sk-ant-test123")
    assert await is_available(p) is True


# ────────────────────────────────────────────────────────────────────────────
# Test 3/4: _call_anthropic request shape + response parsing
# ────────────────────────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("error", request=None, response=self)

    def json(self):
        return self._json


class _FakeAsyncClient:
    """Minimal async context-manager stand-in for httpx.AsyncClient."""

    def __init__(self, captured, response):
        self._captured = captured
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        self._captured["url"] = url
        self._captured["json"] = json
        self._captured["headers"] = headers
        return self._response


@pytest.mark.asyncio
async def test_call_anthropic_sends_native_headers_and_payload():
    from lib.apex_client import _call_anthropic
    from lib.provider import Provider

    p = Provider(id="anthropic", name="Anthropic", kind="anthropic",
                 base_url="https://api.anthropic.com/v1/messages", model="claude-haiku-4-5",
                 api_key="sk-ant-test123", options={"max_tokens": 999})

    captured = {}
    fake_response = _FakeResponse({"content": [{"type": "text", "text": "PoC steps..."}]})

    with patch("lib.apex_client.httpx.AsyncClient", lambda timeout: _FakeAsyncClient(captured, fake_response)):
        result = await _call_anthropic("analyze this finding", p, "claude-haiku-4-5")

    assert result == "PoC steps..."
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "sk-ant-test123"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in captured["headers"]  # not OpenAI-style bearer auth
    assert captured["json"]["model"] == "claude-haiku-4-5"
    assert captured["json"]["max_tokens"] == 999
    assert captured["json"]["messages"] == [{"role": "user", "content": "analyze this finding"}]


@pytest.mark.asyncio
async def test_call_anthropic_concatenates_text_blocks_and_skips_others():
    from lib.apex_client import _call_anthropic
    from lib.provider import Provider

    p = Provider(id="anthropic", name="Anthropic", kind="anthropic",
                 base_url="https://api.anthropic.com/v1/messages", model="claude-haiku-4-5",
                 api_key="sk-ant-test123")

    captured = {}
    fake_response = _FakeResponse({"content": [
        {"type": "text", "text": "Step 1. "},
        {"type": "some_future_block_type", "data": "ignore me"},
        {"type": "text", "text": "Step 2."},
    ]})

    with patch("lib.apex_client.httpx.AsyncClient", lambda timeout: _FakeAsyncClient(captured, fake_response)):
        result = await _call_anthropic("prompt", p, "claude-haiku-4-5")

    assert result == "Step 1. Step 2."


# ────────────────────────────────────────────────────────────────────────────
# Test 5: dispatch routes "anthropic" kind to _call_anthropic
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_once_dispatches_anthropic_kind():
    from lib.apex_client import _generate_once
    from lib.provider import Provider

    p = Provider(id="anthropic", name="Anthropic", kind="anthropic",
                 base_url="https://api.anthropic.com/v1/messages", model="claude-haiku-4-5",
                 api_key="sk-ant-test123")

    with patch("lib.apex_client._call_anthropic", new_callable=AsyncMock, return_value="ok") as m_anthropic, \
         patch("lib.apex_client._call_openai", new_callable=AsyncMock) as m_openai, \
         patch("lib.apex_client._call_ollama", new_callable=AsyncMock) as m_ollama:
        result = await _generate_once("prompt", p, "claude-haiku-4-5")

    assert result == "ok"
    m_anthropic.assert_awaited_once()
    m_openai.assert_not_awaited()
    m_ollama.assert_not_awaited()


# ────────────────────────────────────────────────────────────────────────────
# Test 6: failover chain — primary Anthropic model errors, fallback succeeds
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_generate_failover_across_anthropic_models():
    from lib.apex_client import _generate
    from lib.provider import Provider

    p = Provider(id="anthropic", name="Anthropic", kind="anthropic",
                 base_url="https://api.anthropic.com/v1/messages",
                 model="claude-haiku-4-5", model_failover=["claude-sonnet-5"],
                 api_key="sk-ant-test123")

    async def fake_generate_once(prompt, provider, model):
        if model == "claude-haiku-4-5":
            raise httpx.HTTPStatusError("529 overloaded", request=None, response=_FakeResponse({}, 529))
        return "fallback PoC text"

    with patch("lib.apex_client._generate_once", side_effect=fake_generate_once):
        gen = await _generate("prompt", p, scan_id="t-anthropic-failover")

    assert gen["text"] == "fallback PoC text"
    assert gen["model"] == "claude-sonnet-5"
    assert "claude-haiku-4-5 (error)" in gen["refused_chain"]


@pytest.mark.asyncio
async def test_analyze_findings_streams_partial_results_with_bounded_concurrency():
    from lib.apex_client import analyze_findings
    from lib.provider import Provider
    import lib.apex_client as apex_client

    provider = Provider(
        id="fake", name="Fake", kind="anthropic", base_url="https://example.test",
        model="fake", api_key="test-key",
    )
    active = 0
    peak = 0

    async def fake_generate(*_args, **_kwargs):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.01)
        active -= 1
        return {"text": "safe analysis", "model": "fake", "refused_chain": []}

    async def fake_replay(*_args, **_kwargs):
        return {"status": "skipped", "confirmed": False}

    async def fake_review(*_args, **_kwargs):
        return {"status": "ok", "text": "review"}

    findings = [
        {"id": f"F-{i}", "title": "candidate", "severity": "medium", "category": "api", "endpoint": "https://example.test"}
        for i in range(8)
    ]
    callbacks = []
    async def on_result(result):
        callbacks.append(result["finding_id"])

    with patch.object(apex_client, "is_available", return_value=True), \
         patch.object(apex_client, "_generate", side_effect=fake_generate), \
         patch.object(apex_client, "replay_safe_poc", side_effect=fake_replay), \
         patch.object(apex_client, "review_generated_poc", side_effect=fake_review), \
         patch.object(apex_client, "APEX_CONCURRENCY", 2):
        result = await analyze_findings(
            findings, target="https://example.test", provider=provider,
            scan_id="bounded", on_result=on_result,
        )

    assert [item["finding_id"] for item in result] == [f"F-{i}" for i in range(8)]
    assert sorted(callbacks) == [f"F-{i}" for i in range(8)]
    assert 1 < peak <= 2
