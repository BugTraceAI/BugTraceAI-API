"""Tests for the BugTraceAI-API provider management contract."""

import json
from pathlib import Path

import pytest


def _fixture_config(tmp_path: Path, monkeypatch):
    import lib.provider as provider

    providers_dir = tmp_path / "providers"
    providers_dir.mkdir()
    source_dir = Path(__file__).parents[1] / "config" / "providers"
    for source in source_dir.glob("*.json"):
        (providers_dir / source.name).write_text(source.read_text(), encoding="utf-8")
    apex_file = tmp_path / "apex.json"
    apex_file.write_text(json.dumps({"enabled": True, "active_provider": "openrouter"}), encoding="utf-8")
    secrets_file = tmp_path / "provider_secrets.json"
    monkeypatch.setattr(provider, "PROVIDERS_DIR", providers_dir)
    monkeypatch.setattr(provider, "APEX_CONFIG_FILE", apex_file)
    monkeypatch.setattr(provider, "SECRETS_FILE", secrets_file)
    monkeypatch.delenv("APEX_PROVIDER", raising=False)
    return provider, apex_file, secrets_file


def test_provider_profiles_do_not_expose_keys(tmp_path, monkeypatch):
    provider, _, _ = _fixture_config(tmp_path, monkeypatch)

    profiles = provider.list_provider_profiles()

    assert {profile["id"] for profile in profiles} == {"anthropic", "local", "openrouter", "zai"}
    assert all("api_key" not in profile for profile in profiles)
    assert all(profile["api_key_configured"] is False for profile in profiles if profile["kind"] != "ollama")


def test_api_key_hint_keeps_only_five_tail_characters():
    from api_server import _mask_api_key

    masked = _mask_api_key("sk-or-v1-secret-abcde")

    assert masked.startswith("sk-o…")
    assert masked.endswith("abcde")
    assert "secret" not in masked
    assert _mask_api_key("short") == "••••"


def test_provider_selection_and_key_persist_without_plain_response(tmp_path, monkeypatch):
    provider, apex_file, secrets_file = _fixture_config(tmp_path, monkeypatch)

    provider.set_provider_api_key("openrouter", "sk-test-provider-secret")
    provider.set_active_provider("openrouter")

    assert json.loads(secrets_file.read_text())["openrouter"] == "sk-test-provider-secret"
    assert json.loads(apex_file.read_text())["active_provider"] == "openrouter"
    assert provider.get_active_provider().api_key == "sk-test-provider-secret"


def test_provider_model_selection_persists_and_is_exposed(tmp_path, monkeypatch):
    provider, apex_file, _ = _fixture_config(tmp_path, monkeypatch)

    selected = provider.set_provider_model("openrouter", "deepseek/deepseek-v4-pro")

    assert selected == "deepseek/deepseek-v4-pro"
    assert provider.get_active_provider().model == selected
    saved = json.loads(apex_file.read_text())
    assert saved["provider_models"]["openrouter"] == selected
    profile = provider.get_provider_profile("openrouter")
    assert profile["model"] == selected
    assert selected in profile["models"]


def test_provider_model_selection_rejects_unknown_model(tmp_path, monkeypatch):
    provider, _, _ = _fixture_config(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="not available"):
        provider.set_provider_model("openrouter", "not-a-real-model")


def test_openrouter_catalog_includes_deepseek_v41_flash(tmp_path, monkeypatch):
    provider, _, _ = _fixture_config(tmp_path, monkeypatch)

    profile = provider.get_provider_profile("openrouter")

    assert profile is not None
    assert "deepseek/deepseek-v4.1-flash" in profile["models"]


def test_provider_model_chain_persists_primary_and_two_fallbacks(tmp_path, monkeypatch):
    provider, apex_file, _ = _fixture_config(tmp_path, monkeypatch)

    selected = provider.set_provider_model_chain(
        "openrouter",
        [
            "google/gemini-3.6-flash",
            "deepseek/deepseek-v4-pro",
            "anthropic/claude-haiku-4.5",
        ],
    )

    assert selected == [
        "google/gemini-3.6-flash",
        "deepseek/deepseek-v4-pro",
        "anthropic/claude-haiku-4.5",
    ]
    active = provider.get_active_provider()
    assert active.model == selected[0]
    assert active.model_failover == selected[1:]
    saved = json.loads(apex_file.read_text())
    assert saved["provider_model_chains"]["openrouter"] == selected
    assert saved["provider_models"]["openrouter"] == selected[0]
    profile = provider.get_provider_profile("openrouter")
    assert profile["model_chain"] == selected


def test_provider_model_chain_rejects_more_than_three_or_duplicates(tmp_path, monkeypatch):
    provider, _, _ = _fixture_config(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="at most three"):
        provider.set_provider_model_chain(
            "openrouter",
            [
                "minimax/minimax-m3",
                "deepseek/deepseek-v4-pro",
                "anthropic/claude-haiku-4.5",
                "openai/gpt-5.5",
            ],
        )

    # Duplicate selections are normalised rather than sent as duplicate calls.
    selected = provider.set_provider_model_chain(
        "openrouter",
        ["minimax/minimax-m3", "deepseek/deepseek-v4-pro", "deepseek/deepseek-v4-pro"],
    )
    assert selected == ["minimax/minimax-m3", "deepseek/deepseek-v4-pro"]


@pytest.mark.asyncio
async def test_provider_routes_return_safe_metadata(tmp_path, monkeypatch):
    _provider, _, _ = _fixture_config(tmp_path, monkeypatch)
    import api_server

    result = await api_server.current_provider()

    assert result["provider"] == "openrouter"
    assert "api_key" not in result
    assert result["api_key_configured"] is False


@pytest.mark.asyncio
async def test_provider_update_route_accepts_ordered_model_chain(tmp_path, monkeypatch):
    provider, _, _ = _fixture_config(tmp_path, monkeypatch)
    import api_server

    result = await api_server.update_provider(api_server.ProviderRequest(
        provider="openrouter",
        models=[
            "google/gemini-3.6-flash",
            "openai/gpt-5.5",
            "anthropic/claude-haiku-4.5",
        ],
    ))

    assert result["model_chain"] == [
        "google/gemini-3.6-flash",
        "openai/gpt-5.5",
        "anthropic/claude-haiku-4.5",
    ]
    assert provider.get_active_provider().model_failover == [
        "openai/gpt-5.5",
        "anthropic/claude-haiku-4.5",
    ]
