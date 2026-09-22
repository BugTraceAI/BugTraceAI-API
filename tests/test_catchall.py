"""Catch-all / empty-body discovery noise — generic, not target-specific."""
import pytest

from lib.catchall import filter_noise, is_noise_endpoint, is_placeholder_body, origin_candidates


def test_placeholder_empty_and_not_found_json():
    assert is_placeholder_body(b"")
    assert is_placeholder_body(b"\n")
    assert is_placeholder_body(b'{"error":"Not found"}')
    assert is_placeholder_body('{"detail":"Not Found"}')
    assert not is_placeholder_body(b'{"id":7,"owner":"a"}')


def test_wordlist_tiny_200_is_noise_even_if_baseline_was_405():
    baseline = {"status": 405, "length": 31, "catch_all": False, "signatures": [
        {"status": 405, "length": 31, "hash": "abc"}
    ]}
    ep = {"method": "GET", "status": 200, "url": "https://api.example.com/LoadModule", "size": 1, "source": "wordlist"}
    assert is_noise_endpoint(ep, baseline)


def test_matching_hash_is_noise():
    baseline = {"catch_all": True, "signatures": [{"status": 200, "length": 21, "hash": "c8d3eae160a892e3"}]}
    ep = {"method": "GET", "status": 200, "size": 21, "body_hash": "c8d3eae160a892e3", "source": "crawl"}
    assert is_noise_endpoint(ep, baseline)


def test_real_json_200_is_kept():
    baseline = {"catch_all": True, "signatures": [{"status": 200, "length": 1, "hash": "deadbeef"}]}
    ep = {
        "method": "GET",
        "status": 200,
        "size": 120,
        "body_hash": "aaaaaaaaaaaaaaaa",
        "source": "crawl",
        "url": "https://api.example.com/users",
    }
    assert not is_noise_endpoint(ep, baseline)
    kept, discarded = filter_noise([ep, {"method": "GET", "status": 200, "size": 1, "source": "wordlist"}], baseline)
    assert len(kept) == 1
    assert len(discarded) == 1


@pytest.mark.asyncio
async def test_published_spec_runs_schema_tools_even_with_zero_live_endpoints(scan_state):
    """Tools-then-exploit: a real OpenAPI is enough. Empty crawl must not skip vulnapi/offat."""
    from unittest.mock import AsyncMock, patch

    from lib.evidence import save_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("atk0", "https://api.example.com")
    save_artifact("atk0", "discovery", "all_endpoints", [])
    save_artifact("atk0", "schema_probe", "schema_decision", {
        "has_schema": True,
        "parsed": True,
        "paths_count": 12,
        "coverage": 0.8,
        "url": "https://api.example.com/openapi.json",
        "source": "discovered",
    })
    save_artifact("atk0", "schema_probe", "published_openapi", {
        "openapi": "3.0.0",
        "paths": {"/items": {"get": {}}},
    })
    called = {}

    async def mark_schema(*_a, **_k):
        called["schema"] = True

    async def mark_auth(*_a, **_k):
        called["auth"] = True
        return []

    async def mark_authz(*_a, **_k):
        called["authz"] = True
        return []

    with patch("orchestrator.run_schema_attack", side_effect=mark_schema), \
         patch("orchestrator.run_auth_probe", side_effect=mark_auth), \
         patch("orchestrator.run_authz_probe", side_effect=mark_authz), \
         patch("orchestrator.run_blind_attack", new_callable=AsyncMock):
        await orch._phase_attacks("atk0", "https://api.example.com", None)

    assert called.get("schema") is True
    assert called.get("auth") is True
    assert called.get("authz") is True


def test_origin_candidates_include_host_root():
    assert origin_candidates("https://api.example.com/api/v1") == [
        "https://api.example.com/api/v1",
        "https://api.example.com",
    ]
