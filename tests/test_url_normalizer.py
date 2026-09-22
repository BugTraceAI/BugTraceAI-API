"""Tests for URL normalization module."""
import pytest
from lib.url_normalizer import (
    resolve_base_url,
    normalize_openapi_urls,
    extract_canonical_operations,
    validate_url_in_scope,
)


def test_resolve_base_url_with_servers_absolute():
    """servers[0].url as absolute URL takes precedence."""
    spec = {"servers": [{"url": "https://api.example.com/v2"}]}
    assert resolve_base_url(spec, "https://api.example.com/openapi.json", "https://api.example.com/v1") == "https://api.example.com/v2"


def test_resolve_base_url_with_servers_relative():
    """servers[0].url as relative path resolved against target."""
    spec = {"servers": [{"url": "/v2"}]}
    assert resolve_base_url(spec, "https://api.example.com/openapi.json", "https://api.example.com/v1") == "https://api.example.com/v2"


def test_resolve_base_url_with_host_basepath():
    """host + basePath classic fields."""
    spec = {"host": "api.example.com", "basePath": "/v1"}
    assert resolve_base_url(spec, "https://api.example.com/openapi.json", "https://api.example.com/v1") == "https://api.example.com/v1"


def test_resolve_base_url_fallback_to_target():
    """When no servers/host, fallback to target."""
    spec = {}
    assert resolve_base_url(spec, "https://api.example.com/openapi.json", "https://api.example.com/api/v1") == "https://api.example.com/api/v1"


def test_normalize_openapi_urls_ignores_document_path():
    """Operations should never be placed under the document file path."""
    spec = {
        "servers": [{"url": "https://api.example.com/api/v1"}],
        "paths": {
            "/users": {"get": {"operationId": "listUsers"}},
            "/users/{id}": {"get": {"operationId": "getUser"}},
        },
    }
    result = normalize_openapi_urls(spec, "https://api.example.com/openapi.json", "https://api.example.com/api/v1")
    # Should NOT contain openapi.json prefix
    assert not any("/openapi.json/" in url for url in result.values())
    assert "/users" in result
    assert "/users/{id}" in result


def test_validate_url_in_scope():
    """URLs must match allowed hosts."""
    assert validate_url_in_scope("https://api.example.com/users", ["example.com"]) is True
    assert validate_url_in_scope("https://evil.com/users", ["example.com"]) is False
    assert validate_url_in_scope("http://example.com/users", ["example.com"]) is True


def test_extract_canonical_operations():
    """Extract operations with canonical URLs."""
    spec = {
        "servers": [{"url": "https://api.example.com/api/v1"}],
        "paths": {
            "/users": {"get": {"operationId": "listUsers"}},
            "/users/{id}": {"get": {"operationId": "getUser"}},
        },
    }
    ops = extract_canonical_operations(spec, "https://api.example.com/api/v1", "https://api.example.com/openapi.json")
    assert len(ops) == 2
    assert all(op["source"] == "openapi" for op in ops)
    assert all(op["url"].startswith("https://api.example.com/") for op in ops)
    # Check no openapi.json corruption
    assert not any("/openapi.json/" in op["url"] for op in ops)
