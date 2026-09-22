"""Tests for lib.auth_header — the central auth builder."""
from lib.auth_header import auth_cli_flag, auth_header, auth_headers_dict


def test_no_auth_returns_empty():
    """None / empty / tokenless auth all return empty signals."""
    assert auth_header(None) is None
    assert auth_header({}) is None
    assert auth_header({"type": "bearer"}) is None  # missing token
    assert auth_header({"type": "bearer", "token": ""}) is None
    assert auth_headers_dict(None) == {}
    assert auth_cli_flag(None) == []
    assert auth_cli_flag({}) == []


def test_bearer():
    assert auth_header({"type": "bearer", "token": "abc"}) == "Bearer abc"
    assert auth_headers_dict({"type": "bearer", "token": "abc"}) == {"Authorization": "Bearer abc"}
    assert auth_cli_flag({"type": "bearer", "token": "abc"}) == ["-H", "Authorization: Bearer abc"]


def test_basic():
    assert auth_header({"type": "basic", "token": "dXNlcjpwYXNz"}) == "Basic dXNlcjpwYXNz"
    assert auth_cli_flag({"type": "basic", "token": "dXNlcjpwYXNz"}) == [
        "-H", "Authorization: Basic dXNlcjpwYXNz"
    ]


def test_unknown_type_returns_none():
    """Unknown auth types return empty signals, never crash. Callers can add
    a new type in ONE place and every tool gets it."""
    assert auth_header({"type": "digest", "token": "x"}) is None
    assert auth_cli_flag({"type": "digest", "token": "x"}) == []


def test_cookie_and_api_key():
    assert auth_headers_dict({"type": "cookie", "token": "sid=abc"}) == {"Cookie": "sid=abc"}
    assert auth_headers_dict({"type": "cookie", "name": "sid", "token": "abc"}) == {"Cookie": "sid=abc"}
    assert auth_headers_dict({"type": "api_key", "header": "X-API-Key", "token": "k"}) == {"X-API-Key": "k"}
    assert auth_cli_flag({"type": "cookie", "token": "sid=abc"}) == ["-H", "Cookie: sid=abc"]


def test_does_not_mutate_input():
    auth = {"type": "bearer", "token": "abc"}
    headers = auth_headers_dict(auth)
    assert "Authorization" not in auth  # input dict unchanged
    assert headers == {"Authorization": "Bearer abc"}
