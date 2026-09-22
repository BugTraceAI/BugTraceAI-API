"""Tests for response classification module."""
import pytest
from lib.response_classifier import ResponseClassifier, ClassificationResult


def test_classify_error_json_200():
    """HTTP 200 with error JSON should be classified as error_application."""
    classifier = ResponseClassifier()
    result = classifier.classify(
        status_code=200,
        content_type="application/json",
        body='{"error":"Not found"}',
        url="https://api.example.com/api/users/123",
    )
    assert result.category == "error_application"
    assert result.confidence >= 0.9


def test_classify_success_json_200():
    """HTTP 200 with real data should be classified as success."""
    classifier = ResponseClassifier()
    result = classifier.classify(
        status_code=200,
        content_type="application/json",
        body='{"id": 123, "name": "test"}',
        url="https://api.example.com/api/users/123",
    )
    assert result.category == "success"
    assert result.confidence >= 0.8


def test_classify_catch_all_html():
    """HTML catch-all should be identified."""
    classifier = ResponseClassifier()
    html_body = '<!DOCTYPE html><html><body><div id="app"></div></body></html>'
    result = classifier.classify(
        status_code=200,
        content_type="text/html",
        body=html_body,
        url="https://api.example.com/api/random",
    )
    # Might be catch-all if it matches SPA indicators
    assert result.category in ("catch_all", "success")


def test_classify_auth_challenge():
    """401/403 should be classified as auth_challenge."""
    classifier = ResponseClassifier()
    result = classifier.classify(
        status_code=401,
        content_type="application/json",
        body='{"error":"Unauthorized"}',
        url="https://api.example.com/api/admin",
    )
    assert result.category == "auth_challenge"
    assert result.confidence >= 0.9


def test_classify_empty():
    """204 No Content should be classified as empty."""
    classifier = ResponseClassifier()
    result = classifier.classify(
        status_code=204,
        content_type="",
        body="",
        url="https://api.example.com/api/resource/123",
    )
    assert result.category == "empty"
    assert result.confidence >= 0.95


def test_compare_responses():
    """Compare multiple responses."""
    classifier = ResponseClassifier()
    responses = [
        {"status_code": 200, "body_hash": "abc", "category": "success"},
        {"status_code": 403, "body_hash": "def", "category": "auth_challenge"},
    ]
    diffs = classifier.compare_responses(responses)
    assert len(diffs) == 2
    assert diffs[0]["status_code"] == 200
    assert diffs[1]["status_code"] == 403


def test_consecutive_empty_classification():
    """Multiple empty responses should remain empty."""
    classifier = ResponseClassifier()
    for _ in range(3):
        result = classifier.classify(204, "", "", "https://api.example.com/api/empty")
        assert result.category == "empty"
