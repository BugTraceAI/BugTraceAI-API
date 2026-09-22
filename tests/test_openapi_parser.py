"""OpenAPI/Swagger parsing: JSON, YAML, $ref, diagnostics, method filter."""
import pytest

from lib.http_policy import SAFE_METHODS, is_allowed
from lib.openapi import (
    count_operations,
    count_paths,
    extract_operations,
    extract_swagger_ui_spec_urls,
    filter_spec_methods,
    parse_openapi,
    resolve_refs,
)

YAML_SPEC = """
openapi: 3.0.0
info:
  title: Demo
  version: 1.0.0
paths:
  /users:
    get:
      responses:
        "200":
          description: ok
    post:
      security: []
      responses:
        "201":
          description: created
  /users/{id}:
    get:
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
      security:
        - bearerAuth: []
      responses:
        "200":
          description: ok
components:
  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
"""

JSON_WITH_REF = {
    "openapi": "3.0.0",
    "info": {"title": "ref", "version": "1.0.0"},
    "paths": {
        "/pets": {
            "get": {
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Pet"}
                            }
                        },
                    }
                }
            }
        }
    },
    "components": {
        "schemas": {
            "Pet": {"type": "object", "properties": {"id": {"type": "integer"}}},
        }
    },
}

SWAGGER2 = {
    "swagger": "2.0",
    "info": {"title": "s2", "version": "1.0"},
    "host": "api.example.com",
    "basePath": "/v1",
    "paths": {"/items": {"get": {"responses": {"200": {"description": "ok"}}}}},
}


def test_parse_yaml_counts_paths_and_operations():
    doc = parse_openapi(YAML_SPEC, content_type="application/yaml", url="https://ex/openapi.yaml")
    assert doc.parsed is True
    assert doc.format == "yaml"
    assert doc.paths_count == 2
    assert doc.operations_count == 3
    assert doc.parse_error is None


def test_parse_json_with_internal_ref():
    import json
    doc = parse_openapi(json.dumps(JSON_WITH_REF), content_type="application/json")
    assert doc.parsed
    assert doc.paths_count == 1
    assert doc.operations_count == 1
    resolved, stats = resolve_refs(JSON_WITH_REF)
    schema = resolved["paths"]["/pets"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert schema.get("type") == "object"
    assert "id" in schema.get("properties", {})
    assert stats["internal"] >= 1


def test_parse_swagger2():
    import json
    doc = parse_openapi(json.dumps(SWAGGER2), content_type="text/plain", url="https://ex/swagger")
    assert doc.parsed
    assert doc.paths_count == 1
    ops = extract_operations(doc.spec, "https://ignored")
    assert ops[0]["url"].startswith("https://api.example.com/v1")


def test_html_is_not_a_spec():
    doc = parse_openapi("<html><title>Swagger UI</title></html>", content_type="text/html")
    assert doc.parsed is False
    assert doc.paths_count == 0


def test_filter_spec_methods_drops_post():
    doc = parse_openapi(YAML_SPEC, content_type="application/yaml")
    filtered = filter_spec_methods(doc.spec, SAFE_METHODS)
    assert "post" not in filtered["paths"]["/users"]
    assert "get" in filtered["paths"]["/users"]
    assert count_operations(filtered) == 2
    assert count_paths(filtered) == 2


def test_extract_operations_auth_flags():
    doc = parse_openapi(YAML_SPEC, content_type="application/yaml")
    ops = extract_operations(doc.spec, "https://api.example.com")
    by_key = {(o["method"], o["path"]): o for o in ops}
    assert by_key[("POST", "/users")]["auth_required"] is False
    assert by_key[("GET", "/users/{id}")]["auth_required"] is True
    assert by_key[("GET", "/users")]["auth_required"] is None


def test_swagger_ui_url_extraction_uses_urljoin():
    html = """
    <script>
    const ui = SwaggerUIBundle({
      url: "/v3/api-docs",
      urls: [{ url: "./openapi.yaml", name: "default" }]
    })
    </script>
    """
    urls = extract_swagger_ui_spec_urls(html, "https://api.example.com/docs/")
    assert "https://api.example.com/v3/api-docs" in urls
    assert "https://api.example.com/docs/openapi.yaml" in urls


@pytest.mark.asyncio
async def test_probe_schema_yaml_sets_nonzero_paths_count(monkeypatch):
    """Regression: YAML specs used to land as content=str and paths_count=0."""
    import httpx

    from lib.schema_probe import probe_schema

    yaml_body = YAML_SPEC.encode()

    class FakeResponse:
        status_code = 200
        content = yaml_body
        text = YAML_SPEC
        headers = {"content-type": "application/yaml"}
        url = "https://api.example.com/openapi.yaml"

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False
        async def get(self, url):
            if url.endswith("/openapi.yaml"):
                return FakeResponse()
            other = FakeResponse()
            other.status_code = 404
            other.content = b""
            other.text = ""
            return other

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    result = await probe_schema("https://api.example.com")
    assert result is not None
    assert result["parsed"] is True
    assert result["format"] == "yaml"
    assert result["paths_count"] == 2
    assert result["operations_count"] == 3
    assert isinstance(result["content"], dict)
    assert result["source"] == "discovered"


def test_join_spec_url_does_not_double_api_prefix():
    from lib.openapi import join_spec_url

    target = "https://api.example.com/api/v1"
    assert join_spec_url(target, "/api/user/profile") == "https://api.example.com/api/user/profile"
    assert join_spec_url(target, "/api/items/") == "https://api.example.com/api/items/"
    assert join_spec_url("https://api.example.com/v1", "/users") == "https://api.example.com/v1/users"


def test_redact_does_not_eat_http_method_after_token_word():
    from lib.redact import redact_text

    title = "Spec-protected operation returned 2xx without a token: GET /api/user/profile"
    assert "GET" in redact_text(title)
    assert "Bearer supersecret-token-value" not in redact_text("Authorization: Bearer supersecret-token-value")


def test_http_policy_blocks_mutating_by_default():
    assert is_allowed("GET", False)
    assert is_allowed("OPTIONS", False)
    assert not is_allowed("POST", False)
    assert not is_allowed("DELETE", False)
    assert is_allowed("POST", True)
