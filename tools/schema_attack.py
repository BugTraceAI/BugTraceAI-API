"""DEPRECATED: this module is a thin re-export shim.

The implementation was split into per-tool files under ``tools/attack/`` so each
schema-based scanner (schemathesis, offat, vulnapi) lives in its own module and
can evolve independently. This shim keeps the old import paths working for
external callers and any leftover references in the orchestrator and tests.
"""
from tools.attack import (  # noqa: F401 — re-export public entry points
    run_offat,
    run_schema_attack,
    run_schemathesis,
    run_vulnapi,
)
from tools.attack.offat import (  # noqa: F401
    _OFFAT_BENIGN_STATUSES,
    _OFFAT_FP_PATTERNS,
    _OFFAT_SEVERITY_KEYWORDS,
    _infer_offat_severity,
    _is_offat_false_positive,
    _parse_offat_output,
)

# Re-export private parsers/filters too, because the test suite and any
# downstream callers reach into them. The implementations live in
# ``tools/attack/<tool>.py``; this shim mirrors the original public surface.
from tools.attack.schemathesis import _parse_schemathesis_output  # noqa: F401
from tools.attack.vulnapi import (  # noqa: F401
    _parse_vulnapi_output,
    _vulnapi_auth_flags_openapi,
    _vulnapi_base_flags,
)
