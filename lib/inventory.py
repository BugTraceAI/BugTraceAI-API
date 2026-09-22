"""Canonical, scoped operation inventory; discovery is not proof of existence."""
from urllib.parse import urlparse


def merge_inventory(discovered, operations, coverage, target):
    origin = urlparse(target)
    expected = (origin.scheme, origin.hostname, origin.port or (443 if origin.scheme == "https" else 80))
    observations = {(str(r.get("method", "GET")).upper(), r.get("url")): r for r in coverage}
    merged = {}
    rejected = []
    # Published operations take priority over wordlist guesses.
    for endpoint in [*operations, *discovered]:
        item = dict(endpoint)
        url = str(item.get("url") or "")
        method = str(item.get("method") or "GET").upper()
        try:
            parsed = urlparse(url)
            scope = (parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
            valid = scope == expected and not parsed.username and not parsed.password
            valid = valid and not any(c in url for c in ("%CMR", "{{", "}}", " ", "\n", "\r"))
        except ValueError:
            valid = False
        observation = observations.get((method, url), {})
        reason = observation.get("rejection_reason")
        if not valid or reason or item.get("status") in (404, 410):
            rejected.append({**item, "exclusion_reason": reason or "invalid_or_absent_operation"})
            continue
        key = (method, url)
        if key in merged:
            continue
        item.update(method=method, url=url)
        item["provenance"] = {"source": item.get("source", "unknown"), "spec_path": item.get("spec_path")}
        item["observation"] = observation
        merged[key] = item
    return list(merged.values()), rejected
