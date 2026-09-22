"""Project validation outcomes without deleting the underlying observations."""
import copy


def project_reviews(findings, reviews):
    by_id = {r.get("finding_id"): r for r in reviews}
    projected = []
    for original in findings:
        finding = copy.deepcopy(original)
        review = by_id.get(finding.get("id"))
        if not review:
            projected.append(finding)
            continue
        validation = review.get("validation") or {}
        status = review.get("report_status") or "inconclusive"
        finding["scanner_assessment"] = {k: original.get(k) for k in ("classification", "severity", "cvss", "status")}
        finding["validation_status"] = status
        finding["validation_evidence_refs"] = [validation["evidence_id"]] if validation.get("evidence_id") else []
        finding["review_verdict"] = (review.get("review") or {}).get("verdict")
        # A replay match is not exploitation; only deterministic absence can
        # refute here. Positive conclusions need an explicit validated oracle.
        if status == "refuted" and validation.get("not_found"):
            finding.update(classification="refuted", status="refuted", severity="info", cvss=None)
        elif original.get("classification") != "hardening":
            finding.update(classification="insufficient", status="needs_review")
        projected.append(finding)
    return projected


def review_quality(reviews, overview, expected_count):
    incomplete = sum(bool(r.get("error")) or (r.get("review") or {}).get("status") not in {"ok", "skipped"} for r in reviews)
    missing = max(0, expected_count - len(reviews))
    return {"status": "partial" if incomplete or missing or overview.get("status") != "ok" else "ok",
            "reviews_count": len(reviews), "incomplete_reviews": incomplete, "missing_reviews": missing,
            "pocs_count": sum(bool((r.get("validation") or {}).get("confirmed")) for r in reviews)}
