"""Evidence-backed assessment metadata layered over compatibility scores."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from ._psl_snapshot import RULE_COUNT, RULES_SHA256, SNAPSHOT_DATE
from .tracker_data import TRACKER_DATASET


METHODOLOGY_VERSION = "2026.08.11.1"


def _level(score: int) -> str:
    if score >= 90:
        return "good"
    if score >= 75:
        return "fair"
    if score >= 50:
        return "degraded"
    return "poor"


def _confidence_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(value, 0)


def calculate_scorecard(report: Mapping[str, Any]) -> Dict[str, Any]:
    """Calculate compatibility scores and disclose every deduction.

    Scores intentionally retain the v0.2 numeric contract.  The returned
    factors make the heuristic auditable instead of presenting it as a hidden
    measurement.
    """

    summary = dict(report.get("summary", {}))
    requests = list(report.get("requests", []))
    count = max(1, int(summary.get("requests", 0) or 0))
    slow_penalty = min(35, round(int(summary.get("slow_requests", 0) or 0) / count * 80))
    large_penalty = min(25, int(summary.get("large_requests", 0) or 0) * 5)
    duplicate_penalty = min(15, round(int(summary.get("duplicate_requests", 0) or 0) / count * 40))
    span = float(summary.get("page_span_ms", 0) or 0)
    span_penalty = 20 if span > 10_000 else 10 if span > 5_000 else 0
    reliability_penalty = min(70, (int(summary.get("failed", 0) or 0) + int(summary.get("http_errors", 0) or 0)) * 8)
    tracker_penalty = min(55, int(summary.get("trackers", 0) or 0) * 7)
    third_party_penalty = min(25, round(float(summary.get("third_party_percent", 0) or 0) / 4))
    insecure = sum(
        item.get("scheme") == "http" and item.get("domain") not in ("localhost", "127.0.0.1", "::1")
        for item in requests
    )
    old_tls = sum(
        str((item.get("security_details") or {}).get("protocol", "")).lower() in ("tls 1.0", "tls 1.1")
        for item in requests
    )
    insecure_penalty = min(60, insecure * 15)
    tls_penalty = min(30, old_tls * 10)
    factors = {
        "performance": [
            {"code": "slow-requests", "deduction": slow_penalty, "evidence": f"{summary.get('slow_requests', 0)} of {summary.get('requests', 0)} requests"},
            {"code": "large-resources", "deduction": large_penalty, "evidence": f"{summary.get('large_requests', 0)} resources at least 1 MB"},
            {"code": "duplicate-requests", "deduction": duplicate_penalty, "evidence": f"{summary.get('duplicate_requests', 0)} duplicate requests"},
            {"code": "page-span", "deduction": span_penalty, "evidence": f"{span} ms observed page span"},
        ],
        "reliability": [
            {"code": "request-errors", "deduction": reliability_penalty, "evidence": f"{summary.get('failed', 0)} failures plus {summary.get('http_errors', 0)} HTTP errors"},
        ],
        "privacy": [
            {"code": "tracker-signatures", "deduction": tracker_penalty, "evidence": f"{summary.get('trackers', 0)} curated signature matches"},
            {"code": "third-party-share", "deduction": third_party_penalty, "evidence": f"{summary.get('third_party_percent', 0)}% third-party requests"},
        ],
        "security": [
            {"code": "unencrypted-http", "deduction": insecure_penalty, "evidence": f"{insecure} non-local HTTP requests"},
            {"code": "legacy-tls", "deduction": tls_penalty, "evidence": f"{old_tls} TLS 1.0/1.1 requests"},
        ],
    }
    performance = max(0, 100 - slow_penalty - large_penalty - duplicate_penalty - span_penalty)
    reliability = max(0, 100 - reliability_penalty)
    privacy = max(0, 100 - tracker_penalty - third_party_penalty)
    security = max(0, 100 - insecure_penalty - tls_penalty)
    scores = {
        "overall": max(0, round((performance + reliability + privacy + security) / 4)),
        "performance": performance,
        "reliability": reliability,
        "privacy": privacy,
        "security": security,
    }
    return {"scores": scores, "factors": factors, "base_score": 100, "overall_method": "unweighted-mean"}


def build_assessment_context(report: Mapping[str, Any], scores: Mapping[str, int]) -> Dict[str, Any]:
    requests = list(report.get("requests", []))
    summary = dict(report.get("summary", {}))
    count = len(requests)
    duration_observed = sum(isinstance(item.get("duration_ms"), (int, float)) for item in requests)
    https_requests = [item for item in requests if item.get("scheme") in ("https", "wss")]
    security_observed = sum(bool(item.get("security_details")) for item in https_requests)
    tracker_matches = [item.get("tracker_match") for item in requests if item.get("tracker_match")]
    insecure = [item for item in requests if item.get("scheme") == "http" and item.get("domain") not in ("localhost", "127.0.0.1", "::1")]
    old_tls = [
        item
        for item in requests
        if str((item.get("security_details") or {}).get("protocol", "")).lower() in ("tls 1.0", "tls 1.1")
    ]
    party_confidences = [item.get("third_party_confidence", "low") for item in requests]
    party_confidence = min(party_confidences, key=_confidence_rank) if party_confidences else "low"
    duration_coverage = round(duration_observed / count, 3) if count else 0.0
    security_coverage = round(security_observed / len(https_requests), 3) if https_requests else 1.0
    source = str(report.get("source_type", "unknown"))
    scorecard = calculate_scorecard(report)

    facts = {
        "request_count": count,
        "duration_observed": duration_observed,
        "duration_coverage": duration_coverage,
        "failed_requests": int(summary.get("failed", 0) or 0),
        "http_error_responses": int(summary.get("http_errors", 0) or 0),
        "third_party_requests": int(summary.get("third_party", 0) or 0),
        "tracker_signature_matches": len(tracker_matches),
        "insecure_http_requests": len(insecure),
        "legacy_tls_requests": len(old_tls),
        "https_requests": len(https_requests),
        "security_details_observed": security_observed,
        "security_details_coverage": security_coverage,
    }

    performance_confidence = "high" if duration_coverage >= 0.9 else "medium" if duration_coverage >= 0.5 else "low"
    reliability_confidence = "high" if source == "chrome-cdp" else "medium" if count else "low"
    privacy_confidence = "low" if not count or party_confidence == "low" else "medium"
    security_confidence = "low" if not count else "high" if insecure or old_tls or security_coverage >= 0.9 else "medium" if security_coverage >= 0.4 else "low"
    common = {"methodology_version": METHODOLOGY_VERSION}
    assessments: Dict[str, Dict[str, Any]] = {
        "performance": {
            **common,
            "score": scores.get("performance", 0),
            "level": _level(scores.get("performance", 0)),
            "confidence": performance_confidence,
            "evidence": [f"Durations observed for {duration_observed}/{count} requests", f"{summary.get('slow_requests', 0)} slow and {summary.get('large_requests', 0)} large requests"],
            "limitations": [] if duration_coverage >= 0.9 else ["Some request durations were unavailable; the performance score may be incomplete."],
            "factors": scorecard["factors"]["performance"],
        },
        "reliability": {
            **common,
            "score": scores.get("reliability", 0),
            "level": _level(scores.get("reliability", 0)),
            "confidence": reliability_confidence,
            "evidence": [f"{facts['failed_requests']} transport failures", f"{facts['http_error_responses']} HTTP error responses"],
            "limitations": [] if source == "chrome-cdp" else ["The source may not distinguish every transport failure from an incomplete recording."],
            "factors": scorecard["factors"]["reliability"],
        },
        "privacy": {
            **common,
            "score": scores.get("privacy", 0),
            "level": _level(scores.get("privacy", 0)),
            "confidence": privacy_confidence,
            "evidence": [f"{len(tracker_matches)} curated tracker-signature matches", f"{facts['third_party_requests']} requests classified as third-party using PSL eTLD+1"],
            "limitations": list(TRACKER_DATASET["limitations"]) + (["Third-party classification used an inferred primary domain."] if party_confidence == "low" else []),
            "factors": scorecard["factors"]["privacy"],
        },
        "security": {
            **common,
            "score": scores.get("security", 0),
            "level": _level(scores.get("security", 0)),
            "confidence": security_confidence,
            "evidence": [f"{len(insecure)} non-local HTTP requests", f"{len(old_tls)} legacy TLS requests", f"TLS details observed for {security_observed}/{len(https_requests)} HTTPS requests"],
            "limitations": [] if security_coverage >= 0.9 else ["TLS version and certificate details were unavailable for some HTTPS requests."],
            "factors": scorecard["factors"]["security"],
        },
    }
    category_confidences: List[str] = [item["confidence"] for item in assessments.values()]
    overall_confidence = min(category_confidences, key=_confidence_rank) if category_confidences else "low"
    assessments["overall"] = {
        **common,
        "score": scores.get("overall", 0),
        "level": _level(scores.get("overall", 0)),
        "confidence": overall_confidence,
        "evidence": ["Compatibility score is the unweighted mean of four category scores."],
        "limitations": ["Scores are heuristic indicators for comparison, not proof of privacy, security, or compliance."],
        "factors": [{"code": "category-mean", "deduction": None, "evidence": "Unweighted mean of performance, reliability, privacy, and security"}],
    }
    return {
        "methodology_version": METHODOLOGY_VERSION,
        "facts": facts,
        "assessments": assessments,
        "datasets": {
            "tracker_signatures": dict(TRACKER_DATASET),
            "public_suffix_list": {
                "name": "Mozilla Public Suffix List",
                "captured_at": SNAPSHOT_DATE,
                "rule_count": RULE_COUNT,
                "sha256": RULES_SHA256,
                "supports": ["ICANN domains", "private domains", "exact rules", "wildcard rules", "exception rules"],
                "runtime_network": False,
            },
        },
    }
