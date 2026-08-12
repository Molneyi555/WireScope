"""Structured and explainable tracker endpoint classification."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urlsplit

from .public_suffix import canonical_host
from .tracker_data import TRACKER_DATASET, TRACKER_RULES


def _domain_matches(host: str, rule_domain: str) -> bool:
    candidate = canonical_host(rule_domain)
    return bool(candidate and (host == candidate or host.endswith("." + candidate)))


def classify_tracker(url: str, domain: str = "") -> Optional[Dict[str, Any]]:
    """Return structured match evidence or ``None``.

    Domain matching observes DNS label boundaries, avoiding false positives
    such as ``notgoogle-analytics.com``.  Path signatures are matched only on
    parsed URL paths and never against query values.
    """

    parsed = urlsplit(url or "")
    host = canonical_host(domain or parsed.hostname or "")
    path = parsed.path.lower()
    for raw_rule in TRACKER_RULES:
        domains = tuple(raw_rule.get("domains", ()))
        matched_domain = next((value for value in domains if _domain_matches(host, value)), None)
        if domains and not matched_domain:
            continue
        prefixes = tuple(value.lower() for value in raw_rule.get("path_prefixes", ()))
        suffixes = tuple(value.lower() for value in raw_rule.get("path_suffixes", ()))
        matched_path = next((value for value in prefixes if path == value or path.startswith(value + "/")), None)
        if not matched_path:
            matched_path = next((value for value in suffixes if path.endswith(value)), None)
        if (prefixes or suffixes) and not matched_path:
            continue
        matched_on = "domain+path" if matched_domain and matched_path else "domain" if matched_domain else "path"
        return {
            "dataset": TRACKER_DATASET["name"],
            "dataset_version": TRACKER_DATASET["version"],
            "rule_id": raw_rule["id"],
            "owner": raw_rule["owner"],
            "category": raw_rule["category"],
            "confidence": raw_rule["confidence"],
            "matched_on": matched_on,
            "matched_value": matched_path or matched_domain,
            "domain": host,
            "explanation": raw_rule.get("description", "Request endpoint matched a bundled, reviewed tracker signature."),
        }
    return None


def is_tracker(url: str, domain: str = "") -> bool:
    return classify_tracker(url, domain) is not None
