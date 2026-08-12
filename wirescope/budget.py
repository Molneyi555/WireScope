from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping


@dataclass(frozen=True)
class BudgetRule:
    metric: str
    operator: str
    label: str


BUDGET_RULES: Dict[str, BudgetRule] = {
    "max_requests": BudgetRule("requests", "max", "Requests"),
    "max_transfer_bytes": BudgetRule("transfer_bytes", "max", "Transferred bytes"),
    "max_page_span_ms": BudgetRule("page_span_ms", "max", "Page span"),
    "max_errors": BudgetRule("errors", "max", "Failed and HTTP-error requests"),
    "max_failed": BudgetRule("failed", "max", "Failed requests"),
    "max_http_errors": BudgetRule("http_errors", "max", "HTTP-error requests"),
    "max_third_party_percent": BudgetRule("third_party_percent", "max", "Third-party requests"),
    "max_trackers": BudgetRule("trackers", "max", "Likely trackers"),
    "min_cache_percent": BudgetRule("cache_percent", "min", "Cache hits"),
    "min_overall_score": BudgetRule("overall_score", "min", "Overall score"),
    "min_performance_score": BudgetRule("performance_score", "min", "Performance score"),
    "min_reliability_score": BudgetRule("reliability_score", "min", "Reliability score"),
    "min_privacy_score": BudgetRule("privacy_score", "min", "Privacy score"),
    "min_security_score": BudgetRule("security_score", "min", "Security score"),
}


_SIZE_PATTERN = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b)?\s*$", re.IGNORECASE)
_SIZE_MULTIPLIERS = {
    "": 1,
    "b": 1,
    "kb": 1_000,
    "mb": 1_000_000,
    "gb": 1_000_000_000,
    "tb": 1_000_000_000_000,
    "kib": 1 << 10,
    "mib": 1 << 20,
    "gib": 1 << 30,
    "tib": 1 << 40,
}


def parse_byte_size(value: Any) -> int:
    """Parse byte counts such as 750KB, 2.5MB, or 4MiB."""
    if isinstance(value, bool):
        raise ValueError("byte size must be a number, not a boolean")
    if isinstance(value, (int, float)):
        if value < 0:
            raise ValueError("byte size cannot be negative")
        return int(value)
    match = _SIZE_PATTERN.match(str(value))
    if not match:
        raise ValueError(f"invalid byte size {value!r}; use bytes, KB, MB, GB, KiB, or MiB")
    number, unit = match.groups()
    return int(float(number) * _SIZE_MULTIPLIERS[(unit or "").lower()])


def normalize_budget_policy(policy: Mapping[str, Any]) -> Dict[str, float]:
    if not isinstance(policy, Mapping):
        raise ValueError("budget policy must be a JSON object")
    unknown = sorted(set(policy) - set(BUDGET_RULES))
    if unknown:
        raise ValueError(f"unknown budget key(s): {', '.join(unknown)}")
    normalized: Dict[str, float] = {}
    for key, value in policy.items():
        if value is None:
            continue
        if key == "max_transfer_bytes":
            parsed: float = parse_byte_size(value)
        else:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be a number")
            parsed = value
        if parsed < 0:
            raise ValueError(f"{key} cannot be negative")
        if (key.endswith("_percent") or key.endswith("_score")) and parsed > 100:
            raise ValueError(f"{key} must be between 0 and 100")
        normalized[key] = parsed
    if not normalized:
        raise ValueError("budget policy contains no limits")
    return normalized


def load_budget_policy(path: str) -> Dict[str, float]:
    source = Path(path)
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("budget policy root must be a JSON object")
    if "budgets" in value:
        if len(value) != 1:
            raise ValueError("a policy with a 'budgets' object cannot contain other top-level keys")
        value = value["budgets"]
    return normalize_budget_policy(value)


def merge_budget_policy(file_policy: Mapping[str, Any], overrides: Mapping[str, Any]) -> Dict[str, float]:
    combined = dict(file_policy)
    combined.update({key: value for key, value in overrides.items() if value is not None})
    return normalize_budget_policy(combined)


def report_metrics(report: Mapping[str, Any]) -> Dict[str, float]:
    summary = report.get("summary", {})
    scores = report.get("scores", {})
    if not isinstance(summary, Mapping) or not isinstance(scores, Mapping):
        raise ValueError("analysis does not contain summary and score objects")
    metrics: Dict[str, float] = {}
    for key in (
        "requests",
        "transfer_bytes",
        "page_span_ms",
        "failed",
        "http_errors",
        "third_party_percent",
        "trackers",
        "cache_percent",
    ):
        value = summary.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            metrics[key] = value
    if "failed" in metrics and "http_errors" in metrics:
        metrics["errors"] = metrics["failed"] + metrics["http_errors"]
    for key in ("overall", "performance", "reliability", "privacy", "security"):
        value = scores.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            metrics[f"{key}_score"] = value
    return metrics


def evaluate_budgets(report: Mapping[str, Any], policy: Mapping[str, Any]) -> Dict[str, Any]:
    budgets = normalize_budget_policy(policy)
    metrics = report_metrics(report)
    checks = []
    for policy_key, limit in budgets.items():
        rule = BUDGET_RULES[policy_key]
        if rule.metric not in metrics:
            source_type = report.get("source_type", "recording")
            raise ValueError(f"metric {rule.metric!r} is not available for {source_type}")
        actual = metrics[rule.metric]
        passed = actual <= limit if rule.operator == "max" else actual >= limit
        overage = max(0, actual - limit) if rule.operator == "max" else max(0, limit - actual)
        checks.append(
            {
                "policy": policy_key,
                "metric": rule.metric,
                "label": rule.label,
                "operator": "<=" if rule.operator == "max" else ">=",
                "limit": limit,
                "actual": actual,
                "overage": round(overage, 2),
                "passed": passed,
            }
        )
    violations = [item for item in checks if not item["passed"]]
    return {
        "schema_version": 1,
        "source_type": report.get("source_type", "recording"),
        "passed": not violations,
        "checked": len(checks),
        "budgets": budgets,
        "metrics": {item["metric"]: item["actual"] for item in checks},
        "checks": checks,
        "violations": violations,
    }
