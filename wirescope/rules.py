from __future__ import annotations

import fnmatch
import json
import math
import re
from collections import deque
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import __version__
from .public_suffix import canonical_host, default_public_suffix_list, registrable_domain
from .session import SessionError, SessionStore


RULE_PACK_SCHEMA_VERSION = 1
MAX_RULE_PACK_BYTES = 2 * 1024 * 1024
MAX_RULES = 500
MAX_PREDICATE_DEPTH = 20
MAX_PREDICATE_NODES = 5000
MAX_EVIDENCE_PER_FINDING = 100
MAX_PACKS = 32
MAX_TOTAL_RULES = 2000
MAX_SOURCE_ROWS = 250_000
MAX_SOURCE_JSON_BYTES = 128 * 1024 * 1024
MAX_EVALUATION_STEPS = 5_000_000
MAX_GRAPH_VISITS = 100_000
MAX_STRING_LENGTH = 4096
MAX_APPLIED_PACK_VERSIONS = 1000

SEVERITIES = {"info", "notice", "warning", "error", "critical"}
SOURCES = {"events", "entities", "relations", "findings", "sessions"}
COMPARISON_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "glob", "exists"}
DOMAIN_MODES = {"exact", "glob", "registrable"}


class RulePackError(ValueError):
    """Raised when a data-only rule pack violates its public contract."""


_MISSING = object()


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RulePackError(f"rule pack JSON contains duplicate field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise RulePackError(f"invalid numeric constant: {value}")


def _strict_stored_json(raw: Any, label: str, expected_type: type) -> Any:
    if not isinstance(raw, str):
        raise RulePackError(f"{label} is not stored as JSON text")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise RulePackError(f"{label} contains invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise RulePackError(f"{label} JSON nesting is too deep") from exc
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise RulePackError(f"{label} contains a non-finite JSON number")
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    if not isinstance(value, expected_type):
        raise RulePackError(f"{label} must contain a JSON {expected_type.__name__}")
    return value


def _finite_number(value: Any) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _consume_budget(budget: List[int], amount: int = 1) -> None:
    budget[0] += amount
    if budget[0] > MAX_EVALUATION_STEPS:
        raise RulePackError(f"rule evaluation exceeds the {MAX_EVALUATION_STEPS}-step limit")


BUILTIN_RULE_PACK: Dict[str, Any] = {
    "schema_version": 1,
    "id": "wirescope.core",
    "version": "1.0.0",
    "min_wirescope_version": "0.3.0rc1",
    "rules": [
        {
            "id": "slow-load-path",
            "title": "Slow request path observed",
            "category": "performance",
            "severity": "warning",
            "confidence": 0.90,
            "when": {
                "count": {
                    "source": "events",
                    "where": {"field": "payload.request.duration_ms", "op": "gte", "value": 1000},
                },
                "op": "gte",
                "value": 1,
            },
            "evidence": {
                "source": "events",
                "where": {"field": "payload.request.duration_ms", "op": "gte", "value": 1000},
                "limit": 20,
            },
            "limitations": ["The source reports elapsed request time; WireScope does not infer server-side cause."],
            "explanation": "At least one observed HTTP request took one second or longer.",
            "remediation": "Inspect the request timing phases and compare them with a known-good baseline.",
        },
        {
            "id": "dns-failure",
            "title": "DNS failure observed",
            "category": "dns",
            "severity": "error",
            "confidence": 0.90,
            "when": {
                "count": {
                    "source": "events",
                    "where": {"field": "event_type", "op": "in", "value": ["dns.failed", "dns.nxdomain", "dns.servfail"]},
                },
                "op": "gte",
                "value": 1,
            },
            "evidence": {
                "source": "events",
                "where": {"field": "event_type", "op": "in", "value": ["dns.failed", "dns.nxdomain", "dns.servfail"]},
                "limit": 20,
            },
            "limitations": ["Encrypted DNS outside available sensors may not be visible."],
            "explanation": "The session contains an explicit DNS failure event.",
            "remediation": "Check resolver reachability, response code, active VPN policy and resolver changes.",
        },
        {
            "id": "connection-churn",
            "title": "Connection churn observed",
            "category": "reliability",
            "severity": "warning",
            "confidence": 0.88,
            "when": {
                "count": {
                    "source": "events",
                    "where": {
                        "field": "event_type",
                        "op": "in",
                        "value": ["connection.opened", "connection.closed"],
                    },
                },
                "op": "gte",
                "value": 100,
            },
            "evidence": {
                "source": "events",
                "where": {
                    "field": "event_type",
                    "op": "in",
                    "value": ["connection.opened", "connection.closed"],
                },
                "limit": 20,
            },
            "limitations": ["A high event count can be expected for load tests and connection-stress workloads."],
            "explanation": "The session crossed the built-in lifecycle-event threshold.",
            "remediation": "Group connections by process and endpoint, then compare churn with a representative baseline.",
        },
        {
            "id": "network-state-change",
            "title": "Network state changed during activity",
            "category": "routing",
            "severity": "notice",
            "confidence": 0.95,
            "when": {
                "count": {
                    "source": "events",
                    "where": {"field": "event_type", "op": "glob", "value": "network.*.changed"},
                },
                "op": "gte",
                "value": 1,
            },
            "evidence": {
                "source": "events",
                "where": {"field": "event_type", "op": "glob", "value": "network.*.changed"},
                "limit": 20,
            },
            "limitations": ["Temporal coexistence is evidence of a change, not proof that the change caused an application failure."],
            "explanation": "A route, resolver, VPN or proxy snapshot changed while the session was recording.",
            "remediation": "Inspect events immediately before and after the change and verify the effective route and resolver.",
        },
        {
            "id": "http-downgrade",
            "title": "Unencrypted HTTP request observed",
            "category": "security",
            "severity": "error",
            "confidence": 0.98,
            "when": {
                "count": {
                    "source": "events",
                    "where": {"field": "payload.request.scheme", "op": "eq", "value": "http"},
                },
                "op": "gte",
                "value": 1,
            },
            "evidence": {
                "source": "events",
                "where": {"field": "payload.request.scheme", "op": "eq", "value": "http"},
                "limit": 20,
            },
            "limitations": ["Loopback and intentionally isolated development traffic may be acceptable by policy."],
            "explanation": "The source explicitly identifies at least one request with the http scheme.",
            "remediation": "Use HTTPS or document an explicit local-development exception in the Network Manifest.",
        },
        {
            "id": "incomplete-evidence",
            "title": "Session has no source artifact provenance",
            "category": "visibility",
            "severity": "notice",
            "confidence": 1.0,
            "when": {"field": "summary.counts.artifacts", "op": "eq", "value": 0},
            "evidence": {"source": "sessions", "where": {"field": "id", "op": "exists"}, "limit": 1},
            "limitations": ["Live recordings can contain valid direct observations without an imported source artifact."],
            "explanation": "No imported artifact hash is attached to this session.",
            "remediation": "Use session ingest for HAR/JSONL evidence or retain the direct-recording capability summary.",
        },
    ],
}


def _version_tuple(value: str) -> Tuple[Tuple[int, int, int], Optional[Tuple[Any, ...]]]:
    match = re.fullmatch(
        r"(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+)|-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+(?:[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?",
        value,
    )
    if match is None:
        raise RulePackError(f"invalid semantic version: {value!r}")
    release_text = match.groups()[:3]
    if any(len(item) > 1 and item.startswith("0") for item in release_text):
        raise RulePackError(f"invalid semantic version: {value!r}")
    release = tuple(int(item) for item in release_text)
    pep_stage, pep_number, semver_prerelease = match.groups()[3:]
    if pep_stage is not None:
        normalized_stage = {"a": "alpha", "b": "beta", "rc": "rc"}[pep_stage]
        prerelease: Optional[Tuple[Any, ...]] = (normalized_stage, int(pep_number))
    elif semver_prerelease is not None:
        identifiers: List[Any] = []
        for identifier in semver_prerelease.split("."):
            if identifier.isdigit():
                if len(identifier) > 1 and identifier.startswith("0"):
                    raise RulePackError(f"invalid semantic version: {value!r}")
                identifiers.append(int(identifier))
            else:
                identifiers.append(identifier)
        prerelease = tuple(identifiers)
    else:
        prerelease = None
    return (release[0], release[1], release[2]), prerelease


def _prerelease_compare(first: Tuple[Any, ...], second: Tuple[Any, ...]) -> int:
    for left, right in zip(first, second):
        if left == right:
            continue
        if isinstance(left, int) and isinstance(right, str):
            return -1
        if isinstance(left, str) and isinstance(right, int):
            return 1
        return -1 if left < right else 1
    if len(first) == len(second):
        return 0
    return -1 if len(first) < len(second) else 1


def _minimum_version_satisfied(required: str, current: str) -> bool:
    required_release, required_pre = _version_tuple(required)
    current_release, current_pre = _version_tuple(current)
    if current_release != required_release:
        return current_release > required_release
    if required_pre is None:
        return current_pre is None
    if current_pre is None:
        return True
    return _prerelease_compare(current_pre, required_pre) >= 0


def _resolve(value: Any, path: str) -> Any:
    current = value
    for component in path.split(".") if path else ():
        if isinstance(current, dict) and component in current:
            current = current[component]
        else:
            return _MISSING
    return current


def _json_equal(actual: Any, expected: Any, budget: List[int]) -> Optional[bool]:
    pending = [(actual, expected)]
    while pending:
        _consume_budget(budget)
        left, right = pending.pop()
        if isinstance(left, bool) or isinstance(right, bool):
            if not (isinstance(left, bool) and isinstance(right, bool) and left == right):
                return False
            continue
        if left is None or right is None:
            if left is not None or right is not None:
                return False
            continue
        if (
            isinstance(left, (int, float))
            and not isinstance(left, bool)
            and isinstance(right, (int, float))
            and not isinstance(right, bool)
        ):
            if left != right:
                return False
            continue
        if isinstance(left, str) or isinstance(right, str):
            if not (isinstance(left, str) and isinstance(right, str) and left == right):
                return False
            continue
        if isinstance(left, list) or isinstance(right, list):
            if not (isinstance(left, list) and isinstance(right, list)) or len(left) != len(right):
                return False
            pending.extend(zip(left, right))
            continue
        if isinstance(left, dict) or isinstance(right, dict):
            if not (isinstance(left, dict) and isinstance(right, dict)) or set(left) != set(right):
                return False
            pending.extend((left[key], right[key]) for key in left)
            continue
        if type(left) is not type(right) or left != right:
            return False
    return True


def _compare(
    actual: Any,
    operator: str,
    expected: Any = None,
    budget: Optional[List[int]] = None,
) -> Optional[bool]:
    comparison_budget = budget if budget is not None else [0]
    if operator == "exists":
        return actual is not _MISSING and actual is not None
    if actual is _MISSING:
        return None
    if isinstance(actual, float) and not math.isfinite(actual):
        return None
    if operator == "eq":
        return _json_equal(actual, expected, comparison_budget)
    if operator == "ne":
        equal = _json_equal(actual, expected, comparison_budget)
        return None if equal is None else not equal
    if operator == "in":
        if not isinstance(expected, list):
            return None
        unknown = False
        for candidate in expected:
            equal = _json_equal(actual, candidate, comparison_budget)
            if equal is True:
                return True
            unknown = unknown or equal is None
        return None if unknown else False
    if operator == "not_in":
        included = _compare(actual, "in", expected, comparison_budget)
        return None if included is None else not included
    if operator == "glob":
        return fnmatch.fnmatchcase(actual, expected) if isinstance(actual, str) and isinstance(expected, str) else None
    if operator in {"gt", "gte", "lt", "lte"}:
        if not isinstance(actual, (int, float)) or isinstance(actual, bool):
            return None
        if not isinstance(expected, (int, float)) or isinstance(expected, bool):
            return None
        if operator == "gt":
            return actual > expected
        if operator == "gte":
            return actual >= expected
        if operator == "lt":
            return actual < expected
        return actual <= expected
    raise RulePackError(f"unsupported comparison operator: {operator}")


def _validate_selector(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise RulePackError(f"{path} must be an object")
    unknown = set(value) - {"source", "where", "limit"}
    if unknown:
        raise RulePackError(f"{path} has unknown fields: {', '.join(sorted(unknown))}")
    if value.get("source") not in SOURCES:
        raise RulePackError(f"{path}.source must be one of: {', '.join(sorted(SOURCES))}")
    if "where" in value:
        _validate_predicate(value["where"], f"{path}.where", depth=0, nodes=[0])
    limit = value.get("limit", 20)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_EVIDENCE_PER_FINDING:
        raise RulePackError(f"{path}.limit must be between 1 and {MAX_EVIDENCE_PER_FINDING}")


def _validate_predicate(value: Any, path: str, *, depth: int, nodes: List[int]) -> None:
    nodes[0] += 1
    if nodes[0] > MAX_PREDICATE_NODES:
        raise RulePackError(f"{path} exceeds the {MAX_PREDICATE_NODES}-node limit")
    if depth > MAX_PREDICATE_DEPTH:
        raise RulePackError(f"{path} exceeds the {MAX_PREDICATE_DEPTH}-level depth limit")
    if not isinstance(value, dict) or not value:
        raise RulePackError(f"{path} must be a non-empty predicate object")
    if "all" in value or "any" in value:
        key = "all" if "all" in value else "any"
        if set(value) != {key} or not isinstance(value[key], list) or not value[key]:
            raise RulePackError(f"{path}.{key} must be the predicate's only field and contain a non-empty array")
        for index, child in enumerate(value[key]):
            _validate_predicate(child, f"{path}.{key}[{index}]", depth=depth + 1, nodes=nodes)
        return
    if "not" in value:
        if set(value) != {"not"}:
            raise RulePackError(f"{path}.not must be the predicate's only field")
        _validate_predicate(value["not"], f"{path}.not", depth=depth + 1, nodes=nodes)
        return
    if "field" in value:
        allowed = {"field", "op", "value"}
        if set(value) - allowed:
            raise RulePackError(f"{path} has unknown comparison fields")
        if not isinstance(value.get("field"), str) or not value["field"]:
            raise RulePackError(f"{path}.field must be a non-empty string")
        if len(value["field"]) > 512:
            raise RulePackError(f"{path}.field is too long")
        operator = value.get("op")
        if operator not in COMPARISON_OPERATORS:
            raise RulePackError(f"{path}.op is unknown: {operator!r}")
        if operator != "exists" and "value" not in value:
            raise RulePackError(f"{path}.value is required for {operator}")
        if operator == "exists" and "value" in value:
            raise RulePackError(f"{path}.value is not allowed for exists")
        expected = value.get("value")
        if operator in ("in", "not_in") and (
            not isinstance(expected, list) or len(expected) > 10_000
        ):
            raise RulePackError(f"{path}.value must be a bounded array for {operator}")
        if operator == "glob" and (not isinstance(expected, str) or len(expected) > MAX_STRING_LENGTH):
            raise RulePackError(f"{path}.value must be a bounded string for glob")
        if operator in ("gt", "gte", "lt", "lte") and not _finite_number(expected):
            raise RulePackError(f"{path}.value must be a finite number for {operator}")
        return
    if "domain" in value:
        if set(value) != {"domain"} or not isinstance(value["domain"], dict):
            raise RulePackError(f"{path}.domain must be the predicate's only field and an object")
        domain = value["domain"]
        if set(domain) - {"field", "mode", "value"}:
            raise RulePackError(f"{path}.domain has unknown fields")
        if not isinstance(domain.get("field"), str) or not domain.get("field") or len(domain["field"]) > 512 or domain.get("mode") not in DOMAIN_MODES:
            raise RulePackError(f"{path}.domain requires field and mode exact|glob|registrable")
        if not isinstance(domain.get("value"), str) or not domain["value"] or len(domain["value"]) > MAX_STRING_LENGTH:
            raise RulePackError(f"{path}.domain.value must be a non-empty string")
        if domain["mode"] == "registrable":
            parts = default_public_suffix_list().split(domain["value"])
            if parts.is_ip or parts.public_suffix == parts.registrable_domain:
                raise RulePackError(f"{path}.domain.value must contain a registrable domain")
        return
    for aggregate in ("count", "ratio", "duration"):
        if aggregate in value:
            allowed = {aggregate, "op", "value"}
            if set(value) - allowed:
                raise RulePackError(f"{path} has unknown {aggregate} fields")
            spec = value[aggregate]
            if not isinstance(spec, dict) or spec.get("source") not in SOURCES:
                raise RulePackError(f"{path}.{aggregate}.source is invalid")
            allowed_spec = {"source", "where"} | ({"denominator_where"} if aggregate == "ratio" else set())
            if set(spec) - allowed_spec:
                raise RulePackError(f"{path}.{aggregate} has unknown fields")
            if "where" in spec:
                _validate_predicate(spec["where"], f"{path}.{aggregate}.where", depth=depth + 1, nodes=nodes)
            if aggregate == "ratio" and "denominator_where" in spec:
                _validate_predicate(
                    spec["denominator_where"],
                    f"{path}.ratio.denominator_where",
                    depth=depth + 1,
                    nodes=nodes,
                )
            if value.get("op") not in COMPARISON_OPERATORS - {"in", "not_in", "glob", "exists"}:
                raise RulePackError(f"{path}.op is invalid for {aggregate}")
            if not _finite_number(value.get("value")):
                raise RulePackError(f"{path}.value must be a finite number")
            return
    if "graph_path" in value:
        if set(value) != {"graph_path"} or not isinstance(value["graph_path"], dict):
            raise RulePackError(f"{path}.graph_path must be the predicate's only field")
        spec = value["graph_path"]
        if set(spec) - {"from", "to", "relations", "max_depth"}:
            raise RulePackError(f"{path}.graph_path has unknown fields")
        for endpoint in ("from", "to"):
            selector = spec.get(endpoint)
            if (
                not isinstance(selector, dict)
                or not selector
                or set(selector) - {"type", "key", "label"}
                or not all(isinstance(item, str) and item and len(item) <= MAX_STRING_LENGTH for item in selector.values())
            ):
                raise RulePackError(f"{path}.graph_path.{endpoint} is invalid")
        relations = spec.get("relations", [])
        if (
            not isinstance(relations, list)
            or len(relations) > 1000
            or not all(isinstance(item, str) and item and len(item) <= MAX_STRING_LENGTH for item in relations)
            or len(relations) != len(set(relations))
        ):
            raise RulePackError(f"{path}.graph_path.relations must be a string array")
        max_depth = spec.get("max_depth", 4)
        if not isinstance(max_depth, int) or isinstance(max_depth, bool) or not 1 <= max_depth <= 8:
            raise RulePackError(f"{path}.graph_path.max_depth must be between 1 and 8")
        return
    raise RulePackError(f"{path} uses an unknown predicate operator")


def validate_rule_pack(pack: Any) -> Dict[str, Any]:
    if not isinstance(pack, dict):
        raise RulePackError("rule pack must be a JSON object")
    try:
        encoded_size = len(json.dumps(pack, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise RulePackError(f"rule pack must contain finite JSON data: {exc}") from exc
    if encoded_size > MAX_RULE_PACK_BYTES:
        raise RulePackError(f"rule pack exceeds {MAX_RULE_PACK_BYTES} bytes")
    required = {"schema_version", "id", "version", "min_wirescope_version", "rules"}
    missing = required - set(pack)
    unknown = set(pack) - required
    if missing:
        raise RulePackError(f"rule pack is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise RulePackError(f"rule pack has unknown fields: {', '.join(sorted(unknown))}")
    if (
        not isinstance(pack["schema_version"], int)
        or isinstance(pack["schema_version"], bool)
        or pack["schema_version"] != RULE_PACK_SCHEMA_VERSION
    ):
        raise RulePackError(f"unsupported rule pack schema: {pack['schema_version']!r}")
    for key in ("id", "version", "min_wirescope_version"):
        if not isinstance(pack[key], str) or not pack[key].strip() or len(pack[key]) > 256:
            raise RulePackError(f"rule pack {key} must be a non-empty string")
    if re.fullmatch(r"[A-Za-z0-9_.-]+", pack["id"]) is None:
        raise RulePackError("rule pack id may contain only letters, digits, dot, underscore, and hyphen")
    _version_tuple(pack["version"])
    _version_tuple(pack["min_wirescope_version"])
    if not isinstance(pack["rules"], list) or not 1 <= len(pack["rules"]) <= MAX_RULES:
        raise RulePackError(f"rule pack rules must contain between 1 and {MAX_RULES} entries")
    rule_ids = set()
    required_rule = {
        "id",
        "title",
        "category",
        "severity",
        "confidence",
        "when",
        "evidence",
        "limitations",
        "explanation",
        "remediation",
    }
    for index, rule in enumerate(pack["rules"]):
        path = f"rules[{index}]"
        if not isinstance(rule, dict):
            raise RulePackError(f"{path} must be an object")
        missing_rule = required_rule - set(rule)
        unknown_rule = set(rule) - required_rule
        if missing_rule:
            raise RulePackError(f"{path} is missing fields: {', '.join(sorted(missing_rule))}")
        if unknown_rule:
            raise RulePackError(f"{path} has unknown fields: {', '.join(sorted(unknown_rule))}")
        for key in ("id", "title", "category", "explanation", "remediation"):
            if not isinstance(rule[key], str) or not rule[key].strip() or len(rule[key]) > MAX_STRING_LENGTH:
                raise RulePackError(f"{path}.{key} must be a non-empty string")
        if len(rule["id"]) > 256 or re.fullmatch(r"[A-Za-z0-9_.-]+", rule["id"]) is None:
            raise RulePackError(f"{path}.id contains unsupported characters or is too long")
        if rule["id"] in rule_ids:
            raise RulePackError(f"duplicate rule id: {rule['id']}")
        rule_ids.add(rule["id"])
        if rule["severity"] not in SEVERITIES:
            raise RulePackError(f"{path}.severity is invalid")
        confidence = rule["confidence"]
        if not _finite_number(confidence) or not 0 <= float(confidence) <= 1:
            raise RulePackError(f"{path}.confidence must be between 0 and 1")
        if not isinstance(rule["limitations"], list) or not rule["limitations"] or len(rule["limitations"]) > 100:
            raise RulePackError(f"{path}.limitations must be a non-empty string array")
        if not all(isinstance(item, str) and item.strip() and len(item) <= MAX_STRING_LENGTH for item in rule["limitations"]):
            raise RulePackError(f"{path}.limitations contains an invalid value")
        _validate_predicate(rule["when"], f"{path}.when", depth=0, nodes=[0])
        _validate_selector(rule["evidence"], f"{path}.evidence")
    return pack


def load_rule_pack(path: str) -> Dict[str, Any]:
    source = Path(path)
    try:
        size = source.stat().st_size
    except FileNotFoundError as exc:
        raise RulePackError(f"rule pack does not exist: {path}") from exc
    except OSError as exc:
        raise RulePackError(f"cannot inspect rule pack: {path}: {exc}") from exc
    if size > MAX_RULE_PACK_BYTES:
        raise RulePackError(f"rule pack exceeds {MAX_RULE_PACK_BYTES} bytes")
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise RulePackError(f"invalid rule pack JSON at line {exc.lineno}: {exc.msg}") from exc
    except RecursionError as exc:
        raise RulePackError("rule pack JSON nesting is too deep") from exc
    except OSError as exc:
        raise RulePackError(f"cannot read rule pack: {path}: {exc}") from exc
    return validate_rule_pack(value)


def builtin_rule_pack() -> Dict[str, Any]:
    return json.loads(json.dumps(validate_rule_pack(BUILTIN_RULE_PACK), sort_keys=True))


def _row_sources(
    store: SessionStore,
    session_id: str,
    excluded_findings: Optional[set] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    counts = {
        table: int(
            store.connection.execute(
                f'SELECT COUNT(*) FROM "{table}" WHERE session_id=?', (session_id,)
            ).fetchone()[0]
        )
        for table in ("events", "entities", "relations", "findings")
    }
    if sum(counts.values()) + 1 > MAX_SOURCE_ROWS:
        raise RulePackError(f"session rule sources exceed the {MAX_SOURCE_ROWS}-row limit")
    json_bytes = 0
    for table, column in (
        ("events", "payload_json"),
        ("entities", "attributes_json"),
        ("relations", "evidence_json"),
        ("findings", "evidence_json"),
        ("findings", "limitations_json"),
        ("sessions", "host_json"),
        ("sessions", "config_json"),
        ("sessions", "summary_json"),
    ):
        identity_column = "id" if table == "sessions" else "session_id"
        json_bytes += int(
            store.connection.execute(
                f'SELECT COALESCE(SUM(LENGTH(CAST("{column}" AS BLOB))), 0) FROM "{table}" WHERE {identity_column}=?',
                (session_id,),
            ).fetchone()[0]
        )
    if json_bytes > MAX_SOURCE_JSON_BYTES:
        raise RulePackError(
            f"session rule-source JSON exceeds the {MAX_SOURCE_JSON_BYTES}-byte limit"
        )
    events = []
    for row in store.connection.execute(
        "SELECT * FROM events WHERE session_id=? ORDER BY sequence", (session_id,)
    ):
        events.append(
            {
                **{key: row[key] for key in row.keys() if key != "payload_json"},
                "payload": _strict_stored_json(row["payload_json"], "event payload", dict),
            }
        )
    entities = []
    for row in store.connection.execute(
        "SELECT * FROM entities WHERE session_id=? ORDER BY id", (session_id,)
    ):
        entities.append(
            {
                **{key: row[key] for key in row.keys() if key != "attributes_json"},
                "attributes": _strict_stored_json(
                    row["attributes_json"], "entity attributes", dict
                ),
            }
        )
    relations = []
    for row in store.connection.execute(
        "SELECT * FROM relations WHERE session_id=? ORDER BY id", (session_id,)
    ):
        relations.append(
            {
                **{key: row[key] for key in row.keys() if key != "evidence_json"},
                "evidence": _strict_stored_json(
                    row["evidence_json"], "relation evidence", dict
                ),
            }
        )
    findings = []
    for row in store.connection.execute(
        "SELECT * FROM findings WHERE session_id=? ORDER BY id", (session_id,)
    ):
        if (str(row["pack_id"] or ""), str(row["pack_version"] or "")) in (excluded_findings or set()):
            continue
        findings.append(
            {
                **{
                    key: row[key]
                    for key in row.keys()
                    if key not in ("evidence_json", "limitations_json")
                },
                "evidence": _strict_stored_json(
                    row["evidence_json"], "finding evidence", list
                ),
                "limitations": _strict_stored_json(
                    row["limitations_json"], "finding limitations", list
                ),
            }
        )
    sessions = []
    for row in store.connection.execute("SELECT * FROM sessions WHERE id=?", (session_id,)):
        sessions.append(
            {
                **{
                    key: row[key]
                    for key in row.keys()
                    if key not in ("host_json", "config_json", "summary_json")
                },
                "host": _strict_stored_json(row["host_json"], "session host", dict),
                "config": _strict_stored_json(row["config_json"], "session config", dict),
                "summary": _strict_stored_json(row["summary_json"], "session summary", dict),
            }
        )
    return {
        "events": events,
        "entities": entities,
        "relations": relations,
        "findings": findings,
        "sessions": sessions,
    }


def _active_summary(
    store: SessionStore,
    session_id: str,
    sources: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    event_types: Dict[str, int] = {}
    event_sources: Dict[str, int] = {}
    entity_types: Dict[str, int] = {}
    for item in sources["events"]:
        event_types[str(item.get("event_type"))] = event_types.get(str(item.get("event_type")), 0) + 1
        event_sources[str(item.get("source"))] = event_sources.get(str(item.get("source")), 0) + 1
    for item in sources["entities"]:
        entity_types[str(item.get("entity_type"))] = entity_types.get(str(item.get("entity_type")), 0) + 1
    artifact_count = int(
        store.connection.execute("SELECT COUNT(*) FROM artifacts WHERE session_id=?", (session_id,)).fetchone()[0]
    )
    return {
        "schema_version": store.schema_version,
        "path": str(store.path),
        "sessions": sources["sessions"],
        "counts": {
            "events": len(sources["events"]),
            "entities": len(sources["entities"]),
            "relations": len(sources["relations"]),
            "findings": len(sources["findings"]),
            "artifacts": artifact_count,
        },
        "events_by_type": {key: event_types[key] for key in sorted(event_types)},
        "events_by_source": {key: event_sources[key] for key in sorted(event_sources)},
        "entities_by_type": {key: entity_types[key] for key in sorted(entity_types)},
    }


def _applied_pack_versions(store: SessionStore, session_id: str) -> List[str]:
    row = store.connection.execute(
        "SELECT value_json FROM metadata WHERE key=?", (f"rule_pack_versions:{session_id}",)
    ).fetchone()
    if row is None:
        return []
    try:
        value = json.loads(
            row["value_json"],
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise RulePackError(f"stored rule-pack metadata is invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise RulePackError("stored rule-pack metadata nesting is too deep") from exc
    if (
        not isinstance(value, list)
        or len(value) > MAX_APPLIED_PACK_VERSIONS
        or not all(
            isinstance(item, str)
            and item.count("@") == 1
            and all(part for part in item.split("@", 1))
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise RulePackError("stored rule-pack metadata must be a unique string array")
    return sorted(value)


def _selector_matches(entity: Dict[str, Any], selector: Dict[str, Any]) -> bool:
    if selector.get("type") and entity.get("entity_type") != selector["type"]:
        return False
    if selector.get("key") and not fnmatch.fnmatchcase(str(entity.get("entity_key") or ""), str(selector["key"])):
        return False
    if selector.get("label") and not fnmatch.fnmatchcase(str(entity.get("label") or ""), str(selector["label"])):
        return False
    return True


def _graph_path(
    spec: Dict[str, Any],
    sources: Dict[str, List[Dict[str, Any]]],
    budget: List[int],
) -> bool:
    entities = {}
    for item in sources["entities"]:
        _consume_budget(budget)
        entities[str(item["id"])] = item
    starts = [identifier for identifier, item in entities.items() if _selector_matches(item, spec["from"])]
    targets = {identifier for identifier, item in entities.items() if _selector_matches(item, spec["to"])}
    if not starts or not targets:
        return False
    allowed = set(spec.get("relations", []))
    adjacency: Dict[str, List[str]] = {}
    for relation in sources["relations"]:
        _consume_budget(budget)
        if allowed and relation.get("relation_type") not in allowed:
            continue
        source_id = str(relation.get("source_id"))
        target_id = str(relation.get("target_id"))
        adjacency.setdefault(source_id, []).append(target_id)
        adjacency.setdefault(target_id, []).append(source_id)
    depth_limit = int(spec.get("max_depth", 4))
    frontier = deque((identifier, 0) for identifier in sorted(starts))
    visited = set(starts)
    while frontier:
        _consume_budget(budget)
        if len(visited) > MAX_GRAPH_VISITS:
            raise RulePackError(f"graph traversal exceeds the {MAX_GRAPH_VISITS}-node limit")
        identifier, depth = frontier.popleft()
        if identifier in targets:
            return True
        if depth >= depth_limit:
            continue
        for neighbor in sorted(adjacency.get(identifier, [])):
            if neighbor not in visited:
                visited.add(neighbor)
                frontier.append((neighbor, depth + 1))
    return False


def _timestamp_ms(value: Any) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        result = parsed.astimezone(timezone.utc).timestamp() * 1000
        return result if math.isfinite(result) else None
    except (OverflowError, OSError, ValueError):
        return None


def _evaluate_predicate(
    predicate: Dict[str, Any],
    current: Any,
    root: Dict[str, Any],
    sources: Dict[str, List[Dict[str, Any]]],
    budget: List[int],
) -> Optional[bool]:
    _consume_budget(budget)
    if "all" in predicate:
        unknown = False
        for item in predicate["all"]:
            outcome = _evaluate_predicate(item, current, root, sources, budget)
            if outcome is False:
                return False
            unknown = unknown or outcome is None
        return None if unknown else True
    if "any" in predicate:
        unknown = False
        for item in predicate["any"]:
            outcome = _evaluate_predicate(item, current, root, sources, budget)
            if outcome is True:
                return True
            unknown = unknown or outcome is None
        return None if unknown else False
    if "not" in predicate:
        outcome = _evaluate_predicate(predicate["not"], current, root, sources, budget)
        return None if outcome is None else not outcome
    if "field" in predicate:
        base = current if current is not None else root
        return _compare(
            _resolve(base, predicate["field"]),
            predicate["op"],
            predicate.get("value"),
            budget,
        )
    if "domain" in predicate:
        domain = predicate["domain"]
        base = current if current is not None else root
        resolved = _resolve(base, domain["field"])
        if resolved is _MISSING or not isinstance(resolved, str) or not resolved.strip():
            return None
        actual_domain = canonical_host(resolved)
        expected = str(domain["value"]).lower().rstrip(".")
        if domain["mode"] == "exact":
            return actual_domain == canonical_host(expected)
        if domain["mode"] == "glob":
            return fnmatch.fnmatchcase(actual_domain, expected)
        parts = default_public_suffix_list().split(actual_domain)
        if parts.is_ip or parts.public_suffix == parts.registrable_domain:
            return None
        return parts.registrable_domain == registrable_domain(expected)
    for aggregate in ("count", "ratio", "duration"):
        if aggregate not in predicate:
            continue
        spec = predicate[aggregate]
        rows = sources[spec["source"]]
        matching: List[Dict[str, Any]] = []
        unknown_membership = False
        for item in rows:
            _consume_budget(budget)
            if "where" not in spec:
                matching.append(item)
                continue
            outcome = _evaluate_predicate(spec["where"], item, root, sources, budget)
            if outcome is True:
                matching.append(item)
            elif outcome is None:
                unknown_membership = True
        if unknown_membership:
            return None
        aggregate_value: Any
        if aggregate == "count":
            aggregate_value = len(matching)
        elif aggregate == "ratio":
            denominator_count = 0
            denominator_unknown = False
            for item in rows:
                _consume_budget(budget)
                if "denominator_where" not in spec:
                    denominator_count += 1
                    continue
                outcome = _evaluate_predicate(
                    spec["denominator_where"], item, root, sources, budget
                )
                if outcome is True:
                    denominator_count += 1
                elif outcome is None:
                    denominator_unknown = True
            if denominator_unknown or denominator_count == 0:
                return None
            aggregate_value = len(matching) / denominator_count
        else:
            timestamps = [_timestamp_ms(item.get("timestamp")) for item in matching]
            if len(timestamps) < 2 or any(item is None for item in timestamps):
                return None
            valid = [item for item in timestamps if item is not None]
            aggregate_value = max(valid) - min(valid)
        return _compare(aggregate_value, predicate["op"], predicate["value"], budget)
    if "graph_path" in predicate:
        return _graph_path(predicate["graph_path"], sources, budget)
    raise RulePackError("unknown predicate reached the evaluator")


def _evidence_item(source: str, row: Dict[str, Any]) -> Dict[str, Any]:
    if source == "events":
        return {
            "event_id": row.get("event_id"),
            "event_type": row.get("event_type"),
            "timestamp": row.get("timestamp"),
            "entity_id": row.get("entity_id"),
        }
    if source == "entities":
        return {
            "entity_id": row.get("id"),
            "entity_type": row.get("entity_type"),
            "entity_key": row.get("entity_key"),
        }
    if source == "relations":
        return {
            "relation_id": row.get("id"),
            "relation_type": row.get("relation_type"),
            "source_id": row.get("source_id"),
            "target_id": row.get("target_id"),
        }
    if source == "findings":
        return {"finding_id": row.get("id"), "rule_id": row.get("rule_id")}
    return {"session_id": row.get("id"), "started_at": row.get("started_at"), "status": row.get("status")}


def _prepare_packs(packs: Optional[Iterable[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    if packs is None:
        selected = [builtin_rule_pack()]
    else:
        if isinstance(packs, (str, bytes, dict)):
            raise RulePackError("rule packs must be an array of pack objects")
        try:
            selected = list(islice(iter(packs), MAX_PACKS + 1))
        except TypeError as exc:
            raise RulePackError("rule packs must be an array of pack objects") from exc
    if not selected:
        raise RulePackError("at least one rule pack is required")
    if len(selected) > MAX_PACKS:
        raise RulePackError(f"analysis accepts at most {MAX_PACKS} rule packs")
    identities = set()
    total_rules = 0
    for pack in selected:
        validate_rule_pack(pack)
        total_rules += len(pack["rules"])
        identity = (str(pack["id"]), str(pack["version"]))
        if identity in identities:
            raise RulePackError(f"duplicate rule pack selection: {identity[0]} {identity[1]}")
        identities.add(identity)
    if total_rules > MAX_TOTAL_RULES:
        raise RulePackError(f"analysis accepts at most {MAX_TOTAL_RULES} total rules")
    return sorted(selected, key=lambda item: (str(item["id"]), str(item["version"])))


def analyze_session_with_rules(
    session: str,
    packs: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    selected_packs = _prepare_packs(packs)
    identities = {(str(pack["id"]), str(pack["version"])) for pack in selected_packs}
    for pack in selected_packs:
        if not _minimum_version_satisfied(pack["min_wirescope_version"], __version__):
            raise RulePackError(
                f"rule pack {pack['id']} requires WireScope {pack['min_wirescope_version']} or newer"
            )
    with SessionStore(session) as store:
        store.connection.execute("BEGIN IMMEDIATE")
        active = store._require_session_id(session_id)
        if store.connection.execute("SELECT 1 FROM sessions WHERE id=?", (active,)).fetchone() is None:
            raise SessionError(f"session not found: {active}")
        sources = _row_sources(store, active, identities)
        root = {"summary": _active_summary(store, active, sources), "wirescope_version": __version__}
        budget = [0]
        proposed: List[Tuple[Dict[str, Any], Dict[str, Any], List[Dict[str, Any]]]] = []
        for pack in selected_packs:
            for rule in sorted(pack["rules"], key=lambda item: str(item["id"])):
                if _evaluate_predicate(rule["when"], None, root, sources, budget) is not True:
                    continue
                selector = rule["evidence"]
                evidence_rows = []
                evidence_limit = int(selector.get("limit", 20))
                for item in sources[selector["source"]]:
                    _consume_budget(budget)
                    if "where" in selector and _evaluate_predicate(
                        selector["where"], item, root, sources, budget
                    ) is not True:
                        continue
                    evidence_rows.append(item)
                    if len(evidence_rows) >= evidence_limit:
                        break
                evidence = [_evidence_item(selector["source"], item) for item in evidence_rows]
                if not evidence:
                    evidence = [{"session_id": active, "fact": rule["when"]}]
                proposed.append((pack, rule, evidence))

        # A run replaces the result set for the selected pack versions.  This
        # removes stale findings when evidence disappears and also prevents a
        # pack from matching findings produced by its own previous run.
        for pack_id, pack_version in sorted(identities):
            store.connection.execute(
                "DELETE FROM findings WHERE session_id=? AND pack_id=? AND pack_version=?",
                (active, pack_id, pack_version),
            )
        matched: List[str] = []
        for pack, rule, evidence in proposed:
            finding_id = store.add_finding(
                rule_id=str(rule["id"]),
                pack_id=str(pack["id"]),
                pack_version=str(pack["version"]),
                title=str(rule["title"]),
                category=str(rule["category"]),
                severity=str(rule["severity"]),
                confidence=float(rule["confidence"]),
                evidence=evidence,
                limitations=list(rule["limitations"]),
                explanation=str(rule["explanation"]),
                recommendation=str(rule["remediation"]),
                session_id=active,
            )
            matched.append(finding_id)
        applied_versions = set(_applied_pack_versions(store, active))
        applied_versions.update(f"{pack_id}@{pack_version}" for pack_id, pack_version in identities)
        if len(applied_versions) > MAX_APPLIED_PACK_VERSIONS:
            raise RulePackError(
                f"session records more than {MAX_APPLIED_PACK_VERSIONS} applied rule-pack versions"
            )
        store.set_metadata(f"rule_pack_versions:{active}", sorted(applied_versions))
        store.commit()
        placeholders = ",".join("?" for _item in matched)
        if matched:
            rows = store.connection.execute(
                f"SELECT * FROM findings WHERE id IN ({placeholders}) ORDER BY id",
                matched,
            ).fetchall()
        else:
            rows = []
        findings = [
            {
                **{
                    key: row[key]
                    for key in row.keys()
                    if key not in ("evidence_json", "limitations_json", "timestamp")
                },
                "evidence": _strict_stored_json(
                    row["evidence_json"], "finding evidence", list
                ),
                "limitations": _strict_stored_json(
                    row["limitations_json"], "finding limitations", list
                ),
            }
            for row in rows
        ]
        return {
            "schema_version": 1,
            "session_id": active,
            "packs": [
                {"id": pack["id"], "version": pack["version"], "schema_version": pack["schema_version"]}
                for pack in selected_packs
            ],
            "finding_count": len(findings),
            "findings": findings,
        }


def list_rules(packs: Optional[Iterable[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    result = []
    for pack in _prepare_packs(packs):
        for rule in pack["rules"]:
            result.append(
                {
                    "pack_id": pack["id"],
                    "pack_version": pack["version"],
                    "id": rule["id"],
                    "title": rule["title"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                }
            )
    return sorted(
        result,
        key=lambda item: (
            str(item["pack_id"]),
            str(item["pack_version"]),
            str(item["id"]),
        ),
    )


def show_rule(identifier: str, packs: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 1024:
        raise SessionError("rule identifier must be a non-empty bounded string")
    matches = []
    for pack in _prepare_packs(packs):
        for rule in pack["rules"]:
            qualified = f"{pack['id']}:{rule['id']}"
            if identifier in (rule["id"], qualified):
                matches.append((pack, rule))
    if len(matches) > 1:
        raise SessionError(f"rule id is ambiguous across selected pack versions: {identifier}")
    if matches:
        pack, rule = matches[0]
        return {
            "pack": {
                "id": pack["id"],
                "version": pack["version"],
                "schema_version": pack["schema_version"],
            },
            "rule": rule,
        }
    raise SessionError(f"rule not found: {identifier}")
