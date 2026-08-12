from __future__ import annotations

import fnmatch
import json
import math
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlsplit

from .analyzer import analyze_recording
from .artifacts import atomic_write_text
from .baseline import BaselineError, compare_baseline, load_baseline, session_snapshot
from .public_suffix import canonical_host, default_public_suffix_list, registrable_domain
from .session import SessionStore


MANIFEST_SCHEMA_VERSION = 1
MANIFEST_KIND = "wirescope-network-manifest"
TLS_ORDER = {"TLS 1.0": 10, "TLS 1.1": 11, "TLS 1.2": 12, "TLS 1.3": 13}
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_PROFILES = 64
MAX_LIST_VALUES = 10_000
MAX_STRING_LENGTH = 4096
MANIFEST_BUDGET_METRICS = {
    "session_duration_ms",
    "event_count",
    "request_count",
    "transfer_bytes",
    "failure_count",
    "connection_churn",
    "listener_count",
    "finding_count",
    "critical_finding_count",
    "error_finding_count",
    "request_duration_p90_ms",
    "ttfb_p90_ms",
}


class ManifestError(ValueError):
    """Raised when a Network Manifest is invalid or unsafe to evaluate."""


def _plain_text(value: str) -> bool:
    return all(
        ord(character) >= 32
        and ord(character) != 127
        and not 0xD800 <= ord(character) <= 0xDFFF
        for character in value
    )


def _canonical_domain_pattern(value: str) -> str:
    labels = value.strip().lower().rstrip(".").split(".")
    normalized = []
    for label in labels:
        if any(token in label for token in ("*", "?", "[", "]")):
            normalized.append(label)
            continue
        try:
            normalized.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            normalized.append(label)
    return ".".join(normalized)


def _empty_profile() -> Dict[str, Any]:
    return {
        "domains": {"allowed": [], "denied": [], "allowed_registrable": []},
        "protocols": [],
        "ports": [],
        "tls_minimum": None,
        "resolvers": [],
        "routes": [],
        "interfaces": [],
        "tunnel_required": None,
        "allowed_tracker_ids": [],
        "allowed_rule_ids": [],
        "budgets": {},
        "baseline": None,
        "required_findings": [],
        "forbidden_findings": [],
        "optional_checks": [],
    }


def _string_list(value: Any, path: str) -> List[str]:
    if (
        not isinstance(value, list)
        or len(value) > MAX_LIST_VALUES
        or not all(
            isinstance(item, str)
            and item.strip()
            and item == item.strip()
            and len(item) <= MAX_STRING_LENGTH
            and _plain_text(item)
            for item in value
        )
        or len(value) != len(set(value))
    ):
        raise ManifestError(f"{path} must be an array of non-empty strings")
    return value


def _reject_duplicate_pairs(pairs: Sequence[Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ManifestError(f"manifest JSON contains duplicate field: {key}")
        result[key] = item
    return result


def _reject_json_constant(value: str) -> Any:
    raise ManifestError(f"invalid numeric constant: {value}")


def _finite_number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    return number if math.isfinite(number) else None


def _percentile(values: Sequence[float], percentile: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * percentile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _request_from_payload(event_type: str, payload: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(payload, dict):
        return None
    request = payload.get("request")
    if isinstance(request, dict):
        return request
    if event_type.startswith("browser.Network"):
        params = payload.get("params")
        if isinstance(params, dict) and isinstance(params.get("request"), dict):
            return params["request"]
    return None


def validate_manifest(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError("manifest must be a JSON object")
    try:
        encoded_size = len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise ManifestError(f"manifest must contain finite JSON data: {exc}") from exc
    if encoded_size > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    allowed_root = {"schema_version", "kind", "mode", "approved", "profiles", "proposal"}
    unknown = set(value) - allowed_root
    required = {"schema_version", "kind", "mode", "approved", "profiles"}
    missing = required - set(value)
    if missing:
        raise ManifestError(f"manifest is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ManifestError(f"manifest has unknown fields: {', '.join(sorted(unknown))}")
    if (
        not isinstance(value["schema_version"], int)
        or isinstance(value["schema_version"], bool)
        or value["schema_version"] != MANIFEST_SCHEMA_VERSION
        or value["kind"] != MANIFEST_KIND
    ):
        raise ManifestError("unsupported Network Manifest schema or kind")
    if value["mode"] not in ("policy", "proposal"):
        raise ManifestError("manifest mode must be policy or proposal")
    if not isinstance(value["approved"], bool):
        raise ManifestError("manifest approved must be boolean")
    if value["mode"] == "proposal" and value["approved"]:
        raise ManifestError("a generated proposal cannot approve itself; change mode to policy during human review")
    profiles = value["profiles"]
    if not isinstance(profiles, dict) or not profiles or len(profiles) > MAX_PROFILES:
        raise ManifestError("manifest profiles must be a non-empty object")
    profile_fields = set(_empty_profile())
    for name, profile in profiles.items():
        if not isinstance(name, str) or not name.strip() or name != name.strip() or len(name) > 128 or not _plain_text(name) or not isinstance(profile, dict):
            raise ManifestError("profile names must be non-empty strings and values must be objects")
        missing_profile = profile_fields - set(profile)
        unknown_profile = set(profile) - profile_fields
        if missing_profile:
            raise ManifestError(f"profiles.{name} is missing fields: {', '.join(sorted(missing_profile))}")
        if unknown_profile:
            raise ManifestError(f"profiles.{name} has unknown fields: {', '.join(sorted(unknown_profile))}")
        domains = profile["domains"]
        if not isinstance(domains, dict) or set(domains) != {"allowed", "denied", "allowed_registrable"}:
            raise ManifestError(f"profiles.{name}.domains has an invalid shape")
        for key in ("allowed", "denied", "allowed_registrable"):
            _string_list(domains[key], f"profiles.{name}.domains.{key}")
        normalized_allowed = {_canonical_domain_pattern(item) for item in domains["allowed"]}
        normalized_denied = {_canonical_domain_pattern(item) for item in domains["denied"]}
        if len(normalized_allowed) != len(domains["allowed"]) or len(normalized_denied) != len(domains["denied"]):
            raise ManifestError(f"profiles.{name}.domains contains equivalent duplicate patterns")
        if normalized_allowed & normalized_denied:
            raise ManifestError(f"profiles.{name}.domains cannot allow and deny the same pattern")
        normalized_registrable = [canonical_host(item) for item in domains["allowed_registrable"]]
        if len(normalized_registrable) != len(set(normalized_registrable)):
            raise ManifestError(
                f"profiles.{name}.domains.allowed_registrable contains equivalent duplicates"
            )
        for domain in domains["allowed_registrable"]:
            normalized = canonical_host(domain)
            parts = default_public_suffix_list().split(normalized)
            if (
                any(token in domain for token in ("*", "?", "[", "]"))
                or not normalized
                or parts.is_ip
                or parts.registrable_domain != normalized
                or parts.public_suffix == normalized
            ):
                raise ManifestError(f"profiles.{name}.domains.allowed_registrable must contain registrable domains, not patterns")
        _string_list(profile["protocols"], f"profiles.{name}.protocols")
        if not isinstance(profile["ports"], list) or not all(
            isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535
            for port in profile["ports"]
        ):
            raise ManifestError(f"profiles.{name}.ports must contain integers from 1 to 65535")
        if len(profile["ports"]) != len(set(profile["ports"])) or len(profile["ports"]) > MAX_LIST_VALUES:
            raise ManifestError(f"profiles.{name}.ports must not contain duplicates")
        if profile["tls_minimum"] is not None and profile["tls_minimum"] not in TLS_ORDER:
            raise ManifestError(f"profiles.{name}.tls_minimum is unsupported")
        for key in (
            "resolvers",
            "routes",
            "interfaces",
            "allowed_tracker_ids",
            "allowed_rule_ids",
            "required_findings",
            "forbidden_findings",
            "optional_checks",
        ):
            _string_list(profile[key], f"profiles.{name}.{key}")
        if profile["tunnel_required"] is not None and not isinstance(profile["tunnel_required"], bool):
            raise ManifestError(f"profiles.{name}.tunnel_required must be boolean or null")
        budgets = profile["budgets"]
        if not isinstance(budgets, dict) or not all(
            isinstance(metric, str)
            and metric
            and len(metric) <= 256
            and metric in MANIFEST_BUDGET_METRICS
            and _finite_number(limit) is not None
            and float(limit) >= 0
            for metric, limit in budgets.items()
        ) or len(budgets) > MAX_LIST_VALUES:
            raise ManifestError(f"profiles.{name}.budgets must map metric names to non-negative numbers")
        if set(profile["required_findings"]) & set(profile["forbidden_findings"]):
            raise ManifestError(f"profiles.{name} cannot require and forbid the same finding")
        allowed_optional = {
            "domains.allowed",
            "protocols",
            "ports",
            "resolvers",
            "routes",
            "interfaces",
            "tls",
            "tunnel",
            "trackers.allowed",
            "rules.allowed",
            "baseline",
        } | {f"budget.{metric}" for metric in budgets}
        unknown_optional = set(profile["optional_checks"]) - allowed_optional
        if unknown_optional:
            raise ManifestError(f"profiles.{name}.optional_checks contains unknown checks: {', '.join(sorted(unknown_optional))}")
        baseline = profile["baseline"]
        if baseline is not None:
            if not isinstance(baseline, str) or not baseline:
                raise ManifestError(f"profiles.{name}.baseline must be a local path or null")
            if len(baseline) > MAX_STRING_LENGTH or not _plain_text(baseline):
                raise ManifestError(f"profiles.{name}.baseline must be a bounded plain-text path")
            parsed = urlsplit(baseline)
            if parsed.scheme or parsed.netloc:
                raise ManifestError("remote baseline references and remote includes are not allowed")
    if "proposal" in value:
        proposal = value["proposal"]
        if (
            not isinstance(proposal, dict)
            or set(proposal) != {"source_kind", "review_required", "notice"}
            or not isinstance(proposal.get("source_kind"), str)
            or not _plain_text(proposal.get("source_kind", ""))
            or proposal.get("review_required") is not True
            or not isinstance(proposal.get("notice"), str)
            or not proposal["notice"].strip()
            or len(proposal["notice"]) > MAX_STRING_LENGTH
            or not _plain_text(proposal["notice"])
        ):
            raise ManifestError("manifest proposal metadata has an invalid shape")
    return value


def load_manifest(path: str) -> Dict[str, Any]:
    source = Path(path)
    try:
        size = source.stat().st_size
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest does not exist: {path}") from exc
    except OSError as exc:
        raise ManifestError(f"cannot inspect manifest: {path}: {exc}") from exc
    if size > MAX_MANIFEST_BYTES:
        raise ManifestError(f"manifest exceeds {MAX_MANIFEST_BYTES} bytes")
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ManifestError(f"invalid manifest JSON at line {exc.lineno}: {exc.msg}") from exc
    except RecursionError as exc:
        raise ManifestError("manifest JSON nesting is too deep") from exc
    except OSError as exc:
        raise ManifestError(f"cannot read manifest: {path}: {exc}") from exc
    return validate_manifest(value)


def _recording_observation(path: str) -> Dict[str, Any]:
    report = analyze_recording(path)
    requests = report.get("requests", []) if isinstance(report.get("requests"), list) else []
    domains = sorted(
        {
            str(item.get("domain"))
            for item in requests
            if isinstance(item, dict) and item.get("domain")
        }
    )
    protocols = sorted(
        {
            str(item.get("protocol"))
            for item in requests
            if isinstance(item, dict) and item.get("protocol") not in (None, "", "unknown")
        }
    )
    ports = sorted(
        {
            int(item["remote_port"])
            for item in requests
            if isinstance(item, dict)
            and isinstance(item.get("remote_port"), int)
            and not isinstance(item.get("remote_port"), bool)
        }
    )
    tls_versions = sorted(
        {
            str(details.get("protocol"))
            for item in requests
            for details in [item.get("security_details") if isinstance(item, dict) else None]
            if isinstance(details, dict) and details.get("protocol")
        }
    )
    tracker_ids = sorted(
        {
            str(match.get("rule_id"))
            for item in requests
            for match in [item.get("tracker_match") if isinstance(item, dict) else None]
            if isinstance(match, dict) and match.get("rule_id")
        }
    )
    request_count = len(requests)
    transfer_values: List[float] = []
    duration_values: List[float] = []
    ttfb_values: List[float] = []
    failure_values: List[bool] = []
    secure_requests = 0
    tls_observed = 0
    protocol_observed = 0
    port_observed = 0
    domain_observed = 0
    tracker_observed = 0
    for item in requests:
        if not isinstance(item, dict):
            continue
        if item.get("domain"):
            domain_observed += 1
        if item.get("protocol") not in (None, "", "unknown"):
            protocol_observed += 1
        port = item.get("remote_port")
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            port_observed += 1
        if "tracker_match" in item or "tracker" in item:
            tracker_observed += 1
        transfer = _finite_number(item.get("transfer_bytes"))
        if transfer is not None and transfer >= 0:
            transfer_values.append(transfer)
        duration = _finite_number(item.get("duration_ms"))
        if duration is not None and duration >= 0:
            duration_values.append(duration)
        timing = item.get("timing")
        ttfb = _finite_number(timing.get("ttfb_ms")) if isinstance(timing, dict) else None
        if ttfb is not None and ttfb >= 0:
            ttfb_values.append(ttfb)
        status = _finite_number(item.get("status"))
        failed = item.get("failed")
        if isinstance(failed, bool) or status is not None:
            failure_values.append(failed is True or (status is not None and status >= 400))
        if item.get("scheme") in ("https", "wss"):
            secure_requests += 1
            details = item.get("security_details")
            if isinstance(details, dict) and details.get("protocol") in TLS_ORDER:
                tls_observed += 1
    metrics = {
        "request_count": float(request_count),
        "transfer_bytes": sum(transfer_values) if len(transfer_values) == request_count else (0.0 if request_count == 0 else None),
        "failure_count": float(sum(failure_values)) if len(failure_values) == request_count else (0.0 if request_count == 0 else None),
        "request_duration_p90_ms": _percentile(duration_values, 0.90) if len(duration_values) == request_count and request_count else None,
        "ttfb_p90_ms": _percentile(ttfb_values, 0.90) if len(ttfb_values) == request_count and request_count else None,
    }
    return {
        "kind": "recording",
        "sets": {
            "domains": domains,
            "protocols": protocols,
            "ports": ports,
            "resolvers": [],
            "routes": [],
            "interfaces": [],
            "tunnels": [],
            "tracker_ids": tracker_ids,
            "rule_ids": sorted(
                {
                    str(item.get("rule_id") or item.get("code"))
                    for item in report.get("findings", [])
                    if isinstance(item, dict) and (item.get("rule_id") or item.get("code"))
                }
            ),
            "finding_ids": sorted(
                {
                    str(item.get("id") or item.get("rule_id") or item.get("code"))
                    for item in report.get("findings", [])
                    if isinstance(item, dict) and (item.get("id") or item.get("rule_id") or item.get("code"))
                }
            ),
            "tls_versions": tls_versions,
        },
        "metrics": metrics,
        "values": {"tunnel_active": None},
        "available": {
            "domains": request_count > 0 and domain_observed == request_count,
            "protocols": request_count > 0 and protocol_observed == request_count,
            "ports": request_count > 0 and port_observed == request_count,
            "tls": secure_requests > 0 and tls_observed == secure_requests,
            "resolvers": False,
            "routes": False,
            "interfaces": False,
            "tunnel": False,
            "findings": True,
            "trackers": request_count > 0 and tracker_observed == request_count,
        },
    }


def _session_observation(path: str) -> Dict[str, Any]:
    snapshot = session_snapshot(path)
    sets = {key: list(value) for key, value in snapshot["sets"].items()}
    sets.setdefault("interfaces", [])
    sets["tracker_ids"] = []
    sets["rule_ids"] = []
    sets["finding_ids"] = []
    sets["tls_versions"] = []
    request_domains = set()
    request_count = 0
    domain_observed = 0
    protocol_observed = 0
    port_observed = 0
    tracker_observed = 0
    secure_requests = 0
    tls_observed = 0
    dns_seen = routes_seen = interfaces_seen = tunnel_seen = False
    dns_complete = routes_complete = interfaces_complete = tunnel_complete = True
    available = {
        "domains": bool(sets.get("domains")),
        "protocols": False,
        "ports": False,
        "tls": False,
        "resolvers": False,
        "routes": False,
        "interfaces": False,
        "tunnel": False,
        "findings": True,
        "trackers": True,
    }
    tunnel_active: Optional[bool] = None
    with SessionStore(path, read_only=True) as store:
        store.connection.execute("BEGIN")
        active = str(snapshot["session_id"])
        for row in store.connection.execute(
            "SELECT event_type, payload_json FROM events WHERE session_id=? ORDER BY sequence", (active,)
        ):
            event_type = str(row["event_type"])
            try:
                payload = json.loads(
                    row["payload_json"],
                    object_pairs_hook=_reject_duplicate_pairs,
                    parse_constant=_reject_json_constant,
                )
            except json.JSONDecodeError as exc:
                raise ManifestError(f"event payload contains invalid JSON: {exc.msg}") from exc
            except RecursionError as exc:
                raise ManifestError("event payload JSON nesting is too deep") from exc
            if not isinstance(payload, dict):
                raise ManifestError("event payload must contain a JSON object")
            if event_type.startswith("network.dns"):
                dns_seen = True
                value = payload.get("value") if isinstance(payload, dict) else None
                dns_complete = dns_complete and isinstance(value, list) and all(
                    isinstance(item, dict)
                    and (
                        "nameservers" not in item
                        or isinstance(item.get("nameservers"), list)
                    )
                    for item in value if isinstance(value, list)
                )
            if event_type.startswith("network.routes"):
                routes_seen = True
                value = payload.get("value") if isinstance(payload, dict) else None
                routes_complete = routes_complete and isinstance(value, list) and all(
                    isinstance(item, dict) for item in value if isinstance(value, list)
                )
            if event_type.startswith("network.interfaces"):
                interfaces_seen = True
                value = payload.get("value") if isinstance(payload, dict) else None
                if isinstance(value, list):
                    for interface in value:
                        if isinstance(interface, dict):
                            name = interface.get("name") or interface.get("interface") or interface.get("device")
                            if name:
                                sets["interfaces"].append(str(name))
                            else:
                                interfaces_complete = False
                        else:
                            interfaces_complete = False
                else:
                    interfaces_complete = False
            if event_type.startswith("network.vpn"):
                tunnel_seen = True
                value = payload.get("value") if isinstance(payload, dict) else None
                if isinstance(value, dict) and isinstance(value.get("active"), bool):
                    tunnel_active = value["active"]
                else:
                    tunnel_complete = False
            request = _request_from_payload(event_type, payload)
            if isinstance(request, dict):
                request_count += 1
                if isinstance(request.get("domain"), str) and request["domain"]:
                    domain_observed += 1
                    request_domains.add(str(request["domain"]))
                    if len(request_domains) > MAX_LIST_VALUES:
                        raise ManifestError(
                            f"session contains more than {MAX_LIST_VALUES} observed request domains"
                        )
                if request.get("protocol") not in (None, "", "unknown"):
                    protocol_observed += 1
                port = request.get("remote_port")
                if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
                    port_observed += 1
                if "tracker_match" in request or "tracker" in request:
                    tracker_observed += 1
                security = request.get("security_details")
                if request.get("scheme") in ("https", "wss"):
                    secure_requests += 1
                    if isinstance(security, dict) and security.get("protocol") in TLS_ORDER:
                        tls_observed += 1
                        sets["tls_versions"].append(str(security["protocol"]))
                tracker = request.get("tracker_match")
                if isinstance(tracker, dict) and tracker.get("rule_id"):
                    sets["tracker_ids"].append(str(tracker["rule_id"]))
        for row in store.connection.execute(
            "SELECT id, rule_id FROM findings WHERE session_id=? ORDER BY id", (active,)
        ):
            sets["finding_ids"].append(str(row["id"]))
            sets["rule_ids"].append(str(row["rule_id"]))
    try:
        final_snapshot = session_snapshot(path)
    except BaselineError as exc:
        raise ManifestError(f"session changed or became invalid during manifest observation: {exc}") from exc
    if (
        final_snapshot["fingerprint"] != snapshot["fingerprint"]
        or final_snapshot["session_id"] != snapshot["session_id"]
    ):
        raise ManifestError("session changed while manifest evidence was being observed")
    sets["domains"] = sorted(set(sets["domains"]) | request_domains)
    for name in sets:
        sets[name] = sorted(set(sets[name]))
    available["domains"] = request_count > 0 and domain_observed == request_count
    available["protocols"] = request_count > 0 and protocol_observed == request_count
    available["ports"] = request_count > 0 and port_observed == request_count
    available["trackers"] = request_count > 0 and tracker_observed == request_count
    available["tls"] = secure_requests > 0 and tls_observed == secure_requests
    available["resolvers"] = dns_seen and dns_complete
    available["routes"] = routes_seen and routes_complete
    available["interfaces"] = interfaces_seen and interfaces_complete
    available["tunnel"] = tunnel_seen and tunnel_complete and tunnel_active is not None
    available["findings"] = bool(snapshot["rule_pack_versions"])
    return {
        "kind": "session",
        "sets": sets,
        "metrics": snapshot["metrics"],
        "values": {"tunnel_active": tunnel_active},
        "available": available,
        "snapshot": snapshot,
    }


def observe_input(path: str) -> Dict[str, Any]:
    return _session_observation(path) if Path(path).suffix.lower() == ".wsdb" else _recording_observation(path)


def discover_manifest(source: str, output: Optional[str] = None, *, profile: str = "observed") -> Dict[str, Any]:
    if not isinstance(profile, str) or not profile.strip() or profile != profile.strip() or len(profile) > 128:
        raise ManifestError("profile name must be a non-empty string of at most 128 characters")
    observation = observe_input(source)
    policy = _empty_profile()
    policy["domains"]["allowed"] = list(observation["sets"]["domains"])
    policy["domains"]["allowed_registrable"] = sorted(
        {
            parts.registrable_domain
            for domain in observation["sets"]["domains"]
            for parts in [default_public_suffix_list().split(domain)]
            if domain and not parts.is_ip and parts.public_suffix != parts.registrable_domain
        }
    )
    policy["protocols"] = list(observation["sets"]["protocols"])
    policy["ports"] = sorted(int(port) for port in observation["sets"]["ports"] if str(port).isdigit())
    policy["resolvers"] = list(observation["sets"].get("resolvers", []))
    policy["routes"] = list(observation["sets"].get("routes", []))
    policy["interfaces"] = list(observation["sets"].get("interfaces", []))
    policy["allowed_tracker_ids"] = list(observation["sets"].get("tracker_ids", []))
    policy["allowed_rule_ids"] = list(observation["sets"].get("rule_ids", []))
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "kind": MANIFEST_KIND,
        "mode": "proposal",
        "approved": False,
        "profiles": {profile: policy},
        "proposal": {
            "source_kind": observation["kind"],
            "review_required": True,
            "notice": "Observed values are a proposal, not an allowlist, until a human changes mode to policy and approved to true.",
        },
    }
    validate_manifest(manifest)
    if output:
        atomic_write_text(output, json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return manifest


def _domain_allowed(domain: str, profile: Dict[str, Any]) -> bool:
    policies = profile["domains"]
    normalized = canonical_host(domain)
    if any(fnmatch.fnmatchcase(normalized, _canonical_domain_pattern(pattern)) for pattern in policies["allowed"]):
        return True
    return registrable_domain(normalized) in {
        registrable_domain(value) for value in policies["allowed_registrable"]
    }


def _check(
    results: List[Dict[str, Any]],
    identifier: str,
    status: str,
    *,
    required: bool,
    expected: Any,
    actual: Any,
    evidence: Optional[Any] = None,
) -> None:
    results.append(
        {
            "id": identifier,
            "status": status,
            "required": required,
            "expected": expected,
            "actual": actual,
            "evidence": evidence if evidence is not None else actual,
        }
    )


def check_manifest(
    manifest: Dict[str, Any],
    source: str,
    *,
    profile_name: str,
    manifest_path: Optional[str] = None,
) -> Dict[str, Any]:
    manifest = validate_manifest(manifest)
    if manifest["mode"] != "policy" or not manifest["approved"]:
        raise ManifestError("manifest is an unapproved proposal; human review must set mode=policy and approved=true")
    if profile_name not in manifest["profiles"]:
        raise ManifestError(f"manifest profile not found: {profile_name}")
    profile = manifest["profiles"][profile_name]
    observation = observe_input(source)
    optional = set(profile["optional_checks"])
    results: List[Dict[str, Any]] = []

    domains = observation["sets"]["domains"]
    domain_available = bool(observation["available"].get("domains", False))
    denied_patterns = sorted(profile["domains"]["denied"])
    if domain_available:
        denied = sorted(
            domain
            for domain in domains
            if any(fnmatch.fnmatchcase(canonical_host(domain), _canonical_domain_pattern(pattern)) for pattern in denied_patterns)
        )
        _check(
            results,
            "domains.denied",
            "violation" if denied else "pass",
            required=True,
            expected={"denied": denied_patterns},
            actual=denied,
        )
    elif denied_patterns:
        _check(results, "domains.denied", "unevaluable", required=True, expected={"denied": denied_patterns}, actual=None)
    if profile["domains"]["allowed"] or profile["domains"]["allowed_registrable"]:
        required = "domains.allowed" not in optional
        expected_domains = {
            "allowed": sorted(profile["domains"]["allowed"]),
            "denied": denied_patterns,
            "allowed_registrable": sorted(profile["domains"]["allowed_registrable"]),
        }
        if not domain_available:
            _check(results, "domains.allowed", "unevaluable", required=required, expected=expected_domains, actual=None)
        else:
            unexpected = sorted(domain for domain in domains if not _domain_allowed(domain, profile))
            _check(
                results,
                "domains.allowed",
                "violation" if unexpected else "pass",
                required=required,
                expected=expected_domains,
                actual=unexpected,
            )

    for group, configured in (
        ("protocols", profile["protocols"]),
        ("ports", profile["ports"]),
        ("resolvers", profile["resolvers"]),
        ("routes", profile["routes"]),
        ("interfaces", profile["interfaces"]),
    ):
        if not configured:
            continue
        required = group not in optional
        if not observation["available"].get(group, False):
            _check(results, group, "unevaluable", required=required, expected=sorted(configured, key=str), actual=None)
            continue
        actual_values = observation["sets"].get(group, [])
        normalized_expected = {str(item) for item in configured}
        unexpected = sorted(item for item in actual_values if str(item) not in normalized_expected)
        _check(
            results,
            group,
            "violation" if unexpected else "pass",
            required=required,
            expected=sorted(configured, key=str),
            actual=unexpected,
        )

    if profile["tls_minimum"] is not None:
        required = "tls" not in optional
        versions = observation["sets"]["tls_versions"]
        if not observation["available"]["tls"]:
            _check(results, "tls", "unevaluable", required=required, expected=profile["tls_minimum"], actual=None)
        else:
            weak = sorted(
                version
                for version in versions
                if TLS_ORDER.get(version, -1) < TLS_ORDER[profile["tls_minimum"]]
            )
            _check(
                results,
                "tls",
                "violation" if weak else "pass",
                required=required,
                expected={"minimum": profile["tls_minimum"]},
                actual=weak,
            )

    if profile["tunnel_required"] is not None:
        required = "tunnel" not in optional
        actual_tunnel = observation["values"]["tunnel_active"]
        status = (
            "unevaluable"
            if not observation["available"]["tunnel"] or actual_tunnel is None
            else ("pass" if actual_tunnel == profile["tunnel_required"] else "violation")
        )
        _check(
            results,
            "tunnel",
            status,
            required=required,
            expected=profile["tunnel_required"],
            actual=actual_tunnel,
        )

    for group, allowed in (
        ("trackers", profile["allowed_tracker_ids"]),
        ("rules", profile["allowed_rule_ids"]),
    ):
        actual = observation["sets"]["tracker_ids" if group == "trackers" else "rule_ids"]
        available = bool(observation["available"].get("trackers" if group == "trackers" else "findings", False))
        required = f"{group}.allowed" not in optional
        if not available:
            _check(results, f"{group}.allowed", "unevaluable", required=required, expected=sorted(allowed), actual=None)
            continue
        if not actual and not allowed:
            continue
        unexpected = sorted(set(actual) - set(allowed))
        _check(
            results,
            f"{group}.allowed",
            "violation" if unexpected else "pass",
            required=required,
            expected=sorted(allowed),
            actual=unexpected,
        )

    for metric, limit in sorted(profile["budgets"].items()):
        actual = observation["metrics"].get(metric)
        if _finite_number(actual) is None:
            actual = None
        required = f"budget.{metric}" not in optional
        status = "unevaluable" if actual is None else ("pass" if float(actual) <= float(limit) else "violation")
        _check(
            results,
            f"budget.{metric}",
            status,
            required=required,
            expected={"maximum": limit},
            actual=actual,
        )

    findings = set(observation["sets"]["finding_ids"]) | set(observation["sets"]["rule_ids"])
    findings_available = bool(observation["available"].get("findings", False))
    for identifier in sorted(profile["required_findings"]):
        status = (
            "pass"
            if identifier in findings
            else ("violation" if findings_available else "unevaluable")
        )
        _check(
            results,
            f"finding.required.{identifier}",
            status,
            required=True,
            expected="present",
            actual="present" if identifier in findings else "missing",
        )
    for identifier in sorted(profile["forbidden_findings"]):
        status = (
            "violation"
            if identifier in findings
            else ("pass" if findings_available else "unevaluable")
        )
        _check(
            results,
            f"finding.forbidden.{identifier}",
            status,
            required=True,
            expected="absent",
            actual="present" if identifier in findings else "absent",
        )

    if profile["baseline"]:
        required = "baseline" not in optional
        if Path(source).suffix.lower() != ".wsdb":
            _check(results, "baseline", "unevaluable", required=required, expected=profile["baseline"], actual=None)
        else:
            root = Path(manifest_path).parent if manifest_path else Path.cwd()
            baseline_path = root / profile["baseline"]
            comparison = compare_baseline(load_baseline(str(baseline_path)), source)
            status = "pass" if comparison["state"] == "pass" else (
                "violation" if comparison["state"] == "regression" else "unevaluable"
            )
            _check(
                results,
                "baseline",
                status,
                required=required,
                expected=profile["baseline"],
                actual=comparison["state"],
                evidence=comparison,
            )

    results.sort(key=lambda item: item["id"])
    violations = [item for item in results if item["status"] == "violation"]
    required_unknown = [
        item for item in results if item["status"] == "unevaluable" and item["required"]
    ]
    warnings = [
        item for item in results if item["status"] == "unevaluable" and not item["required"]
    ]
    passed = not violations and not required_unknown
    return {
        "schema_version": 1,
        "kind": "wirescope-manifest-result",
        "profile": profile_name,
        "source": source,
        "passed": passed,
        "exit_code": 0 if passed else 1,
        "summary": {
            "checks": len(results),
            "violations": len(violations),
            "required_unevaluable": len(required_unknown),
            "warnings": len(warnings),
        },
        "checks": results,
    }


def _xml_safe_text(value: Any) -> str:
    return "".join(
        character
        for character in str(value)
        if ord(character) in (9, 10, 13)
        or 0x20 <= ord(character) <= 0xD7FF
        or 0xE000 <= ord(character) <= 0xFFFD
        or 0x10000 <= ord(character) <= 0x10FFFF
    )


def write_junit(result: Dict[str, Any], output: str) -> None:
    suite = ET.Element(
        "testsuite",
        {
            "name": "WireScope Network Manifest",
            "tests": str(len(result["checks"])),
            "failures": str(result["summary"]["violations"] + result["summary"]["required_unevaluable"]),
            "skipped": str(result["summary"]["warnings"]),
        },
    )
    for check in result["checks"]:
        case = ET.SubElement(
            suite,
            "testcase",
            {"name": _xml_safe_text(check["id"]), "classname": "wirescope.manifest"},
        )
        details = _xml_safe_text(json.dumps(check, ensure_ascii=False, sort_keys=True))
        if check["status"] == "violation" or (check["status"] == "unevaluable" and check["required"]):
            failure = ET.SubElement(case, "failure", {"message": check["status"]})
            failure.text = details
        elif check["status"] == "unevaluable":
            skipped = ET.SubElement(case, "skipped", {"message": "optional evidence unavailable"})
            skipped.text = details
    atomic_write_text(output, ET.tostring(suite, encoding="unicode") + "\n")
