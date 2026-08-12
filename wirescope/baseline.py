from __future__ import annotations

import hashlib
import html
import json
import math
import os
import stat
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .artifacts import atomic_write_text
from .session import SessionError, SessionStore, _hash_file


BASELINE_SCHEMA_VERSION = 1
COMPARISON_SCHEMA_VERSION = 1
DEFAULT_RELATIVE_THRESHOLD = 0.10
DEFAULT_MAD_MULTIPLIER = 3.0
MAX_BASELINE_BYTES = 8 * 1024 * 1024
MAX_BASELINE_SAMPLES = 1000
MAX_SNAPSHOT_EVENTS = 2_000_000
MAX_SNAPSHOT_ROWS = 2_500_000
MAX_SESSION_RECORDINGS = 10_000
MAX_SNAPSHOT_JSON_BYTES = 256 * 1024 * 1024
MAX_SET_VALUES = 100_000
MAX_RULE_PACK_VERSIONS = 1000
BASELINE_METRIC_NAMES = {
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
BASELINE_SET_NAMES = {
    "domains",
    "protocols",
    "ports",
    "resolvers",
    "routes",
    "tunnels",
    "interfaces",
    "relation_types",
    "relations",
}


class BaselineError(ValueError):
    """Raised when a baseline or comparison contract is invalid."""


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BaselineError(f"baseline JSON contains duplicate field: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise BaselineError(f"invalid numeric constant: {value}")


def _strict_stored_json(raw: Any, label: str) -> Any:
    if not isinstance(raw, str):
        raise BaselineError(f"{label} is not stored as JSON text")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{label} contains invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise BaselineError(f"{label} JSON nesting is too deep") from exc
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise BaselineError(f"{label} contains a non-finite JSON number")
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return value


def _strict_stored_object(raw: Any, label: str) -> Dict[str, Any]:
    value = _strict_stored_json(raw, label)
    if not isinstance(value, dict):
        raise BaselineError(f"{label} must contain a JSON object")
    return value


def _canonical(value: Any) -> str:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        rendered.encode("utf-8")
        return rendered
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise BaselineError(f"value is not canonical finite UTF-8 JSON: {exc}") from exc


def _file_fingerprint(path: Path) -> str:
    try:
        return _hash_file(path)[0]
    except (OSError, SessionError) as exc:
        raise BaselineError(f"cannot fingerprint session: {path}: {exc}") from exc


def _require_stable_session_file(path: Path) -> None:
    """Reject a live or structurally unsafe SQLite source.

    A hash of the main database does not identify committed frames that still
    live in a WAL.  Baselines therefore require a closed/checkpointed artifact
    and recheck this invariant around the read transaction.
    """

    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(f"{path}{suffix}")
        try:
            info = os.lstat(sidecar)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BaselineError(f"cannot inspect SQLite sidecar: {sidecar}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise BaselineError(f"invalid SQLite sidecar: {sidecar}")
        if suffix in ("-wal", "-journal") and info.st_size:
            raise BaselineError(
                f"session has an active SQLite {suffix[1:]} sidecar; close/checkpoint it first: {path}"
            )


def _timestamp_ms(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value:
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp() * 1000
    except (ValueError, OverflowError, OSError):
        return None


def _numeric(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def _bounded_add(values: Set[str], value: Any, category: str) -> None:
    values.add(str(value))
    if len(values) > MAX_SET_VALUES:
        raise BaselineError(f"session {category} exceeds the {MAX_SET_VALUES}-value baseline limit")


def _percentile(values: Sequence[float], percentile: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * percentile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def _metric_stats(values: Sequence[float], total_samples: int) -> Dict[str, Any]:
    ordered = sorted(float(item) for item in values)
    median = statistics.median(ordered)
    absolute_deviations = [abs(item - median) for item in ordered]
    return {
        "median": round(float(median), 6),
        "p90": round(float(_percentile(ordered, 0.90)), 6),
        "mad": round(float(statistics.median(absolute_deviations)), 6),
        "sample_count": len(ordered),
        "missing_count": total_samples - len(ordered),
        "minimum": round(min(ordered), 6),
        "maximum": round(max(ordered), 6),
    }


def _request_payload(event_type: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    request = payload.get("request")
    if isinstance(request, dict):
        return request
    if event_type.startswith("browser.Network"):
        params = payload.get("params")
        if isinstance(params, dict) and isinstance(params.get("request"), dict):
            return params["request"]
    return None


def session_snapshot(path: str) -> Dict[str, Any]:
    source = Path(path)
    _require_stable_session_file(source)
    with SessionStore(str(source), read_only=True) as store:
        store.connection.execute("BEGIN")
        _require_stable_session_file(source)
        fingerprint = _file_fingerprint(source)
        session_count = int(store.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
        if session_count == 0:
            raise BaselineError(f"session has no recordings: {path}")
        if session_count > MAX_SESSION_RECORDINGS:
            raise BaselineError(
                f"session contains more than {MAX_SESSION_RECORDINGS} recordings"
            )
        session_rows = store.connection.execute("SELECT * FROM sessions ORDER BY id").fetchall()
        timestamped_rows = []
        for row in session_rows:
            started_ms = _timestamp_ms(row["started_at"])
            if started_ms is None:
                raise BaselineError(f"session has an invalid start timestamp: {path}")
            timestamped_rows.append((started_ms, str(row["id"]), row))
        session_row = max(timestamped_rows, key=lambda item: (item[0], item[1]))[2]
        session = {
            **{key: session_row[key] for key in session_row.keys() if key not in ("host_json", "config_json", "summary_json")},
            "host": _strict_stored_object(session_row["host_json"], "session host metadata"),
            "config": _strict_stored_object(session_row["config_json"], "session configuration"),
            "summary": _strict_stored_object(session_row["summary_json"], "session summary"),
        }
        active = str(session["id"])
        started = _timestamp_ms(session.get("started_at"))
        ended = _timestamp_ms(session.get("ended_at"))
        if started is not None and ended is not None and ended < started:
            raise BaselineError(f"session has an end timestamp before its start: {path}")
        duration_ms = ended - started if started is not None and ended is not None else None

        counted_tables = ["entities", "relations", "events", "findings"]
        if store.schema_version >= 2:
            counted_tables.append("artifacts")
        row_counts = {
            table: int(
                store.connection.execute(
                    f'SELECT COUNT(*) FROM "{table}" WHERE session_id=?', (active,)
                ).fetchone()[0]
            )
            for table in counted_tables
        }
        event_count = row_counts["events"]
        if event_count > MAX_SNAPSHOT_EVENTS:
            raise BaselineError(f"session exceeds the {MAX_SNAPSHOT_EVENTS}-event baseline limit")
        if sum(row_counts.values()) > MAX_SNAPSHOT_ROWS:
            raise BaselineError(f"session exceeds the {MAX_SNAPSHOT_ROWS}-row baseline limit")
        json_columns = [
            ("events", "payload_json"),
            ("entities", "attributes_json"),
            ("relations", "evidence_json"),
            ("findings", "evidence_json"),
        ]
        if store.schema_version >= 2:
            json_columns.append(("findings", "limitations_json"))
        json_bytes = sum(
            int(
                store.connection.execute(
                    f'SELECT COALESCE(SUM(LENGTH(CAST("{column}" AS BLOB))), 0) FROM "{table}" WHERE session_id=?',
                    (active,),
                ).fetchone()[0]
            )
            for table, column in json_columns
        )
        json_bytes += sum(
            int(
                store.connection.execute(
                    f'SELECT COALESCE(LENGTH(CAST("{column}" AS BLOB)), 0) FROM sessions WHERE id=?',
                    (active,),
                ).fetchone()[0]
            )
            for column in ("host_json", "config_json", "summary_json")
        )
        if json_bytes > MAX_SNAPSHOT_JSON_BYTES:
            raise BaselineError(
                f"session JSON evidence exceeds the {MAX_SNAPSHOT_JSON_BYTES}-byte baseline limit"
            )

        request_count = 0
        transfer_values: List[float] = []
        duration_values: List[float] = []
        ttfb_values: List[float] = []
        failures = 0
        transfer_observed = 0
        failure_observed = 0
        protocols: Set[str] = set()
        ports: Set[str] = set()
        resolvers: Set[str] = set()
        routes: Set[str] = set()
        tunnels: Set[str] = set()
        interfaces: Set[str] = set()
        churn = 0
        for row in store.connection.execute(
            "SELECT event_type, payload_json FROM events WHERE session_id=? ORDER BY sequence", (active,)
        ):
            event_type = str(row["event_type"])
            payload = _strict_stored_object(row["payload_json"], "event payload")
            if event_type in ("connection.opened", "connection.closed"):
                churn += 1
                connection = payload.get("connection") if isinstance(payload, dict) else None
                if isinstance(connection, dict):
                    remote = connection.get("remote")
                    if isinstance(remote, dict) and remote.get("port") not in (None, ""):
                        _bounded_add(ports, remote["port"], "ports")
                    connection_path = str(connection.get("path") or "")
                    if any(token in connection_path.lower() for token in ("vpn", "tun", "utun")):
                        _bounded_add(tunnels, connection_path, "tunnels")
            if event_type.startswith("network.dns") and isinstance(payload, dict):
                value = payload.get("value")
                for resolver in value if isinstance(value, list) else []:
                    if isinstance(resolver, dict):
                        nameservers = resolver.get("nameservers", [])
                        for server in nameservers if isinstance(nameservers, list) else []:
                            _bounded_add(resolvers, server, "resolvers")
            if event_type.startswith("network.routes") and isinstance(payload, dict):
                value = payload.get("value")
                for route in value if isinstance(value, list) else []:
                    if isinstance(route, dict):
                        _bounded_add(
                            routes,
                            "|".join(
                                str(route.get(key) or "")
                                for key in ("destination", "gateway", "interface")
                            ),
                            "routes",
                        )
            if event_type.startswith("network.interfaces") and isinstance(payload, dict):
                value = payload.get("value")
                for interface in value if isinstance(value, list) else []:
                    if isinstance(interface, dict):
                        name = interface.get("name") or interface.get("interface") or interface.get("device")
                        if name:
                            _bounded_add(interfaces, name, "interfaces")
            request = _request_payload(event_type, payload)
            if request is None:
                continue
            request_count += 1
            transfer = _numeric(request.get("transfer_bytes"))
            if transfer is not None:
                if transfer < 0:
                    raise BaselineError("request transfer_bytes must not be negative")
                transfer_values.append(transfer)
                transfer_observed += 1
            request_duration = _numeric(request.get("duration_ms"))
            if request_duration is not None:
                if request_duration < 0:
                    raise BaselineError("request duration_ms must not be negative")
                duration_values.append(request_duration)
            timing = request.get("timing")
            if isinstance(timing, dict):
                ttfb = _numeric(timing.get("ttfb_ms"))
                if ttfb is not None:
                    if ttfb < 0:
                        raise BaselineError("request ttfb_ms must not be negative")
                    ttfb_values.append(ttfb)
            status = _numeric(request.get("status"))
            failed_value = request.get("failed")
            if isinstance(failed_value, bool) or status is not None:
                failure_observed += 1
                failures += int(failed_value is True or (status is not None and status >= 400))
            protocol = request.get("protocol")
            if protocol:
                _bounded_add(protocols, protocol, "protocols")
            remote_port = request.get("remote_port")
            if remote_port not in (None, ""):
                _bounded_add(ports, remote_port, "ports")

        domains: Set[str] = set()
        for row in store.connection.execute(
            "SELECT entity_key FROM entities WHERE session_id=? AND entity_type='domain' ORDER BY entity_key",
            (active,),
        ):
            _bounded_add(domains, row[0], "domains")
        listener_count = 0
        for row in store.connection.execute(
            "SELECT attributes_json FROM entities WHERE session_id=? AND entity_type='connection'",
            (active,),
        ):
            attributes = _strict_stored_object(row[0], "entity attributes")
            if str(attributes.get("state") or "").upper() in ("LISTEN", "LISTENING"):
                listener_count += 1
        finding_counts = Counter(
            str(row[0])
            for row in store.connection.execute(
                "SELECT severity FROM findings WHERE session_id=? ORDER BY severity", (active,)
            )
        )
        relation_values = []
        for row in store.connection.execute(
            "SELECT relation_type, source_id, target_id FROM relations WHERE session_id=? ORDER BY relation_type, source_id, target_id",
            (active,),
        ):
            relation_values.append(
                (
                    str(row["relation_type"]),
                    str(row["source_id"]),
                    str(row["target_id"]),
                )
            )
            if len(relation_values) > MAX_SET_VALUES:
                raise BaselineError(
                    f"session relations exceeds the {MAX_SET_VALUES}-value baseline limit"
                )
        relation_types = {item[0] for item in relation_values}
        applied_row = store.connection.execute(
            "SELECT value_json FROM metadata WHERE key=?",
            (f"rule_pack_versions:{active}",),
        ).fetchone()
        if applied_row is not None:
            applied_versions = _strict_stored_json(
                applied_row["value_json"], "rule-pack analysis metadata"
            )
            if (
                not isinstance(applied_versions, list)
                or len(applied_versions) > MAX_RULE_PACK_VERSIONS
                or not all(
                    isinstance(item, str)
                    and item.count("@") == 1
                    and all(item_part for item_part in item.split("@", 1))
                    for item in applied_versions
                )
                or len(applied_versions) != len(set(applied_versions))
            ):
                raise BaselineError("rule-pack analysis metadata must be a unique string array")
            pack_versions = sorted(applied_versions)
        elif store.schema_version >= 2:
            pack_versions = sorted(
                {
                    f"{row[0]}@{row[1]}"
                    for row in store.connection.execute(
                        """SELECT pack_id, pack_version FROM findings
                           WHERE session_id=? AND pack_id IS NOT NULL AND pack_id <> ''
                             AND pack_version IS NOT NULL AND pack_version <> ''
                           ORDER BY pack_id, pack_version""",
                        (active,),
                    )
                }
            )
        else:
            pack_versions = []
        config = session.get("config")
        if not isinstance(config, dict):
            raise BaselineError("session config must be a JSON object")
        capabilities = config.get("capabilities", {})
        if not isinstance(capabilities, dict):
            raise BaselineError("session capabilities must be a JSON object")
        capability_signature = hashlib.sha256(_canonical(capabilities).encode()).hexdigest()
        finding_count = int(
            store.connection.execute("SELECT COUNT(*) FROM findings WHERE session_id=?", (active,)).fetchone()[0]
        )
        metrics: Dict[str, Optional[float]] = {
            "session_duration_ms": round(duration_ms, 6) if duration_ms is not None else None,
            "event_count": float(event_count),
            "request_count": float(request_count),
            "transfer_bytes": sum(transfer_values) if transfer_observed == request_count else (0.0 if request_count == 0 else None),
            "failure_count": float(failures) if failure_observed == request_count else (0.0 if request_count == 0 else None),
            "connection_churn": float(churn),
            "listener_count": float(listener_count),
            "finding_count": float(finding_count),
            "critical_finding_count": float(finding_counts.get("critical", 0)),
            "error_finding_count": float(finding_counts.get("error", 0)),
            "request_duration_p90_ms": _percentile(duration_values, 0.90) if len(duration_values) == request_count and request_count else None,
            "ttfb_p90_ms": _percentile(ttfb_values, 0.90) if len(ttfb_values) == request_count and request_count else None,
        }
        snapshot = {
            "fingerprint": fingerprint,
            "schema_version": store.schema_version,
            "session_id": session["id"],
            "capability_profile": capabilities,
            "capability_signature": capability_signature,
            "rule_pack_versions": pack_versions,
            "metrics": metrics,
            "sets": {
                "domains": sorted(domains),
                "protocols": sorted(protocols),
                "ports": sorted(ports),
                "resolvers": sorted(resolvers),
                "routes": sorted(routes),
                "tunnels": sorted(tunnels),
                "interfaces": sorted(interfaces),
                "relation_types": sorted(relation_types),
                "relations": ["|".join(item) for item in relation_values],
            },
        }
    _require_stable_session_file(source)
    fingerprint_after = _file_fingerprint(source)
    _require_stable_session_file(source)
    if fingerprint_after != fingerprint:
        raise BaselineError(f"session changed while its baseline snapshot was being read: {path}")
    return snapshot


def _set_stats(snapshots: Sequence[Dict[str, Any]], name: str) -> Dict[str, Any]:
    values = [set(snapshot["sets"].get(name, [])) for snapshot in snapshots]
    union = set().union(*values) if values else set()
    intersection = set.intersection(*values) if values else set()
    frequency = Counter(item for sample in values for item in sample)
    return {
        "observed": sorted(union),
        "stable": sorted(intersection),
        "frequency": {key: frequency[key] for key in sorted(frequency)},
    }


def build_baseline(
    sessions: Sequence[str],
    output: Optional[str] = None,
    *,
    allow_single: bool = False,
    absolute_budgets: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    if isinstance(sessions, (str, bytes)) or not isinstance(sessions, Sequence) or not all(
        isinstance(item, str) and item for item in sessions
    ):
        raise BaselineError("baseline sessions must be an array of non-empty paths")
    if not sessions:
        raise BaselineError("baseline build requires at least one session")
    if len(sessions) > MAX_BASELINE_SAMPLES:
        raise BaselineError(f"baseline supports at most {MAX_BASELINE_SAMPLES} sessions")
    if len(sessions) < 3 and not (allow_single and len(sessions) == 1):
        raise BaselineError("statistical baseline requires at least three sessions; use --single-run for one sample")
    if allow_single and len(sessions) != 1:
        raise BaselineError("--single-run is valid only with exactly one session")
    if allow_single and not absolute_budgets:
        raise BaselineError("single-run baseline requires at least one absolute budget")
    if not allow_single and absolute_budgets:
        raise BaselineError("absolute budgets are supported only for a single-run baseline")
    if absolute_budgets is not None and not isinstance(absolute_budgets, dict):
        raise BaselineError("absolute budgets must be an object")
    for name, limit in (absolute_budgets or {}).items():
        if not isinstance(name, str) or not name:
            raise BaselineError("absolute budget metric names must be non-empty strings")
        if _numeric(limit) is None or float(limit) < 0:
            raise BaselineError(f"absolute budget for {name} must be a finite non-negative number")
    snapshots = sorted((session_snapshot(path) for path in sessions), key=lambda item: item["fingerprint"])
    fingerprints = [item["fingerprint"] for item in snapshots]
    if len(set(fingerprints)) != len(fingerprints):
        raise BaselineError("baseline inputs must be distinct session artifacts")
    capability_signatures = {item["capability_signature"] for item in snapshots}
    if len(capability_signatures) != 1:
        raise BaselineError("baseline sessions must use the same capability profile")
    schema_profiles = {item["schema_version"] for item in snapshots}
    if len(schema_profiles) != 1:
        raise BaselineError("baseline sessions must use the same session schema version")
    rule_profiles = {_canonical(item["rule_pack_versions"]) for item in snapshots}
    if len(rule_profiles) != 1:
        raise BaselineError("baseline sessions must use the same rule-pack versions")
    metric_names = sorted({key for snapshot in snapshots for key in snapshot["metrics"]})
    metrics = {}
    for name in metric_names:
        values = [
            float(value)
            for snapshot in snapshots
            for value in [snapshot["metrics"].get(name)]
            if value is not None
        ]
        if values:
            metrics[name] = _metric_stats(values, len(snapshots))
        else:
            metrics[name] = {
                "median": None,
                "p90": None,
                "mad": None,
                "sample_count": 0,
                "missing_count": len(snapshots),
                "minimum": None,
                "maximum": None,
            }
    set_names = sorted({key for snapshot in snapshots for key in snapshot["sets"]})
    unknown_budgets = set(absolute_budgets or {}) - set(metric_names)
    if unknown_budgets:
        raise BaselineError(f"absolute budgets reference unknown metrics: {', '.join(sorted(unknown_budgets))}")
    capability_profiles = {
        snapshot["capability_signature"]: snapshot["capability_profile"]
        for snapshot in snapshots
    }
    baseline = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "kind": "wirescope-baseline",
        "mode": "single-run" if len(snapshots) == 1 else "statistical",
        "sample_count": len(snapshots),
        "source_fingerprints": fingerprints,
        "session_schema_versions": sorted({snapshot["schema_version"] for snapshot in snapshots}),
        "rule_pack_versions": sorted(
            {version for snapshot in snapshots for version in snapshot["rule_pack_versions"]}
        ),
        "capability_profiles": [
            {"signature": signature, "profile": capability_profiles[signature]}
            for signature in sorted(capability_profiles)
        ],
        "metrics": metrics,
        "sets": {name: _set_stats(snapshots, name) for name in set_names},
        "absolute_budgets": {
            key: float(value) for key, value in sorted((absolute_budgets or {}).items())
        },
        "comparison_defaults": {
            "relative_threshold": DEFAULT_RELATIVE_THRESHOLD,
            "mad_multiplier": DEFAULT_MAD_MULTIPLIER,
        },
    }
    validate_baseline(baseline)
    if output:
        atomic_write_text(output, json.dumps(baseline, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return baseline


def validate_baseline(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise BaselineError("baseline must be a JSON object")
    try:
        encoded_size = len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError) as exc:
        raise BaselineError(f"baseline must contain finite JSON data: {exc}") from exc
    if encoded_size > MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline exceeds {MAX_BASELINE_BYTES} bytes")
    required = {
        "schema_version",
        "kind",
        "mode",
        "sample_count",
        "source_fingerprints",
        "session_schema_versions",
        "rule_pack_versions",
        "capability_profiles",
        "metrics",
        "sets",
        "absolute_budgets",
        "comparison_defaults",
    }
    missing = required - set(value)
    unknown = set(value) - required
    if missing:
        raise BaselineError(f"baseline is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise BaselineError(f"baseline has unknown fields: {', '.join(sorted(unknown))}")
    if (
        not isinstance(value["schema_version"], int)
        or isinstance(value["schema_version"], bool)
        or value["schema_version"] != BASELINE_SCHEMA_VERSION
        or value["kind"] != "wirescope-baseline"
    ):
        raise BaselineError("unsupported baseline schema or kind")
    if value["mode"] not in ("statistical", "single-run"):
        raise BaselineError("baseline mode must be statistical or single-run")
    sample_count = value["sample_count"]
    if not isinstance(sample_count, int) or isinstance(sample_count, bool) or not 1 <= sample_count <= MAX_BASELINE_SAMPLES:
        raise BaselineError(f"baseline sample_count must be between 1 and {MAX_BASELINE_SAMPLES}")
    if value["mode"] == "statistical" and sample_count < 3:
        raise BaselineError("statistical baseline requires at least three samples")
    if value["mode"] == "single-run" and sample_count != 1:
        raise BaselineError("single-run baseline must contain exactly one sample")
    fingerprints = value["source_fingerprints"]
    if (
        not isinstance(fingerprints, list)
        or len(fingerprints) != sample_count
        or not all(isinstance(item, str) and len(item) == 64 and all(char in "0123456789abcdef" for char in item) for item in fingerprints)
        or len(set(fingerprints)) != len(fingerprints)
        or fingerprints != sorted(fingerprints)
    ):
        raise BaselineError("baseline source_fingerprints must contain one unique lowercase SHA-256 per sample")
    schemas = value["session_schema_versions"]
    if not isinstance(schemas, list) or len(schemas) != 1 or not all(isinstance(item, int) and not isinstance(item, bool) and item >= 1 for item in schemas):
        raise BaselineError("baseline must contain exactly one positive session schema version")
    packs = value["rule_pack_versions"]
    if (
        not isinstance(packs, list)
        or len(packs) > MAX_RULE_PACK_VERSIONS
        or not all(
            isinstance(item, str)
            and item.count("@") == 1
            and all(part for part in item.split("@", 1))
            for item in packs
        )
        or len(packs) != len(set(packs))
        or packs != sorted(packs)
    ):
        raise BaselineError("baseline rule_pack_versions must be a unique string array")
    capability_profiles = value["capability_profiles"]
    if not isinstance(capability_profiles, list) or len(capability_profiles) != 1:
        raise BaselineError("baseline must contain exactly one capability profile")
    capability = capability_profiles[0]
    if (
        not isinstance(capability, dict)
        or set(capability) != {"signature", "profile"}
        or not isinstance(capability.get("profile"), dict)
        or not isinstance(capability.get("signature"), str)
        or len(capability["signature"]) != 64
        or any(char not in "0123456789abcdef" for char in capability["signature"])
    ):
        raise BaselineError("baseline capability profile is invalid")
    expected_signature = hashlib.sha256(_canonical(capability["profile"]).encode()).hexdigest()
    if capability["signature"] != expected_signature:
        raise BaselineError("baseline capability profile signature does not match its content")
    if not isinstance(value["metrics"], dict) or set(value["metrics"]) != BASELINE_METRIC_NAMES:
        raise BaselineError("baseline metrics do not match schema version 1")
    if not isinstance(value["sets"], dict) or set(value["sets"]) != BASELINE_SET_NAMES:
        raise BaselineError("baseline sets do not match schema version 1")
    stat_fields = {"median", "p90", "mad", "sample_count", "missing_count", "minimum", "maximum"}
    for name, stats in value["metrics"].items():
        if not isinstance(name, str) or not name or not isinstance(stats, dict) or set(stats) != stat_fields:
            raise BaselineError(f"baseline metric {name!r} has an invalid shape")
        present = stats["sample_count"]
        missing_count = stats["missing_count"]
        if (
            not isinstance(present, int)
            or isinstance(present, bool)
            or not isinstance(missing_count, int)
            or isinstance(missing_count, bool)
            or present < 0
            or missing_count < 0
            or present + missing_count != sample_count
        ):
            raise BaselineError(f"baseline metric {name} has invalid sample coverage")
        numeric_fields = ("median", "p90", "mad", "minimum", "maximum")
        if present == 0:
            if any(stats[field] is not None for field in numeric_fields):
                raise BaselineError(f"baseline metric {name} has values without samples")
        else:
            median = _numeric(stats["median"])
            p90 = _numeric(stats["p90"])
            mad = _numeric(stats["mad"])
            minimum = _numeric(stats["minimum"])
            maximum = _numeric(stats["maximum"])
            if median is None or p90 is None or mad is None or minimum is None or maximum is None:
                raise BaselineError(f"baseline metric {name} must contain finite statistics")
            if minimum < 0 or mad < 0:
                raise BaselineError(f"baseline metric {name} contains negative statistics")
            if not minimum <= median <= p90 <= maximum:
                raise BaselineError(f"baseline metric {name} statistics are not ordered")
    set_fields = {"observed", "stable", "frequency"}
    for name, stats in value["sets"].items():
        if not isinstance(name, str) or not name or not isinstance(stats, dict) or set(stats) != set_fields:
            raise BaselineError(f"baseline set {name!r} has an invalid shape")
        observed = stats["observed"]
        stable = stats["stable"]
        frequency = stats["frequency"]
        if (
            not isinstance(observed, list)
            or len(observed) > MAX_SET_VALUES
            or not all(isinstance(item, str) for item in observed)
            or len(observed) != len(set(observed))
            or observed != sorted(observed)
            or not isinstance(stable, list)
            or not all(isinstance(item, str) for item in stable)
            or len(stable) != len(set(stable))
            or stable != sorted(stable)
            or not set(stable).issubset(observed)
            or not isinstance(frequency, dict)
            or set(frequency) != set(observed)
            or not all(isinstance(count, int) and not isinstance(count, bool) and 1 <= count <= sample_count for count in frequency.values())
            or set(stable) != {item for item, count in frequency.items() if count == sample_count}
        ):
            raise BaselineError(f"baseline set {name} has invalid values or frequencies")
    if not isinstance(value["absolute_budgets"], dict) or not all(
        isinstance(metric, str)
        and metric in value["metrics"]
        and _numeric(limit) is not None
        and float(limit) >= 0
        for metric, limit in value["absolute_budgets"].items()
    ):
        raise BaselineError("baseline absolute_budgets must contain non-negative numbers")
    if value["mode"] == "single-run" and not value["absolute_budgets"]:
        raise BaselineError("single-run baseline must contain absolute budgets")
    if value["mode"] == "statistical" and value["absolute_budgets"]:
        raise BaselineError("statistical baselines must not contain ignored absolute budgets")
    defaults = value["comparison_defaults"]
    if not isinstance(defaults, dict) or set(defaults) != {"relative_threshold", "mad_multiplier"}:
        raise BaselineError("baseline comparison_defaults has an invalid shape")
    if any(_numeric(defaults[key]) is None or float(defaults[key]) < 0 for key in defaults):
        raise BaselineError("baseline comparison defaults must be finite non-negative numbers")
    return value


def load_baseline(path: str) -> Dict[str, Any]:
    source = Path(path)
    try:
        size = source.stat().st_size
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline does not exist: {path}") from exc
    except OSError as exc:
        raise BaselineError(f"cannot inspect baseline: {path}: {exc}") from exc
    if size > MAX_BASELINE_BYTES:
        raise BaselineError(f"baseline exceeds {MAX_BASELINE_BYTES} bytes")
    try:
        value = json.loads(
            source.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise BaselineError(f"invalid baseline JSON at line {exc.lineno}: {exc.msg}") from exc
    except RecursionError as exc:
        raise BaselineError("baseline JSON nesting is too deep") from exc
    except OSError as exc:
        raise BaselineError(f"cannot read baseline: {path}: {exc}") from exc
    return validate_baseline(value)


def compare_baseline(
    baseline: Dict[str, Any],
    session: str,
    *,
    relative_threshold: Optional[float] = None,
    mad_multiplier: Optional[float] = None,
) -> Dict[str, Any]:
    baseline = validate_baseline(baseline)
    current = session_snapshot(session)
    defaults = baseline["comparison_defaults"]
    try:
        relative = float(defaults["relative_threshold"] if relative_threshold is None else relative_threshold)
        mad_factor = float(defaults["mad_multiplier"] if mad_multiplier is None else mad_multiplier)
    except (TypeError, ValueError) as exc:
        raise BaselineError("comparison thresholds must be numeric") from exc
    if not math.isfinite(relative) or not math.isfinite(mad_factor) or relative < 0 or mad_factor < 0:
        raise BaselineError("comparison thresholds must be finite and non-negative")
    known_capabilities = {item["signature"] for item in baseline["capability_profiles"]}
    capability_compatible = current["capability_signature"] in known_capabilities
    schema_compatible = current["schema_version"] in baseline["session_schema_versions"]
    rule_packs_compatible = current["rule_pack_versions"] == baseline["rule_pack_versions"]
    metric_results = []
    metric_names = (
        sorted(baseline["absolute_budgets"])
        if baseline["mode"] == "single-run"
        else sorted(baseline["metrics"])
    )
    for name in metric_names:
        stats = baseline["metrics"][name]
        actual = current["metrics"].get(name)
        median = stats.get("median")
        p90 = stats.get("p90")
        mad = stats.get("mad")
        if baseline["mode"] == "single-run":
            limit = baseline["absolute_budgets"].get(name)
            if actual is None or limit is None:
                metric_results.append(
                    {
                        "metric": name,
                        "status": "unknown",
                        "actual": actual,
                        "reason": (
                            "metric is missing from the current session"
                            if actual is None
                            else "single-run baselines require an explicit absolute budget for this metric"
                        ),
                    }
                )
            else:
                regression = float(actual) > float(limit)
                metric_results.append(
                    {
                        "metric": name,
                        "status": "regression" if regression else "stable",
                        "actual": actual,
                        "absolute_limit": float(limit),
                        "formula": "actual <= absolute_limit",
                    }
                )
            continue
        if int(stats.get("sample_count", 0)) != int(baseline["sample_count"]):
            metric_results.append(
                {
                    "metric": name,
                    "status": "unknown",
                    "actual": actual,
                    "reason": "metric coverage is incomplete across baseline samples",
                    "baseline": stats,
                }
            )
            continue
        if actual is None or median is None or p90 is None or mad is None:
            metric_results.append(
                {
                    "metric": name,
                    "status": "unknown",
                    "actual": actual,
                    "reason": "metric is missing from the baseline or current session",
                }
            )
            continue
        variability_upper = max(float(p90), float(median) + mad_factor * float(mad))
        relative_upper = float(median) * (1.0 + relative)
        if not math.isfinite(variability_upper) or not math.isfinite(relative_upper):
            raise BaselineError("comparison thresholds overflow the supported numeric range")
        regression = float(actual) > variability_upper and float(actual) > relative_upper
        metric_results.append(
            {
                "metric": name,
                "status": "regression" if regression else "stable",
                "actual": actual,
                "baseline": stats,
                "variability_upper": round(variability_upper, 6),
                "relative_upper": round(relative_upper, 6),
                "relative_threshold": relative,
                "mad_multiplier": mad_factor,
                "formula": "actual > max(p90, median + mad_multiplier*MAD) AND actual > median*(1+relative_threshold)",
            }
        )
    set_changes = {}
    for name in sorted(baseline["sets"]):
        expected = set(baseline["sets"][name].get("observed", []))
        stable = set(baseline["sets"][name].get("stable", []))
        actual = set(current["sets"].get(name, []))
        set_changes[name] = {
            "new": sorted(actual - expected),
            "missing_stable": sorted(stable - actual),
            "unchanged": sorted(actual & expected),
            "policy_effect": "change-only",
        }
    regressions = [item for item in metric_results if item["status"] == "regression"]
    unknown = [item for item in metric_results if item["status"] == "unknown"]
    if not capability_compatible or not schema_compatible or not rule_packs_compatible:
        state = "incompatible"
    elif regressions:
        state = "regression"
    elif unknown:
        state = "unknown"
    else:
        state = "pass"
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "kind": "wirescope-baseline-comparison",
        "state": state,
        "passed": state == "pass",
        "baseline": {
            "mode": baseline["mode"],
            "sample_count": baseline["sample_count"],
            "source_fingerprints": baseline["source_fingerprints"],
        },
        "current": {
            "fingerprint": current["fingerprint"],
            "session_id": current["session_id"],
            "schema_version": current["schema_version"],
        },
        "capability": {
            "compatible": capability_compatible,
            "current_signature": current["capability_signature"],
            "baseline_signatures": sorted(known_capabilities),
        },
        "compatibility": {
            "compatible": capability_compatible and schema_compatible and rule_packs_compatible,
            "capabilities": capability_compatible,
            "session_schema": schema_compatible,
            "rule_packs": rule_packs_compatible,
            "current_rule_packs": current["rule_pack_versions"],
            "baseline_rule_packs": baseline["rule_pack_versions"],
        },
        "metrics": metric_results,
        "changes": set_changes,
        "summary": {
            "regressions": len(regressions),
            "unknown_metrics": len(unknown),
            "new_domains": len(set_changes.get("domains", {}).get("new", [])),
            "new_routes": len(set_changes.get("routes", {}).get("new", [])),
        },
    }


def compare_sessions(before: str, after: str) -> Dict[str, Any]:
    before_snapshot = session_snapshot(before)
    after_snapshot = session_snapshot(after)
    metrics = {}
    for name in sorted(set(before_snapshot["metrics"]) | set(after_snapshot["metrics"])):
        first = before_snapshot["metrics"].get(name)
        second = after_snapshot["metrics"].get(name)
        metrics[name] = {
            "before": first,
            "after": second,
            "delta": second - first if first is not None and second is not None else None,
            "status": "known" if first is not None and second is not None else "unknown",
        }
    changes = {}
    for name in sorted(set(before_snapshot["sets"]) | set(after_snapshot["sets"])):
        first = set(before_snapshot["sets"].get(name, []))
        second = set(after_snapshot["sets"].get(name, []))
        changes[name] = {"added": sorted(second - first), "removed": sorted(first - second)}
    return {
        "schema_version": COMPARISON_SCHEMA_VERSION,
        "kind": "wirescope-session-comparison",
        "before": {"fingerprint": before_snapshot["fingerprint"], "session_id": before_snapshot["session_id"]},
        "after": {"fingerprint": after_snapshot["fingerprint"], "session_id": after_snapshot["session_id"]},
        "metrics": metrics,
        "changes": changes,
    }


def write_comparison_report(result: Dict[str, Any], output: str) -> None:
    destination = Path(output)
    if destination.suffix.lower() == ".html":
        payload = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
        document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>WireScope Baseline Comparison</title>
<style>body{{font:15px system-ui;margin:2rem;max-width:1100px}}pre{{white-space:pre-wrap;background:#111;color:#eee;padding:1rem;border-radius:8px}}</style>
</head><body><h1>WireScope Baseline Comparison</h1><p>State: <strong>{html.escape(str(result.get('state', 'comparison')))}</strong></p>
<pre>{html.escape(payload)}</pre></body></html>"""
        atomic_write_text(destination, document)
    else:
        atomic_write_text(destination, json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
