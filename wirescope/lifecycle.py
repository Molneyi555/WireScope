from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import struct
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .artifacts import (
    PRIVATE_FILE_MODE,
    ArtifactSecurityError,
    atomic_text_writer,
    atomic_write_text,
    verify_private_artifact,
)
from .redact import RedactionRules
from .session import (
    SESSION_SCHEMA_VERSION,
    SessionError,
    SessionStore,
    _hash_file,
    _inspect_session_path,
    _json,
    _open_regular_binary,
    verify_session,
)
from .session_report import build_session_report_data, generate_session_html


SUPPORT_BUNDLE_SCHEMA_VERSION = 1
EXPORT_SCHEMA_VERSION = 1
MAX_TAGS_PER_SESSION = 100
MAX_TAG_LENGTH = 128
MAX_TAG_METADATA_BYTES = 32 * 1024
MAX_MERGE_METADATA_BYTES = 64 * 1024
MAX_MERGE_PACK_VERSIONS = 1000
MAX_MERGE_SOURCES = 32
MAX_MERGE_ROWS = 250_000
MAX_MERGE_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CLOCK_OFFSET_MS = 7 * 24 * 60 * 60 * 1000
MAX_PRUNE_ROWS = 500_000
MAX_PRUNE_EVIDENCE_BYTES = 128 * 1024 * 1024
MAX_PRUNE_EVIDENCE_NODES = 1_000_000
MAX_BUNDLE_ENTRIES = 64
MAX_BUNDLE_MANIFEST_BYTES = 1024 * 1024
MAX_BUNDLE_POLICY_BYTES = 64 * 1024
MAX_BUNDLE_ENTRY_BYTES = 512 * 1024 * 1024
MAX_BUNDLE_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_GENERATED_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_SESSION_BYTES = 64 * 1024 * 1024
MAX_BUNDLE_CAPABILITY_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_CENTRAL_DIRECTORY_BYTES = 4 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 200
ZIP_RATIO_EXEMPT_BYTES = 1024 * 1024


def _destination_must_be_new(path: Path, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode):
        raise ArtifactSecurityError(f"refusing symlink {label} destination: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ArtifactSecurityError(f"{label} destination is not a regular file: {path}")
    raise SessionError(f"{label} destination already exists: {path}")


def _sqlite_family(path: Path) -> Tuple[Path, ...]:
    return (
        path,
        Path(f"{path}-wal"),
        Path(f"{path}-shm"),
        Path(f"{path}-journal"),
    )


def _paths_refer_to_same_file(first: Path, second: Path) -> bool:
    if os.path.normcase(os.path.abspath(str(first))) == os.path.normcase(
        os.path.abspath(str(second))
    ):
        return True
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _reject_sqlite_family_collision(source: Path, output: Path, label: str) -> None:
    if any(_paths_refer_to_same_file(member, output) for member in _sqlite_family(source)):
        raise SessionError(f"{label} output cannot replace a SQLite source or sidecar: {output}")


def _require_absent_paths(paths: Sequence[Path], label: str) -> None:
    for path in paths:
        try:
            os.lstat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SessionError(f"cannot inspect {label} companion: {path}: {exc}") from exc
        raise SessionError(f"{label} companion already exists: {path}")


def _publish_new_private_file(
    temporary: Path,
    destination: Path,
    label: str,
    *,
    forbidden_companions: Sequence[Path] = (),
) -> None:
    verify_private_artifact(temporary, repair_mode=False)
    temporary_info = os.lstat(temporary)
    expected_digest, expected_size = _hash_file(temporary)
    published_identity: Optional[Tuple[int, int]] = None
    _require_absent_paths(forbidden_companions, label)
    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise SessionError(f"{label} destination appeared during publication: {destination}") from exc
    except OSError as exc:
        raise SessionError(f"cannot publish {label} atomically: {destination}: {exc}") from exc
    try:
        with _open_regular_binary(destination) as published:
            destination_info = os.fstat(published.fileno())
            published_identity = (destination_info.st_dev, destination_info.st_ino)
            if published_identity != (temporary_info.st_dev, temporary_info.st_ino):
                raise ArtifactSecurityError(
                    f"{label} destination changed during publication: {destination}"
                )
            if stat.S_IMODE(destination_info.st_mode) != PRIVATE_FILE_MODE:
                raise ArtifactSecurityError(
                    f"{label} destination permissions are not owner-only: {destination}"
                )
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: published.read(1024 * 1024), b""):
                size += len(chunk)
                digest.update(chunk)
            if size != expected_size or digest.hexdigest() != expected_digest:
                raise ArtifactSecurityError(
                    f"{label} destination content changed during publication: {destination}"
                )
            _require_absent_paths(forbidden_companions, label)
    except Exception:
        try:
            current = os.lstat(destination)
            if (
                current.st_dev,
                current.st_ino,
            ) == (temporary_info.st_dev, temporary_info.st_ino):
                destination.unlink()
        except FileNotFoundError:
            pass
        raise
    temporary.unlink()


def _parse_timestamp(value: Any, label: str, *, allow_none: bool = False) -> Optional[datetime]:
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not value:
        raise SessionError(f"{label} must be a non-empty ISO 8601 timestamp")
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise SessionError(f"invalid {label}: {value!r}") from exc


def _shift_timestamp(value: Any, offset_ms: float, label: str = "timestamp") -> Any:
    if value is None:
        return value
    try:
        parsed = _parse_timestamp(value, label)
        if offset_ms == 0:
            return value
        assert parsed is not None
        shifted = parsed + timedelta(milliseconds=offset_ms)
        return shifted.isoformat(timespec="milliseconds")
    except (OverflowError, ValueError) as exc:
        raise SessionError(f"timestamp shift is outside the supported range: {value!r}") from exc


def _require_timestamp_order(first: Any, last: Any, label: str) -> None:
    first_value = _parse_timestamp(first, f"{label} start timestamp")
    last_value = _parse_timestamp(last, f"{label} end timestamp", allow_none=True)
    if last_value is not None and first_value is not None and last_value < first_value:
        raise SessionError(f"{label} end timestamp precedes its start timestamp")


def _normalize_tags(tags: Any, *, require_nonempty: bool) -> List[str]:
    if isinstance(tags, (str, bytes)) or not isinstance(tags, Sequence):
        raise SessionError("tags must be an array of strings")
    if len(tags) > MAX_TAGS_PER_SESSION:
        raise SessionError(f"a session accepts at most {MAX_TAGS_PER_SESSION} tags")
    normalized = []
    for tag in tags:
        if not isinstance(tag, str):
            raise SessionError("tags must contain only strings")
        value = tag.strip()
        if not value:
            continue
        if len(value) > MAX_TAG_LENGTH:
            raise SessionError(f"tags must not exceed {MAX_TAG_LENGTH} characters")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise SessionError("tags must not contain control characters")
        normalized.append(value)
    result = sorted(set(normalized))
    if require_nonempty and not result:
        raise SessionError("at least one non-empty tag is required")
    return result


def _strict_json_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SessionError(f"stored JSON contains duplicate field: {key}")
        result[key] = value
    return result


def _strict_json_constant(value: str) -> Any:
    raise SessionError(f"stored JSON contains invalid numeric constant: {value}")


def _strict_json(raw: Any, label: str) -> Any:
    if not isinstance(raw, str):
        raise SessionError(f"{label} is not stored as JSON text")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_pairs,
            parse_constant=_strict_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise SessionError(f"{label} contains invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise SessionError(f"{label} JSON nesting is too deep") from exc
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, float) and not math.isfinite(item):
            raise SessionError(f"{label} contains a non-finite JSON number")
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return value


def _stored_tags(store: SessionStore, key: str) -> List[str]:
    row = store.connection.execute(
        "SELECT value_json, LENGTH(value_json) AS value_size FROM metadata WHERE key=?", (key,)
    ).fetchone()
    if row is None:
        return []
    if int(row["value_size"] or 0) > MAX_TAG_METADATA_BYTES:
        raise SessionError("stored session tags exceed the metadata size limit")
    return _normalize_tags(_strict_json(row["value_json"], "stored session tags"), require_nonempty=False)


def _require_stable_session_source(path: Path, operation: str) -> int:
    total_size = int(_inspect_session_path(path).st_size)
    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{path}{suffix}")
        try:
            info = os.lstat(companion)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ArtifactSecurityError(f"invalid SQLite sidecar for {operation}: {companion}")
        if suffix != "-shm" and info.st_size:
            raise SessionError(
                f"{operation} source has an active SQLite {suffix[1:]} sidecar; close/checkpoint it first: {path}"
            )
        total_size += int(info.st_size)
    return total_size


def _existing_session_id(store: SessionStore, session_id: Optional[str]) -> str:
    active = store._require_session_id(session_id)
    if store.connection.execute("SELECT 1 FROM sessions WHERE id=?", (active,)).fetchone() is None:
        raise SessionError(f"session not found: {active}")
    return active


def tag_session(session: str, tags: Sequence[str], *, session_id: Optional[str] = None) -> Dict[str, Any]:
    normalized = _normalize_tags(tags, require_nonempty=True)
    with SessionStore(session) as store:
        store.connection.execute("BEGIN IMMEDIATE")
        active = _existing_session_id(store, session_id)
        key = f"session_tags:{active}"
        existing_tags = _stored_tags(store, key)
        combined = sorted(set(existing_tags) | set(normalized))
        if len(combined) > MAX_TAGS_PER_SESSION:
            raise SessionError(f"a session accepts at most {MAX_TAGS_PER_SESSION} tags")
        store.set_metadata(key, combined)
        store.commit()
        return {"session": session, "session_id": active, "tags": combined}


def session_tags(session: str, *, session_id: Optional[str] = None) -> Dict[str, Any]:
    with SessionStore(session, read_only=True) as store:
        active = _existing_session_id(store, session_id)
        tags = _stored_tags(store, f"session_tags:{active}")
        return {"session": session, "session_id": active, "tags": tags}


def _source_rows(path: Path, offset_ms: float, max_rows: int) -> Dict[str, Any]:
    _require_stable_session_source(path, "merge")
    with SessionStore(str(path), read_only=True) as store:
        store.connection.execute("BEGIN")
        _require_stable_session_source(path, "merge")
        digest, size = _hash_file(path)
        _require_stable_session_source(path, "merge")
        if store.schema_version != SESSION_SCHEMA_VERSION:
            raise SessionError(
                f"merge requires schema {SESSION_SCHEMA_VERSION}; migrate {path} before merging"
            )
        order_by = {
            "sessions": "id",
            "artifacts": "id",
            "entities": "id",
            "relations": "id",
            "events": "sequence",
            "findings": "id",
        }
        counts = {
            table: int(store.connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
            for table in order_by
        }
        row_count = sum(counts.values())
        if row_count > max_rows:
            raise SessionError(f"merge sources exceed the {MAX_MERGE_ROWS}-row limit")
        tables = {
            table: [
                dict(row)
                for row in store.connection.execute(
                    f'SELECT * FROM "{table}" ORDER BY {order_by[table]}'
                )
            ]
            for table in order_by
        }
        metadata = {}
        for row in store.connection.execute(
            """SELECT key, value_json, LENGTH(CAST(value_json AS BLOB)) AS value_size
               FROM metadata
               WHERE substr(key, 1, 13) = 'session_tags:'
                  OR substr(key, 1, 19) = 'rule_pack_versions:'
               ORDER BY key"""
        ):
            if int(row["value_size"] or 0) > MAX_MERGE_METADATA_BYTES:
                raise SessionError("merge source session metadata exceeds the size limit")
            key = str(row["key"])
            metadata[key] = _strict_json(row["value_json"], "merge source session metadata")
        if len(metadata) > len(tables["sessions"]) * 2:
            raise SessionError("merge source contains excess per-session metadata")
        session_ids = {str(item["id"]) for item in tables["sessions"]}
        for key, values in list(metadata.items()):
            if key.startswith("session_tags:"):
                session_key = key[len("session_tags:") :]
                metadata[key] = _normalize_tags(values, require_nonempty=False)
            elif key.startswith("rule_pack_versions:"):
                session_key = key[len("rule_pack_versions:") :]
                if (
                    not isinstance(values, list)
                    or len(values) > MAX_MERGE_PACK_VERSIONS
                    or not all(
                        isinstance(item, str)
                        and item.count("@") == 1
                        and all(part for part in item.split("@", 1))
                        for item in values
                    )
                    or len(values) != len(set(values))
                ):
                    raise SessionError(
                        "merge source rule-pack metadata must be a bounded unique string array"
                    )
                metadata[key] = sorted(values)
            else:
                raise SessionError("merge source contains unsupported per-session metadata")
            if session_key not in session_ids:
                raise SessionError("merge source contains orphaned per-session metadata")
        _require_stable_session_source(path, "merge")
        digest_after, size_after = _hash_file(path)
        _require_stable_session_source(path, "merge")
    if (digest, size) != (digest_after, size_after):
        raise SessionError(f"merge source changed while it was being read: {path}")
    return {
        "path": str(path),
        "sha256": digest,
        "size_bytes": size,
        "clock_offset_ms": float(offset_ms),
        "tables": tables,
        "metadata": metadata,
        "row_count": row_count,
    }


def merge_sessions(
    sources: Sequence[str],
    destination: str,
    *,
    clock_offsets_ms: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    if isinstance(sources, (str, bytes)) or not isinstance(sources, Sequence):
        raise SessionError("merge sources must be an array of non-empty path strings")
    if len(sources) < 2:
        raise SessionError("session merge requires at least two source files")
    if len(sources) > MAX_MERGE_SOURCES:
        raise SessionError(f"session merge accepts at most {MAX_MERGE_SOURCES} source files")
    if not all(isinstance(item, str) and item for item in sources):
        raise SessionError("merge sources must be non-empty path strings")
    destination_path = Path(os.path.abspath(str(Path(destination).expanduser())))
    _destination_must_be_new(destination_path, "merge")
    if clock_offsets_ms is not None and not isinstance(clock_offsets_ms, dict):
        raise SessionError("clock offsets must be a path-to-milliseconds object")
    offsets: Dict[str, float] = {}
    for raw_path, raw_value in (clock_offsets_ms or {}).items():
        if not isinstance(raw_path, str) or not raw_path:
            raise SessionError("clock offset paths must be non-empty strings")
        if isinstance(raw_value, bool) or not isinstance(raw_value, (int, float)):
            raise SessionError("clock offsets must be finite numbers of milliseconds")
        value = float(raw_value)
        if not math.isfinite(value) or abs(value) > MAX_CLOCK_OFFSET_MS:
            raise SessionError(
                f"clock offsets must be finite and within +/-{MAX_CLOCK_OFFSET_MS} milliseconds"
            )
        normalized_path = os.path.abspath(str(Path(raw_path).expanduser()))
        if normalized_path in offsets:
            raise SessionError(f"clock offsets contain an equivalent duplicate path: {normalized_path}")
        offsets[normalized_path] = 0.0 if value == 0 else value
    resolved_sources: List[Tuple[Path, int]] = []
    for source_name in sources:
        path = Path(os.path.abspath(str(Path(source_name).expanduser())))
        source_size = _require_stable_session_source(path, "merge")
        if path == destination_path:
            raise SessionError("merge destination cannot also be a source")
        resolved_sources.append((path, source_size))
    destination_family = _sqlite_family(destination_path)
    _require_absent_paths(destination_family[1:], "merge")
    for source_path, _source_size in resolved_sources:
        if any(
            _paths_refer_to_same_file(source_member, destination_member)
            for source_member in _sqlite_family(source_path)
            for destination_member in destination_family
        ):
            raise SessionError(
                "merge destination and its SQLite companions cannot overlap a source file family"
            )
    source_paths = [str(path) for path, _size in resolved_sources]
    if len(source_paths) != len(set(source_paths)):
        raise SessionError("merge sources contain duplicate paths")
    if sum(size for _path, size in resolved_sources) > MAX_MERGE_TOTAL_BYTES:
        raise SessionError(
            f"merge source files exceed the {MAX_MERGE_TOTAL_BYTES}-byte limit"
        )
    unknown_offsets = sorted(set(offsets) - set(source_paths))
    if unknown_offsets:
        raise SessionError(f"clock offsets reference unknown sources: {', '.join(unknown_offsets)}")
    source_values: List[Dict[str, Any]] = []
    remaining_rows = MAX_MERGE_ROWS
    for resolved_path, _size in resolved_sources:
        source_value = _source_rows(
            resolved_path,
            offsets.get(str(resolved_path), 0.0),
            remaining_rows,
        )
        remaining_rows -= int(source_value["row_count"])
        source_values.append(source_value)
    source_values.sort(key=lambda item: item["sha256"])
    hashes = [item["sha256"] for item in source_values]
    if len(set(hashes)) != len(hashes):
        raise SessionError("merge sources contain duplicate SHA-256 artifacts")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.", suffix=".wsdb.tmp", dir=str(destination_path.parent)
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    inserted_sessions: Set[str] = set()
    artifact_ids: Set[str] = set()
    entity_ids: Set[str] = set()
    event_ids: Set[str] = set()
    finding_ids: Set[str] = set()
    merged_session_order: List[Tuple[datetime, str]] = []
    event_buffer: List[Tuple[datetime, str, int, Dict[str, Any], float]] = []
    try:
        with SessionStore(str(temporary)) as store:
            for source_data in source_values:
                offset = float(source_data["clock_offset_ms"])
                tables: Dict[str, List[Dict[str, Any]]] = source_data["tables"]
                for session_row in sorted(tables["sessions"], key=lambda item: str(item["id"])):
                    session_id = str(session_row["id"])
                    if session_id in inserted_sessions:
                        raise SessionError(f"merge source session ID collision: {session_id}")
                    inserted_sessions.add(session_id)
                    session_row["started_at"] = _shift_timestamp(
                        session_row["started_at"], offset, "session start timestamp"
                    )
                    session_row["ended_at"] = _shift_timestamp(
                        session_row["ended_at"], offset, "session end timestamp"
                    )
                    _require_timestamp_order(
                        session_row["started_at"], session_row["ended_at"], "session"
                    )
                    started_value = _parse_timestamp(
                        session_row["started_at"], "session start timestamp"
                    )
                    assert started_value is not None
                    merged_session_order.append((started_value, session_id))
                    store.connection.execute(
                        """INSERT INTO sessions
                           (id, title, source, status, started_at, ended_at, wirescope_version,
                            host_json, config_json, summary_json)
                           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        tuple(session_row[key] for key in (
                            "id", "title", "source", "status", "started_at", "ended_at",
                            "wirescope_version", "host_json", "config_json", "summary_json",
                        )),
                    )
                for artifact_row in sorted(tables["artifacts"], key=lambda item: str(item["id"])):
                    artifact_id = str(artifact_row["id"])
                    if artifact_id in artifact_ids:
                        raise SessionError(f"merge artifact ID collision: {artifact_id}")
                    artifact_ids.add(artifact_id)
                    artifact_row["imported_at"] = _shift_timestamp(
                        artifact_row["imported_at"], offset, "artifact import timestamp"
                    )
                    store.connection.execute(
                        """INSERT INTO artifacts
                           (id, session_id, sha256, size_bytes, source_path, source_type, imported_at, metadata_json)
                           VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                        tuple(artifact_row[key] for key in (
                            "id", "session_id", "sha256", "size_bytes", "source_path",
                            "source_type", "imported_at", "metadata_json",
                        )),
                    )
                for entity_row in sorted(tables["entities"], key=lambda item: str(item["id"])):
                    entity_id = str(entity_row["id"])
                    if entity_id in entity_ids:
                        raise SessionError(f"merge entity ID collision: {entity_id}")
                    entity_ids.add(entity_id)
                    entity_row["first_seen"] = _shift_timestamp(
                        entity_row["first_seen"], offset, "entity first-seen timestamp"
                    )
                    entity_row["last_seen"] = _shift_timestamp(
                        entity_row["last_seen"], offset, "entity last-seen timestamp"
                    )
                    _require_timestamp_order(
                        entity_row["first_seen"], entity_row["last_seen"], "entity observation"
                    )
                    store.connection.execute(
                        """INSERT INTO entities
                           (id, session_id, entity_type, entity_key, label, first_seen, last_seen, attributes_json)
                           VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
                        tuple(entity_row[key] for key in (
                            "id", "session_id", "entity_type", "entity_key", "label",
                            "first_seen", "last_seen", "attributes_json",
                        )),
                    )
                for event_row in tables["events"]:
                    event_id = str(event_row["event_id"])
                    if event_id in event_ids:
                        raise SessionError(f"merge event ID collision: {event_id}")
                    event_ids.add(event_id)
                    original_sequence = int(event_row.pop("sequence"))
                    original_timestamp = event_row.get("original_timestamp") or event_row["timestamp"]
                    event_row["timestamp"] = _shift_timestamp(
                        event_row["timestamp"], offset, "event timestamp"
                    )
                    if offset:
                        event_row["original_timestamp"] = original_timestamp
                    event_timestamp = _parse_timestamp(event_row["timestamp"], "event timestamp")
                    assert event_timestamp is not None
                    event_buffer.append(
                        (
                            event_timestamp,
                            str(source_data["sha256"]),
                            original_sequence,
                            event_row,
                            offset,
                        )
                    )
                for relation_row in sorted(tables["relations"], key=lambda item: int(item["id"])):
                    relation_row["first_seen"] = _shift_timestamp(
                        relation_row["first_seen"], offset, "relation first-seen timestamp"
                    )
                    relation_row["last_seen"] = _shift_timestamp(
                        relation_row["last_seen"], offset, "relation last-seen timestamp"
                    )
                    _require_timestamp_order(
                        relation_row["first_seen"],
                        relation_row["last_seen"],
                        "relation observation",
                    )
                    evidence = _strict_json(
                        relation_row["evidence_json"], "merge relation evidence"
                    )
                    if not isinstance(evidence, dict):
                        raise SessionError("merge relation evidence must be a JSON object")
                    if offset:
                        evidence["merge_clock_offset_ms"] = offset
                    store.connection.execute(
                        """INSERT INTO relations
                           (session_id, source_id, relation_type, target_id, first_seen, last_seen,
                            confidence, rule_id, rule_version, confidence_basis, evidence_json)
                           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            relation_row["session_id"], relation_row["source_id"],
                            relation_row["relation_type"], relation_row["target_id"],
                            relation_row["first_seen"], relation_row["last_seen"],
                            relation_row["confidence"], relation_row["rule_id"],
                            relation_row["rule_version"], relation_row["confidence_basis"],
                            _json(evidence),
                        ),
                    )
                for finding_row in sorted(tables["findings"], key=lambda item: str(item["id"])):
                    finding_id = str(finding_row["id"])
                    if finding_id in finding_ids:
                        raise SessionError(f"merge finding ID collision: {finding_id}")
                    finding_ids.add(finding_id)
                    finding_row["timestamp"] = _shift_timestamp(
                        finding_row["timestamp"], offset, "finding timestamp"
                    )
                    store.connection.execute(
                        """INSERT INTO findings
                           (id, session_id, timestamp, rule_id, title, category, severity, confidence,
                            entity_id, evidence_json, explanation, recommendation, pack_id, pack_version,
                            limitations_json, status)
                           VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        tuple(finding_row[key] for key in (
                            "id", "session_id", "timestamp", "rule_id", "title", "category", "severity",
                            "confidence", "entity_id", "evidence_json", "explanation", "recommendation",
                            "pack_id", "pack_version", "limitations_json", "status",
                        )),
                    )
                source_metadata: Dict[str, Any] = source_data["metadata"]
                for metadata_key, metadata_value in source_metadata.items():
                    store.set_metadata(metadata_key, metadata_value)

            for _timestamp, _hash, _sequence, buffered_row, _offset in sorted(
                event_buffer, key=lambda item: (item[0], item[1], item[2])
            ):
                store.connection.execute(
                    """INSERT INTO events
                       (event_id, schema_version, session_id, timestamp, source, event_type, severity,
                        confidence, entity_id, correlation_id, artifact_id, source_index,
                        original_timestamp, payload_json)
                       VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    tuple(buffered_row[key] for key in (
                        "event_id", "schema_version", "session_id", "timestamp", "source", "event_type",
                        "severity", "confidence", "entity_id", "correlation_id", "artifact_id",
                        "source_index", "original_timestamp", "payload_json",
                    )),
                )
            store.set_metadata(
                "merged_sources",
                [
                    {
                        "sha256": source_data["sha256"],
                        "size_bytes": source_data["size_bytes"],
                        "clock_offset_ms": source_data["clock_offset_ms"],
                    }
                    for source_data in source_values
                ],
            )
            if merged_session_order:
                store.set_metadata(
                    "active_session_id",
                    max(merged_session_order, key=lambda item: (item[0], item[1]))[1],
                )
            store.commit()
            store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            store.connection.execute("PRAGMA journal_mode=DELETE")
        verification = verify_session(str(temporary))
        if not verification["passed"]:
            raise SessionError(f"merged session failed verification: {verification['checks']}")
        for source_data in source_values:
            source_path = Path(str(source_data["path"]))
            _require_stable_session_source(source_path, "merge")
            if _hash_file(source_path) != (
                source_data["sha256"],
                source_data["size_bytes"],
            ):
                raise SessionError(f"merge source changed before destination publication: {source_path}")
        os.chmod(temporary, PRIVATE_FILE_MODE)
        _publish_new_private_file(
            temporary,
            destination_path,
            "merge",
            forbidden_companions=destination_family[1:],
        )
    except Exception:
        temporary.unlink(missing_ok=True)
        for companion in (Path(f"{temporary}-wal"), Path(f"{temporary}-shm"), Path(f"{temporary}-journal")):
            companion.unlink(missing_ok=True)
        raise
    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        "destination": str(destination_path),
        "sources": [
            {
                "sha256": source_data["sha256"],
                "size_bytes": source_data["size_bytes"],
                "clock_offset_ms": source_data["clock_offset_ms"],
            }
            for source_data in source_values
        ],
        "sessions": len(inserted_sessions),
        "events": len(event_buffer),
        "source_files_unchanged": True,
    }


def _collect_event_references(value: Any, references: set, budget: List[int]) -> None:
    pending = [value]
    while pending:
        current = pending.pop()
        budget[0] += 1
        if budget[0] > MAX_PRUNE_EVIDENCE_NODES:
            raise SessionError(
                f"prune evidence exceeds the {MAX_PRUNE_EVIDENCE_NODES}-node limit"
            )
        if isinstance(current, dict):
            budget[0] += len(current)
            for key, item in current.items():
                if key in ("event_id", "evidence_event_id") and isinstance(item, str) and item.startswith("evt_"):
                    references.add(item)
                elif key in ("event_ids", "evidence_ids") and isinstance(item, list):
                    references.update(
                        entry for entry in item if isinstance(entry, str) and entry.startswith("evt_")
                    )
                if isinstance(item, (dict, list)):
                    pending.append(item)
        elif isinstance(current, list):
            budget[0] += len(current)
            pending.extend(item for item in current if isinstance(item, (dict, list)))
        if budget[0] > MAX_PRUNE_EVIDENCE_NODES:
            raise SessionError(
                f"prune evidence exceeds the {MAX_PRUNE_EVIDENCE_NODES}-node limit"
            )


def prune_session(
    session: str,
    *,
    before: str,
    apply: bool = False,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    cutoff = _parse_timestamp(before, "prune timestamp")
    assert cutoff is not None
    cutoff_value = cutoff.isoformat(timespec="milliseconds")
    with SessionStore(session, read_only=not apply) as store:
        if apply:
            store.connection.execute("BEGIN IMMEDIATE")
        else:
            store.connection.execute("BEGIN")
        active = _existing_session_id(store, session_id)
        counts = {
            "events": int(
                store.connection.execute(
                    'SELECT COUNT(*) FROM "events" WHERE session_id=?', (active,)
                ).fetchone()[0]
            ),
            "relations": int(
                store.connection.execute('SELECT COUNT(*) FROM "relations"').fetchone()[0]
            ),
            "findings": int(
                store.connection.execute('SELECT COUNT(*) FROM "findings"').fetchone()[0]
            ),
        }
        if sum(counts.values()) > MAX_PRUNE_ROWS:
            raise SessionError(f"prune input exceeds the {MAX_PRUNE_ROWS}-row limit")
        evidence_bytes = sum(
            int(
                store.connection.execute(
                    f'SELECT COALESCE(SUM(LENGTH(CAST(evidence_json AS BLOB))), 0) FROM "{table}"'
                ).fetchone()[0]
            )
            for table in ("relations", "findings")
        )
        if evidence_bytes > MAX_PRUNE_EVIDENCE_BYTES:
            raise SessionError(
                f"prune evidence exceeds the {MAX_PRUNE_EVIDENCE_BYTES}-byte limit"
            )
        referenced: Set[str] = set()
        evidence_budget = [0]
        for row in store.connection.execute("SELECT evidence_json FROM relations"):
            _collect_event_references(
                _strict_json(row[0], "relation evidence"), referenced, evidence_budget
            )
        for row in store.connection.execute("SELECT evidence_json FROM findings"):
            _collect_event_references(
                _strict_json(row[0], "finding evidence"), referenced, evidence_budget
            )
        rows = []
        for row in store.connection.execute(
            """SELECT event_id, event_type, timestamp FROM events
               WHERE session_id=? ORDER BY sequence""",
            (active,),
        ):
            timestamp = _parse_timestamp(row["timestamp"], "event timestamp")
            assert timestamp is not None
            if timestamp < cutoff:
                rows.append(row)
        candidates = [
            str(row["event_id"])
            for row in rows
            if row["event_type"] != "user.marker" and row["event_id"] not in referenced
        ]
        preserved = [
            str(row["event_id"])
            for row in rows
            if row["event_type"] == "user.marker" or row["event_id"] in referenced
        ]
        if apply:
            for start in range(0, len(candidates), 500):
                batch = candidates[start : start + 500]
                placeholders = ",".join("?" for _item in batch)
                store.connection.execute(f"DELETE FROM events WHERE event_id IN ({placeholders})", batch)
            store.commit()
        return {
            "session": session,
            "session_id": active,
            "cutoff": cutoff_value,
            "mode": "applied" if apply else "dry-run",
            "candidate_count": len(candidates),
            "deleted_count": len(candidates) if apply else 0,
            "preserved_count": len(preserved),
            "preserved_event_ids": preserved[:100],
        }


def export_session(
    session: str,
    output: str,
    *,
    export_format: str = "json",
    private: bool = False,
    redaction_rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    if export_format not in {"json", "jsonl", "html"}:
        raise SessionError(f"unsupported session export format: {export_format}")
    source_path = Path(os.path.abspath(str(Path(session).expanduser())))
    output_path = Path(os.path.abspath(str(Path(output).expanduser())))
    same_path = source_path == output_path
    if not same_path:
        try:
            same_path = os.path.samefile(source_path, output_path)
        except OSError:
            pass
    if same_path:
        raise SessionError("session export output cannot overwrite the source database")
    _reject_sqlite_family_collision(source_path, output_path, "session export")
    if export_format == "html":
        return generate_session_html(
            session,
            output,
            share_safe=not private,
            redaction_rules=redaction_rules,
        )
    data = build_session_report_data(
        session,
        share_safe=not private,
        redaction_rules=redaction_rules,
    )
    payload = {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "kind": "wirescope-session-export",
        **data,
    }
    if export_format == "json":
        atomic_write_text(output, json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    elif export_format == "jsonl":
        with atomic_text_writer(output, encoding="utf-8", newline="\n") as stream:
            for item in payload["timeline"]:
                stream.write(json.dumps(item, ensure_ascii=False, sort_keys=True))
                stream.write("\n")
    return {
        "schema_version": EXPORT_SCHEMA_VERSION,
        "output": output,
        "format": export_format,
        "sharing_mode": "private" if private else "share-safe",
        "events": len(payload["timeline"]),
    }


def _zip_info(name: str, *, compress_type: int = zipfile.ZIP_DEFLATED) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = compress_type
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | PRIVATE_FILE_MODE) << 16
    return info


def _zip_entry(name: str, data: bytes) -> Tuple[zipfile.ZipInfo, bytes]:
    info = _zip_info(name)
    return info, data


def _write_zip_file(
    archive: zipfile.ZipFile,
    name: str,
    source: Path,
    expected_sha256: str,
    expected_size: int,
) -> None:
    digest = hashlib.sha256()
    size = 0
    with _open_regular_binary(source) as input_stream, archive.open(
        _zip_info(name, compress_type=zipfile.ZIP_STORED), "w"
    ) as output_stream:
        for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > MAX_BUNDLE_ENTRY_BYTES:
                raise SessionError(f"bundle entry exceeds {MAX_BUNDLE_ENTRY_BYTES} bytes: {name}")
            digest.update(chunk)
            output_stream.write(chunk)
    if size != expected_size or digest.hexdigest() != expected_sha256:
        raise SessionError(f"bundle source changed while it was being archived: {source}")


def _portable_raw_snapshot(
    source: Path,
    destination: Path,
    expected_source: Tuple[str, int],
) -> Tuple[str, int]:
    source_digest = hashlib.sha256()
    size = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(destination, flags, PRIVATE_FILE_MODE)
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        output_stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with output_stream as output, _open_regular_binary(source) as input_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                size += len(chunk)
                if size > MAX_BUNDLE_ENTRY_BYTES:
                    raise SessionError(
                        f"raw session exceeds the {MAX_BUNDLE_ENTRY_BYTES}-byte bundle limit"
                    )
                source_digest.update(chunk)
                output.write(chunk)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (source_digest.hexdigest(), size) != expected_source:
        raise SessionError(f"bundle source changed while its raw snapshot was copied: {source}")
    try:
        connection = sqlite3.connect(str(destination), timeout=5.0)
        try:
            mode = str(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]).lower()
            if mode != "delete":
                raise SessionError("cannot make the private raw snapshot independently portable")
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise SessionError(f"cannot finalize the private raw snapshot: {exc}") from exc
    for suffix in ("-wal", "-shm", "-journal"):
        companion = Path(f"{destination}{suffix}")
        try:
            info = os.lstat(companion)
        except FileNotFoundError:
            continue
        if suffix != "-shm" and info.st_size:
            raise SessionError(f"portable raw snapshot retained an active SQLite sidecar: {companion}")
        companion.unlink()
    verification = verify_session(str(destination))
    if not verification.get("passed"):
        raise SessionError(f"portable raw snapshot failed verification: {verification['checks']}")
    return _hash_file(destination)


def create_support_bundle(
    session: str,
    output: str,
    *,
    include_raw_private: bool = False,
    redaction_rules: Optional[RedactionRules] = None,
) -> Dict[str, Any]:
    if not isinstance(include_raw_private, bool):
        raise SessionError("include_raw_private must be boolean")
    source = Path(os.path.abspath(str(Path(session).expanduser())))
    _require_stable_session_source(source, "bundle")
    source_before = _hash_file(source)
    destination = Path(os.path.abspath(str(Path(output).expanduser())))
    _reject_sqlite_family_collision(source, destination, "bundle")
    _destination_must_be_new(destination, "bundle")
    share_safe = not include_raw_private
    raw_descriptor: Optional[Dict[str, Any]] = None
    raw_snapshot_path: Optional[Path] = None
    if include_raw_private and source_before[1] > MAX_BUNDLE_ENTRY_BYTES:
        raise SessionError(f"raw session exceeds the {MAX_BUNDLE_ENTRY_BYTES}-byte bundle limit")
    data = build_session_report_data(source.as_posix(), share_safe=share_safe, redaction_rules=redaction_rules)
    with tempfile.TemporaryDirectory(prefix="wirescope-bundle-") as directory:
        if include_raw_private:
            raw_snapshot_path = Path(directory) / "session.wsdb"
            raw_sha256, raw_size = _portable_raw_snapshot(
                source, raw_snapshot_path, source_before
            )
            raw_descriptor = {
                "path": "raw/session.wsdb",
                "size_bytes": raw_size,
                "sha256": raw_sha256,
            }
        report_path = Path(directory) / "report.html"
        generate_session_html(
            str(source),
            str(report_path),
            title="WireScope Support Bundle",
            share_safe=share_safe,
            redaction_rules=redaction_rules,
        )
        report_size = report_path.stat().st_size
        if report_size > MAX_GENERATED_BUNDLE_BYTES:
            raise SessionError("generated support-bundle report is too large")
        contents: Dict[str, bytes] = {
            "session.json": (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(),
            "report.html": report_path.read_bytes(),
            "capability.json": (
                json.dumps(
                    {
                        "schema_version": 1,
                        "sessions": [
                            {
                                "id": item.get("id"),
                                "config": item.get("config", {}),
                                "host": item.get("host", {}),
                            }
                            for item in data["summary"]["sessions"]
                        ],
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            "redaction-policy.json": (
                json.dumps(
                    {
                        "schema_version": 1,
                        "mode": "private" if include_raw_private else "strict-share-safe",
                        "raw_included": include_raw_private,
                        "human_review_required": True,
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            ).encode(),
            "REVIEW.md": (
                "# WireScope support bundle review\n\n"
                "- [ ] Review visible domains and findings.\n"
                "- [ ] Confirm tokens, identifiers, addresses and local paths are absent.\n"
                "- [ ] Confirm the intended recipient and transfer channel.\n"
                + (
                    "- [ ] This bundle includes the raw private session and must not be published.\n"
                    if include_raw_private
                    else "- [ ] The bundle is share-safe but still requires human review.\n"
                )
            ).encode(),
        }
        generated_size = sum(len(payload) for payload in contents.values())
        if generated_size > MAX_GENERATED_BUNDLE_BYTES:
            raise SessionError(
                f"generated bundle content exceeds {MAX_GENERATED_BUNDLE_BYTES} bytes"
            )
        file_descriptors = [
            {
                "path": name,
                "size_bytes": len(contents[name]),
                "sha256": hashlib.sha256(contents[name]).hexdigest(),
            }
            for name in sorted(contents)
        ]
        if raw_descriptor is not None:
            file_descriptors.append(raw_descriptor)
            file_descriptors.sort(key=lambda item: str(item["path"]))
        manifest: Dict[str, Any] = {
            "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
            "kind": "wirescope-support-bundle",
            "sharing_mode": "private" if include_raw_private else "share-safe",
            "human_review_required": True,
            "visible_evidence_warning": "Domain names, event categories and findings can reveal activity.",
            "files": file_descriptors,
        }
        manifest_payload = (
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode()
        if len(manifest_payload) > MAX_BUNDLE_MANIFEST_BYTES:
            raise SessionError("support-bundle manifest is too large")
        contents["manifest.json"] = manifest_payload
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
        )
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(temporary, "w") as archive:
                names = set(contents)
                if raw_descriptor is not None:
                    names.add(str(raw_descriptor["path"]))
                for name in sorted(names):
                    if raw_descriptor is not None and name == raw_descriptor["path"]:
                        assert raw_snapshot_path is not None
                        _write_zip_file(
                            archive,
                            name,
                            raw_snapshot_path,
                            str(raw_descriptor["sha256"]),
                            int(raw_descriptor["size_bytes"]),
                        )
                    else:
                        info, payload = _zip_entry(name, contents[name])
                        archive.writestr(info, payload)
            os.chmod(temporary, PRIVATE_FILE_MODE)
            _require_stable_session_source(source, "bundle")
            if _hash_file(source) != source_before:
                raise SessionError(f"bundle source changed while it was being created: {source}")
            temporary_verification = verify_support_bundle(str(temporary))
            if not temporary_verification["passed"]:
                raise SessionError(
                    f"temporary bundle failed verification: {temporary_verification['checks']}"
                )
            _publish_new_private_file(temporary, destination, "bundle")
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
    verification = verify_support_bundle(str(destination))
    if not verification["passed"]:
        raise SessionError(f"created bundle failed verification: {verification['checks']}")
    return {
        "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
        "output": str(destination),
        "sharing_mode": manifest["sharing_mode"],
        "files": len(manifest["files"]),
        "verified": True,
        "human_review_required": True,
    }


def _bundle_json_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _bundle_json_constant(value: str) -> Any:
    raise ValueError(f"invalid manifest numeric constant: {value}")


def _safe_zip_name(name: Any) -> bool:
    if not isinstance(name, str) or not name or len(name) > 512:
        return False
    if (
        name.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:", name) is not None
        or "\\" in name
        or name.endswith("/")
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        return False
    return all(component not in ("", ".", "..") for component in name.split("/"))


def _bounded_compression(info: zipfile.ZipInfo) -> bool:
    if info.file_size <= ZIP_RATIO_EXEMPT_BYTES:
        return True
    if info.compress_size <= 0:
        return False
    return info.file_size <= info.compress_size * MAX_ZIP_COMPRESSION_RATIO


def _preflight_zip_stream(stream: Any, file_size: int) -> Any:
    """Bound the central directory before ZipFile materializes every entry."""

    if file_size < 22:
        raise ValueError("ZIP is too small to contain an end-of-central-directory record")
    tail_size = min(file_size, 22 + 0xFFFF)
    stream.seek(file_size - tail_size)
    tail = stream.read(tail_size)
    marker = tail.rfind(b"PK\x05\x06")
    if marker < 0 or marker + 22 > len(tail):
        raise ValueError("ZIP end-of-central-directory record is missing")
    (
        _signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_size,
    ) = struct.unpack_from("<4s4H2LH", tail, marker)
    if marker + 22 + comment_size != len(tail):
        raise ValueError("ZIP end-of-central-directory comment length is inconsistent")
    eocd_offset = file_size - tail_size + marker
    if (
        total_entries == 0xFFFF
        or disk_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        locator_offset = eocd_offset - 20
        if locator_offset < 0:
            raise ValueError("ZIP64 locator is missing")
        stream.seek(locator_offset)
        locator = stream.read(20)
        if len(locator) != 20:
            raise ValueError("ZIP64 locator is truncated")
        locator_signature, locator_disk, zip64_offset, locator_disks = struct.unpack(
            "<4sLQL", locator
        )
        if locator_signature != b"PK\x06\x07" or locator_disk != 0 or locator_disks != 1:
            raise ValueError("multi-disk or malformed ZIP64 archives are unsupported")
        stream.seek(zip64_offset)
        zip64_record = stream.read(56)
        if len(zip64_record) != 56:
            raise ValueError("ZIP64 end-of-central-directory record is truncated")
        (
            zip64_signature,
            record_size,
            _made_by,
            _needed,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
        ) = struct.unpack("<4sQ2H2L4Q", zip64_record)
        if (
            zip64_signature != b"PK\x06\x06"
            or record_size < 44
            or zip64_offset + 12 + record_size > locator_offset
        ):
            raise ValueError("ZIP64 end-of-central-directory record is malformed")
    if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
        raise ValueError("multi-disk ZIP archives are unsupported")
    if total_entries < 1 or total_entries > MAX_BUNDLE_ENTRIES:
        raise ValueError(
            f"ZIP declares {total_entries} entries (limit {MAX_BUNDLE_ENTRIES})"
        )
    if central_size > MAX_BUNDLE_CENTRAL_DIRECTORY_BYTES:
        raise ValueError(
            "ZIP central directory exceeds "
            f"{MAX_BUNDLE_CENTRAL_DIRECTORY_BYTES} bytes"
        )
    if central_offset > file_size or central_size > file_size - central_offset:
        raise ValueError("ZIP central-directory bounds are invalid")
    stream.seek(central_offset)
    central_directory = stream.read(central_size)
    if len(central_directory) != central_size:
        raise ValueError("ZIP central directory is truncated")
    position = 0
    observed_entries = 0
    while position < len(central_directory):
        if position + 46 > len(central_directory) or central_directory[
            position : position + 4
        ] != b"PK\x01\x02":
            raise ValueError("ZIP central directory contains a malformed entry")
        name_size, extra_size, entry_comment_size = struct.unpack_from(
            "<3H", central_directory, position + 28
        )
        entry_size = 46 + name_size + extra_size + entry_comment_size
        if entry_size > len(central_directory) - position:
            raise ValueError("ZIP central-directory entry is truncated")
        position += entry_size
        observed_entries += 1
        if observed_entries > MAX_BUNDLE_ENTRIES:
            raise ValueError(
                f"ZIP central directory contains more than {MAX_BUNDLE_ENTRIES} entries"
            )
    if observed_entries != total_entries:
        raise ValueError(
            "ZIP central-directory entry count does not match its end record"
        )
    stream.seek(0)
    return stream


def _bounded_zip_bytes(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limit: int,
    label: str,
) -> bytes:
    if info.file_size > limit:
        raise ValueError(f"{label} exceeds its {limit}-byte verification limit")
    with archive.open(info, "r") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ValueError(f"{label} exceeds its {limit}-byte verification limit")
    return payload


def _bounded_zip_json(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    limit: int,
    label: str,
) -> Any:
    payload = _bounded_zip_bytes(archive, info, limit, label)
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_bundle_json_pairs,
            parse_constant=_bundle_json_constant,
        )
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} contains invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise ValueError(f"{label} JSON nesting is too deep") from exc


def _is_schema_v1(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == 1


def _json_contract_equal(first: Any, second: Any) -> bool:
    try:
        return json.dumps(
            first,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8") == json.dumps(
            second,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeEncodeError):
        return False


def _session_payload_contract(value: Any, sharing_mode: str) -> bool:
    required = {
        "schema_version",
        "summary",
        "timeline",
        "entities",
        "relations",
        "findings",
        "limits",
        "sharing_safety",
    }
    if not isinstance(value, dict) or set(value) != required or not _is_schema_v1(
        value.get("schema_version")
    ):
        return False
    if not isinstance(value.get("summary"), dict) or not isinstance(value.get("limits"), dict):
        return False
    if not all(
        isinstance(value.get(name), list)
        for name in ("timeline", "entities", "relations", "findings")
    ):
        return False
    safety = value.get("sharing_safety")
    return (
        isinstance(safety, dict)
        and set(safety) == {"mode", "safe_to_publish_without_review", "warnings"}
        and safety.get("mode") == sharing_mode
        and safety.get("safe_to_publish_without_review") is False
        and isinstance(safety.get("warnings"), list)
        and bool(safety["warnings"])
        and all(isinstance(item, str) and item for item in safety["warnings"])
    )


def _report_payload_matches(report_bytes: bytes, session_data: Dict[str, Any]) -> bool:
    try:
        document = report_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    marker = '<script id="wirescope-session-data" type="application/json">'
    start = document.find(marker)
    if not document.lower().startswith("<!doctype html>") or start < 0:
        return False
    start += len(marker)
    end = document.find("</script>", start)
    if end < 0 or document.find(marker, start) >= 0:
        return False
    try:
        embedded = json.loads(
            document[start:end],
            object_pairs_hook=_bundle_json_pairs,
            parse_constant=_bundle_json_constant,
        )
    except (RecursionError, ValueError, json.JSONDecodeError):
        return False
    return _json_contract_equal(embedded, session_data)


def _raw_session_matches(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    session_data: Dict[str, Any],
) -> bool:
    descriptor, temporary_name = tempfile.mkstemp(prefix="wirescope-bundle-raw-", suffix=".wsdb")
    os.fchmod(descriptor, PRIVATE_FILE_MODE)
    temporary = Path(temporary_name)
    size = 0
    try:
        with os.fdopen(descriptor, "wb") as output, archive.open(info, "r") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                size += len(chunk)
                if size > MAX_BUNDLE_ENTRY_BYTES:
                    return False
                output.write(chunk)
        verification = verify_session(str(temporary))
        if not verification.get("passed"):
            return False
        raw_data = build_session_report_data(str(temporary), share_safe=False)
        expected = dict(session_data)
        actual = dict(raw_data)
        expected_summary = dict(expected.get("summary", {}))
        actual_summary = dict(actual.get("summary", {}))
        expected_summary.pop("path", None)
        actual_summary.pop("path", None)
        expected["summary"] = expected_summary
        actual["summary"] = actual_summary
        return _json_contract_equal(actual, expected)
    except (OSError, SessionError, RuntimeError, ValueError, zipfile.BadZipFile):
        return False
    finally:
        temporary.unlink(missing_ok=True)
        for suffix in ("-wal", "-shm", "-journal"):
            Path(f"{temporary}{suffix}").unlink(missing_ok=True)


def verify_support_bundle(path: str) -> Dict[str, Any]:
    bundle = Path(os.path.abspath(str(Path(path).expanduser())))
    checks: List[Dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail})

    try:
        verify_private_artifact(bundle, repair_mode=False)
        check("private-permissions", True, "regular owner-only file (0600)")
    except OSError as exc:
        check("private-permissions", False, str(exc))
    try:
        bundle_info = os.lstat(bundle)
        if not stat.S_ISREG(bundle_info.st_mode) or stat.S_ISLNK(bundle_info.st_mode):
            check("bounded-bundle-size", False, "bundle is not a regular non-symlink file")
            return {
                "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
                "path": str(bundle),
                "passed": False,
                "checks": checks,
            }
        bundle_size = bundle_info.st_size
        bounded_bundle = bundle_size <= MAX_BUNDLE_TOTAL_BYTES
        check(
            "bounded-bundle-size",
            bounded_bundle,
            f"bundle size is {bundle_size} bytes (limit {MAX_BUNDLE_TOTAL_BYTES})",
        )
        if not bounded_bundle:
            return {
                "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
                "path": str(bundle),
                "passed": False,
                "checks": checks,
            }
    except OSError as exc:
        check("bounded-bundle-size", False, str(exc))
        return {
            "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
            "path": str(bundle),
            "passed": False,
            "checks": checks,
        }
    try:
        with _open_regular_binary(bundle) as bundle_stream, zipfile.ZipFile(
            _preflight_zip_stream(bundle_stream, bundle_size), "r"
        ) as archive:
            opened_info = os.fstat(bundle_stream.fileno())
            opened_private = stat.S_IMODE(opened_info.st_mode) == PRIVATE_FILE_MODE
            check(
                "opened-private-permissions",
                opened_private,
                f"opened bundle mode is {stat.S_IMODE(opened_info.st_mode):#o}",
            )
            opened_stable = (opened_info.st_dev, opened_info.st_ino) == (
                bundle_info.st_dev,
                bundle_info.st_ino,
            )
            check(
                "opened-file-stability",
                opened_stable,
                "the verified path still refers to the inspected bundle",
            )
            infos = archive.infolist()
            names = [info.filename for info in infos]
            bounded_metadata = (
                len(infos) <= MAX_BUNDLE_ENTRIES
                and all(
                    0 <= info.file_size <= MAX_BUNDLE_ENTRY_BYTES
                    and 0 <= info.compress_size <= MAX_BUNDLE_ENTRY_BYTES
                    and _bounded_compression(info)
                    for info in infos
                )
                and sum(info.file_size for info in infos) <= MAX_BUNDLE_TOTAL_BYTES
                and sum(
                    info.file_size
                    for info in infos
                    if info.filename not in ("manifest.json", "raw/session.wsdb")
                )
                <= MAX_GENERATED_BUNDLE_BYTES
            )
            check(
                "bounded-entry-metadata",
                bounded_metadata,
                "entry count and declared compressed/uncompressed sizes are bounded",
            )
            safe_names = all(
                _safe_zip_name(name)
                and stat.S_ISREG((info.external_attr >> 16) & 0o170000)
                and stat.S_IMODE(info.external_attr >> 16) == PRIVATE_FILE_MODE
                and not (info.flag_bits & 0x1)
                and info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                for info, name in ((info, info.filename) for info in infos)
            )
            check(
                "safe-entry-paths",
                safe_names,
                "no traversal, absolute paths, symlinks, encryption or unsupported compression",
            )
            unique = len(names) == len(set(names))
            check("unique-entry-names", unique, "entry names are unique")
            manifest_info = next((info for info in infos if info.filename == "manifest.json"), None)
            try:
                if not bounded_metadata:
                    raise ValueError("bundle entry metadata exceeds verification limits")
                if manifest_info is None:
                    raise ValueError("manifest.json is missing")
                if manifest_info.file_size > MAX_BUNDLE_MANIFEST_BYTES:
                    raise ValueError("manifest.json exceeds the verification limit")
                with archive.open(manifest_info, "r") as stream:
                    manifest_bytes = stream.read(MAX_BUNDLE_MANIFEST_BYTES + 1)
                if len(manifest_bytes) > MAX_BUNDLE_MANIFEST_BYTES:
                    raise ValueError("manifest.json exceeds the verification limit")
                manifest = json.loads(
                    manifest_bytes.decode("utf-8"),
                    object_pairs_hook=_bundle_json_pairs,
                    parse_constant=_bundle_json_constant,
                )
            except (KeyError, RecursionError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                check("manifest", False, str(exc))
                manifest = None
            if isinstance(manifest, dict):
                expected_manifest_fields = {
                    "schema_version",
                    "kind",
                    "sharing_mode",
                    "human_review_required",
                    "visible_evidence_warning",
                    "files",
                }
                valid_manifest = (
                    set(manifest) == expected_manifest_fields
                    and _is_schema_v1(manifest.get("schema_version"))
                    and manifest.get("kind") == "wirescope-support-bundle"
                    and manifest.get("sharing_mode") in ("private", "share-safe")
                    and manifest.get("human_review_required") is True
                    and isinstance(manifest.get("visible_evidence_warning"), str)
                    and bool(manifest.get("visible_evidence_warning"))
                    and isinstance(manifest.get("files"), list)
                    and 1 <= len(manifest.get("files", [])) < MAX_BUNDLE_ENTRIES
                )
                raw_file_items = manifest.get("files")
                file_items: List[Dict[str, Any]] = (
                    raw_file_items
                    if valid_manifest and isinstance(raw_file_items, list)
                    else []
                )
                if valid_manifest:
                    for item in file_items:
                        if not isinstance(item, dict) or set(item) != {"path", "size_bytes", "sha256"}:
                            valid_manifest = False
                            break
                        item_path = item.get("path")
                        item_size = item.get("size_bytes")
                        item_sha256 = item.get("sha256")
                        if not (
                            _safe_zip_name(item_path)
                            and item_path != "manifest.json"
                            and isinstance(item_size, int)
                            and not isinstance(item_size, bool)
                            and 0 <= item_size <= MAX_BUNDLE_ENTRY_BYTES
                            and isinstance(item_sha256, str)
                            and re.fullmatch(r"[0-9a-f]{64}", item_sha256) is not None
                        ):
                            valid_manifest = False
                            break
                if valid_manifest:
                    descriptor_names = [item["path"] for item in file_items]
                    if len(descriptor_names) != len(set(descriptor_names)):
                        valid_manifest = False
                    required_paths = {
                        "REVIEW.md",
                        "capability.json",
                        "redaction-policy.json",
                        "report.html",
                        "session.json",
                    }
                    actual_paths = set(descriptor_names)
                    if manifest["sharing_mode"] == "private":
                        required_paths.add("raw/session.wsdb")
                    if actual_paths != required_paths:
                        valid_manifest = False
                check("manifest", valid_manifest, "supported support-bundle manifest")
                mismatches = []
                expected_names = set()
                info_by_name = {info.filename: info for info in infos} if unique else {}
                for item in file_items if valid_manifest else []:
                    name = item["path"]
                    expected_names.add(name)
                    try:
                        info = info_by_name[name]
                        digest = hashlib.sha256()
                        size = 0
                        with archive.open(info, "r") as stream:
                            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                                size += len(chunk)
                                if size > MAX_BUNDLE_ENTRY_BYTES:
                                    raise ValueError("entry expanded past the verification limit")
                                digest.update(chunk)
                    except (KeyError, RuntimeError, ValueError, zipfile.BadZipFile):
                        mismatches.append(str(name))
                        continue
                    if size != item["size_bytes"] or digest.hexdigest() != item["sha256"]:
                        mismatches.append(str(name))
                actual_payload_names = set(names) - {"manifest.json"}
                if expected_names != actual_payload_names:
                    mismatches.extend(str(item) for item in sorted(expected_names ^ actual_payload_names))
                check(
                    "payload-hashes",
                    valid_manifest and not mismatches,
                    "all payload sizes and SHA-256 values match" if not mismatches else f"mismatch: {', '.join(mismatches[:10])}",
                )
                policy_valid = False
                session_mode_valid = False
                capability_valid = False
                report_valid = False
                raw_session_valid = False
                if valid_manifest and not mismatches:
                    expected_private = manifest["sharing_mode"] == "private"
                    try:
                        policy_info = info_by_name["redaction-policy.json"]
                        policy = _bounded_zip_json(
                            archive,
                            policy_info,
                            MAX_BUNDLE_POLICY_BYTES,
                            "redaction-policy.json",
                        )
                        policy_valid = (
                            isinstance(policy, dict)
                            and set(policy)
                            == {"schema_version", "mode", "raw_included", "human_review_required"}
                            and _is_schema_v1(policy.get("schema_version"))
                            and policy.get("mode")
                            == ("private" if expected_private else "strict-share-safe")
                            and policy.get("raw_included") is expected_private
                            and policy.get("human_review_required") is True
                        )
                    except (
                        KeyError,
                        RecursionError,
                        RuntimeError,
                        UnicodeDecodeError,
                        ValueError,
                        zipfile.BadZipFile,
                    ):
                        policy_valid = False
                    try:
                        session_info = info_by_name["session.json"]
                        session_data = _bounded_zip_json(
                            archive,
                            session_info,
                            MAX_BUNDLE_SESSION_BYTES,
                            "session.json",
                        )
                        session_mode_valid = _session_payload_contract(
                            session_data, manifest["sharing_mode"]
                        )
                        capability = _bounded_zip_json(
                            archive,
                            info_by_name["capability.json"],
                            MAX_BUNDLE_CAPABILITY_BYTES,
                            "capability.json",
                        )
                        summary_sessions = (
                            session_data.get("summary", {}).get("sessions")
                            if isinstance(session_data, dict)
                            and isinstance(session_data.get("summary"), dict)
                            else None
                        )
                        expected_capability_sessions = []
                        if not isinstance(summary_sessions, list) or len(summary_sessions) > 10_000:
                            raise ValueError("session summary has invalid sessions")
                        for item in summary_sessions:
                            if (
                                not isinstance(item, dict)
                                or not isinstance(item.get("id"), str)
                                or not isinstance(item.get("config"), dict)
                                or not isinstance(item.get("host"), dict)
                            ):
                                raise ValueError("session summary contains an invalid session")
                            expected_capability_sessions.append(
                                {
                                    "id": item["id"],
                                    "config": item["config"],
                                    "host": item["host"],
                                }
                            )
                        capability_valid = (
                            isinstance(capability, dict)
                            and set(capability) == {"schema_version", "sessions"}
                            and _is_schema_v1(capability.get("schema_version"))
                            and _json_contract_equal(
                                capability.get("sessions"), expected_capability_sessions
                            )
                        )
                        report_bytes = _bounded_zip_bytes(
                            archive,
                            info_by_name["report.html"],
                            MAX_GENERATED_BUNDLE_BYTES,
                            "report.html",
                        )
                        report_valid = _report_payload_matches(report_bytes, session_data)
                        raw_session_valid = (
                            _raw_session_matches(
                                archive,
                                info_by_name["raw/session.wsdb"],
                                session_data,
                            )
                            if expected_private
                            else "raw/session.wsdb" not in info_by_name
                        )
                    except (
                        KeyError,
                        RecursionError,
                        RuntimeError,
                        UnicodeDecodeError,
                        ValueError,
                        zipfile.BadZipFile,
                    ):
                        session_mode_valid = False
                        capability_valid = False
                        report_valid = False
                        raw_session_valid = False
                check(
                    "sharing-policy",
                    policy_valid,
                    "sharing mode, raw inclusion and redaction policy agree",
                )
                check(
                    "session-sharing-mode",
                    session_mode_valid,
                    "session.json has the supported schema and agrees with the sharing mode",
                )
                check(
                    "capability-contract",
                    capability_valid,
                    "capability.json agrees with session.json",
                )
                check(
                    "report-session-binding",
                    report_valid,
                    "report.html embeds the exact session.json payload",
                )
                check(
                    "raw-session-binding",
                    raw_session_valid,
                    "private raw session is valid and agrees with session.json",
                )
            elif manifest is not None:
                check("manifest", False, "manifest.json must contain a JSON object")
            check("zip-integrity", True, "ZIP central directory and inspected payloads are readable")
    except (EOFError, NotImplementedError, OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        check("zip-integrity", False, str(exc))
    return {
        "schema_version": SUPPORT_BUNDLE_SCHEMA_VERSION,
        "path": str(bundle),
        "passed": bool(checks) and all(item["passed"] for item in checks),
        "checks": checks,
    }
