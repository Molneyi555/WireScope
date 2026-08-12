from __future__ import annotations

import errno
import hashlib
import json
import os
import platform
import sqlite3
import stat
import tempfile
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple, cast
from urllib.parse import urlsplit

from . import __version__
from .artifacts import PRIVATE_FILE_MODE, ArtifactSecurityError, verify_private_artifact
from .models import Connection, utc_now


SESSION_SCHEMA_VERSION = 2
EVENT_SCHEMA_VERSION = 2
SUPPORTED_SESSION_SCHEMA_VERSIONS = (1, 2)
SUPPORTED_EVENT_SCHEMA_VERSIONS = (1, 2)
DEFAULT_SESSION_SUFFIX = ".wsdb"
SQLITE_APPLICATION_ID = 0x57534350  # "WSCP"
SQLITE_USER_VERSION = SESSION_SCHEMA_VERSION
HIGH_CONFIDENCE_MIN = 0.85
MEDIUM_CONFIDENCE_MIN = 0.60

# Import and SQLite limits are deliberately generous enough for long captures,
# while preventing a single hostile scalar/line/file from consuming unbounded
# memory in parsers that necessarily materialize JSON.
MAX_SQLITE_VALUE_BYTES = 16 * 1024 * 1024
MAX_JSON_VALUE_CHARS = 16 * 1024 * 1024
MAX_JSONL_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_HAR_FILE_BYTES = 256 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 8 * 1024 * 1024
MAX_INGEST_EVENTS = 1_000_000
MAX_HAR_REQUESTS = 500_000
MAX_EVIDENCE_NODES = 100_000
MAX_EVIDENCE_REFERENCES = 100_000
MAX_VERIFY_REFERENCE_EVENTS = 2_000_000
MAX_VERIFY_SQLITE_BYTES = 8 * 1024 * 1024 * 1024
MAX_HASH_FILE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SUMMARY_SESSIONS = 10_000
MAX_SUMMARY_GROUPS = 10_000
MAX_SUMMARY_TEXT_BYTES = 64 * 1024 * 1024

# These stable numeric categories come from SQLite's public sqlite3_limit API.
# Python 3.9 exposes Connection.setlimit only on some builds and its typeshed
# stubs do not expose the module constants, so keep compatible local aliases.
_SQLITE_LIMIT_LENGTH: int = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", 0)
_SQLITE_LIMIT_SQL_LENGTH: int = getattr(sqlite3, "SQLITE_LIMIT_SQL_LENGTH", 1)
_SQLITE_LIMIT_ATTACHED: int = getattr(sqlite3, "SQLITE_LIMIT_ATTACHED", 7)

CANONICAL_EVENT_TYPES = {
    "connection_open": "connection.opened",
    "connection_close": "connection.closed",
    "session_start": "session.started",
    "session_end": "session.finished",
}


class SessionError(RuntimeError):
    """Raised when a WireScope session cannot be opened or interpreted."""


@dataclass(frozen=True)
class EventEnvelope:
    event_type: str
    source: str
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=utc_now)
    severity: str = "info"
    confidence: Optional[float] = None
    entity_id: Optional[str] = None
    correlation_id: Optional[str] = None
    artifact_id: Optional[str] = None
    source_index: Optional[int] = None
    original_timestamp: Optional[str] = None
    schema_version: int = EVENT_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventBus:
    """Small synchronous event bus shared by recorders and future views."""

    def __init__(self) -> None:
        self._subscribers: List[Callable[[EventEnvelope], None]] = []

    def subscribe(self, callback: Callable[[EventEnvelope], None]) -> Callable[[], None]:
        self._subscribers.append(callback)

        def unsubscribe() -> None:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

        return unsubscribe

    def publish(self, event: EventEnvelope) -> None:
        for callback in tuple(self._subscribers):
            callback(event)


def _json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _reject_json_constant(token: str) -> Any:
    raise ValueError(f"invalid JSON numeric constant: {token}")


def _load_json(value: Optional[str], fallback: Any) -> Any:
    if not value or not isinstance(value, str) or len(value) > MAX_JSON_VALUE_CHARS:
        return fallback
    try:
        return json.loads(value, parse_constant=_reject_json_constant)
    except (TypeError, ValueError, RecursionError):
        return fallback


def confidence_band(value: Optional[float]) -> str:
    if value is None:
        return "unknown"
    if value >= HIGH_CONFIDENCE_MIN:
        return "high"
    if value >= MEDIUM_CONFIDENCE_MIN:
        return "medium"
    return "low"


def _normalize_timestamp(value: Any) -> Tuple[str, Optional[str], str]:
    """Return a UTC timestamp, its original representation, and clock metadata."""

    if value in (None, ""):
        return utc_now(), None, "ingest-time"
    original = str(value)
    try:
        if isinstance(value, (int, float)):
            parsed = datetime.fromtimestamp(float(value), timezone.utc)
            return parsed.isoformat(timespec="milliseconds"), original, "unix-seconds"
        normalized = original[:-1] + "+00:00" if original.endswith("Z") else original
        parsed = datetime.fromisoformat(normalized)
        basis = "source-timezone"
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
            basis = "assumed-utc"
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds"), original, basis
    except (OSError, OverflowError, ValueError):
        return utc_now(), original, "unparseable-source-time"


def _hash_file(path: Path) -> Tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with _open_regular_binary(path) as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
            if size > MAX_HASH_FILE_BYTES:
                raise SessionError(f"input exceeds the {MAX_HASH_FILE_BYTES}-byte hashing limit: {path}")
    return digest.hexdigest(), size


def _hash_file_bounded(path: Path, max_bytes: int) -> Tuple[str, int]:
    before = _inspect_session_path(path)
    if before.st_size > max_bytes:
        raise SessionError(f"input exceeds the {max_bytes}-byte processing limit: {path}")
    digest, size = _hash_file(path)
    if size > max_bytes:
        raise SessionError(f"input exceeds the {max_bytes}-byte processing limit: {path}")
    return digest, size


def _sqlite_content_state(path: Path) -> Dict[str, Tuple[str, int]]:
    """Fingerprint durable SQLite content (main DB plus transactional sidecars)."""

    state = {"database": _hash_file_bounded(path, MAX_VERIFY_SQLITE_BYTES)}
    remaining_bytes = MAX_VERIFY_SQLITE_BYTES - state["database"][1]
    for label, candidate in (
        ("wal", Path(f"{path}-wal")),
        ("journal", Path(f"{path}-journal")),
    ):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ArtifactSecurityError(f"refusing symlink SQLite sidecar: {candidate}")
        if not stat.S_ISREG(info.st_mode):
            raise ArtifactSecurityError(f"SQLite sidecar is not a regular file: {candidate}")
        try:
            state[label] = _hash_file_bounded(candidate, remaining_bytes)
            remaining_bytes -= state[label][1]
        except FileNotFoundError as exc:
            raise SessionError(f"SQLite sidecar changed while it was being fingerprinted: {candidate}") from exc
    return state


def _sqlite_content_fingerprint(state: Dict[str, Tuple[str, int]]) -> str:
    encoded = _json(
        [
            {"component": name, "sha256": digest, "size_bytes": size}
            for name, (digest, size) in sorted(state.items())
        ]
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _same_file(first: Path, second: Path) -> bool:
    """Compare paths without requiring a missing destination to exist."""

    if first == second:
        return True
    try:
        return os.path.samefile(first, second)
    except OSError:
        return False


def _publish_new_private_file(temporary: Path, destination: Path, label: str) -> None:
    """Publish with create-if-absent semantics, closing the lstat/replace race."""

    try:
        os.link(temporary, destination, follow_symlinks=False)
    except FileExistsError as exc:
        raise SessionError(f"{label} destination appeared during publication: {destination}") from exc
    except OSError as exc:
        raise SessionError(f"cannot publish {label} destination atomically: {destination}: {exc}") from exc
    temporary.unlink()
    verify_private_artifact(destination, repair_mode=False)


def _entity_id(session_id: str, entity_type: str, key: str) -> str:
    digest = hashlib.sha256(f"{session_id}\0{entity_type}\0{key}".encode("utf-8", errors="replace")).hexdigest()[:24]
    return f"{entity_type[:4]}_{digest}"


def _inspect_session_path(path: Path) -> os.stat_result:
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise SessionError(f"session does not exist: {path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise ArtifactSecurityError(f"refusing symlink session path: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ArtifactSecurityError(f"session path is not a regular file: {path}")
    return info


def _open_regular_binary(path: Path) -> BinaryIO:
    """Open a regular input without following a swapped final symlink."""

    before = _inspect_session_path(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise ArtifactSecurityError(f"refusing symlink input path: {path}") from exc
        raise
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ArtifactSecurityError(f"input path is not a regular file: {path}")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ArtifactSecurityError(f"input path changed while it was being opened: {path}")
        return os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise


def _ensure_sqlite_path(path: Path) -> bool:
    """Prepare a destination and return whether it is an empty new database."""

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags, PRIVATE_FILE_MODE)
        except FileExistsError as exc:
            raise ArtifactSecurityError(f"session destination appeared while it was being created: {path}") from exc
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ArtifactSecurityError(f"session destination is not a regular file: {path}")
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
        finally:
            os.close(descriptor)
        return True
    if stat.S_ISLNK(info.st_mode):
        raise ArtifactSecurityError(f"refusing symlink session destination: {path}")
    if not stat.S_ISREG(info.st_mode):
        raise ArtifactSecurityError(f"session destination is not a regular file: {path}")
    return info.st_size == 0


def _sqlite_uri(path: Path, mode: str) -> str:
    # Path.as_uri() percent-encodes URI delimiters such as ?, # and %, so a
    # caller-controlled filename cannot alter SQLite's query parameters.
    return f"{path.as_uri()}?mode={mode}&nofollow=1"


def _read_only_sqlite_uri(path: Path) -> str:
    return _sqlite_uri(path, "ro")


def _inspect_sqlite_sidecars(path: Path) -> None:
    for candidate in (Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal")):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ArtifactSecurityError(f"refusing symlink SQLite sidecar: {candidate}")
        if not stat.S_ISREG(info.st_mode):
            raise ArtifactSecurityError(f"SQLite sidecar is not a regular file: {candidate}")


def _harden_sqlite_files(
    path: Path,
    expected_database_identity: Optional[Tuple[int, int]] = None,
) -> None:
    for candidate in (path, Path(f"{path}-wal"), Path(f"{path}-shm"), Path(f"{path}-journal")):
        try:
            before = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(before.st_mode):
            raise ArtifactSecurityError(f"refusing symlink SQLite file: {candidate}")
        if not stat.S_ISREG(before.st_mode):
            raise ArtifactSecurityError(f"SQLite file is not a regular file: {candidate}")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(candidate, flags)
        except FileNotFoundError:
            continue
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise ArtifactSecurityError(f"refusing symlink SQLite file: {candidate}") from exc
            raise
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode):
                raise ArtifactSecurityError(f"SQLite file is not a regular file: {candidate}")
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ArtifactSecurityError(f"SQLite file changed while being hardened: {candidate}")
            if candidate == path and expected_database_identity is not None:
                if (opened.st_dev, opened.st_ino) != expected_database_identity:
                    raise ArtifactSecurityError(f"session path was replaced while open: {path}")
            os.fchmod(descriptor, PRIVATE_FILE_MODE)
            if stat.S_IMODE(os.fstat(descriptor).st_mode) != PRIVATE_FILE_MODE:
                raise ArtifactSecurityError(f"SQLite file permissions are not owner-only: {candidate}")
        finally:
            os.close(descriptor)


class SessionStore:
    """Versioned, portable SQLite storage for correlated network observations."""

    def __init__(self, path: str, *, read_only: bool = False) -> None:
        # Keep the final path component unresolved so the private-artifact
        # boundary can detect and refuse a caller-supplied symlink.
        self.path = Path(os.path.abspath(str(Path(path).expanduser())))
        self.read_only = read_only
        self.schema_version = SESSION_SCHEMA_VERSION
        self.connection: sqlite3.Connection
        self._database_identity: Optional[Tuple[int, int]] = None
        connection: Optional[sqlite3.Connection] = None
        try:
            _inspect_sqlite_sidecars(self.path)
            if read_only:
                prepared = _inspect_session_path(self.path)
                connection = sqlite3.connect(_read_only_sqlite_uri(self.path), uri=True, timeout=5.0)
            else:
                is_empty = _ensure_sqlite_path(self.path)
                prepared = _inspect_session_path(self.path)
                if not is_empty:
                    validation_connection = sqlite3.connect(
                        _read_only_sqlite_uri(self.path), uri=True, timeout=5.0
                    )
                    try:
                        validation_connection.row_factory = sqlite3.Row
                        if hasattr(validation_connection, "setlimit"):
                            validation_connection.setlimit(
                                _SQLITE_LIMIT_LENGTH,
                                MAX_SQLITE_VALUE_BYTES,
                            )
                            validation_connection.setlimit(_SQLITE_LIMIT_ATTACHED, 0)
                        validation_connection.execute("PRAGMA query_only=ON")
                        validation_connection.execute("PRAGMA trusted_schema=OFF")
                        validation_connection.execute("PRAGMA cell_size_check=ON")
                        self.connection = validation_connection
                        self.schema_version = self._validate_schema()
                        if self.schema_version != SESSION_SCHEMA_VERSION:
                            raise SessionError(
                                f"session schema {self.schema_version} is read-only; migrate it to schema "
                                f"{SESSION_SCHEMA_VERSION} before writing"
                            )
                    finally:
                        validation_connection.close()
                    after_validation = _inspect_session_path(self.path)
                    if (prepared.st_dev, prepared.st_ino) != (
                        after_validation.st_dev,
                        after_validation.st_ino,
                    ):
                        raise ArtifactSecurityError(
                            f"session path changed while it was being validated: {self.path}"
                        )
                    _inspect_sqlite_sidecars(self.path)
                connection = sqlite3.connect(_sqlite_uri(self.path, "rw"), uri=True, timeout=5.0)
            after_open = _inspect_session_path(self.path)
            if (prepared.st_dev, prepared.st_ino) != (after_open.st_dev, after_open.st_ino):
                raise ArtifactSecurityError(f"session path changed while SQLite was opening it: {self.path}")
            self._database_identity = (after_open.st_dev, after_open.st_ino)
            self.connection = connection
            self.connection.row_factory = sqlite3.Row
            if hasattr(self.connection, "setlimit"):
                self.connection.setlimit(_SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)
                self.connection.setlimit(_SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024)
                self.connection.setlimit(_SQLITE_LIMIT_ATTACHED, 0)
            self.connection.execute("PRAGMA busy_timeout=5000")
            self.connection.execute("PRAGMA trusted_schema=OFF")
            self.connection.execute("PRAGMA recursive_triggers=OFF")
            self.connection.execute("PRAGMA cell_size_check=ON")
            if read_only:
                self.connection.execute("PRAGMA query_only=ON")
                self.schema_version = self._validate_schema()
            elif is_empty:
                self.connection.execute("PRAGMA foreign_keys=ON")
                self._initialize()
                self.connection.execute("PRAGMA journal_mode=WAL")
                self.connection.execute("PRAGMA synchronous=NORMAL")
                _harden_sqlite_files(self.path, self._database_identity)
            else:
                # Validate before changing permissions, journal mode, schema, or
                # any other state in a caller-supplied SQLite file.
                self.schema_version = self._validate_schema()
                if self.schema_version != SESSION_SCHEMA_VERSION:
                    raise SessionError(
                        f"session schema {self.schema_version} is read-only; migrate it to schema "
                        f"{SESSION_SCHEMA_VERSION} before writing"
                    )
                _harden_sqlite_files(self.path, self._database_identity)
                self.connection.execute("PRAGMA foreign_keys=ON")
                self.connection.execute("PRAGMA journal_mode=WAL")
                self.connection.execute("PRAGMA synchronous=NORMAL")
                _harden_sqlite_files(self.path, self._database_identity)
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def __enter__(self) -> "SessionStore":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        try:
            if exc_type is None and not self.read_only:
                self.connection.commit()
            elif not self.read_only:
                self.connection.rollback()
        finally:
            self.close()

    def close(self) -> None:
        identity_error: Optional[Exception] = None
        try:
            self._assert_database_identity()
        except Exception as exc:
            identity_error = exc
        if not self.read_only and identity_error is None:
            try:
                self.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
        self.connection.close()
        if not self.read_only and identity_error is None:
            _harden_sqlite_files(self.path, self._database_identity)
        if identity_error is not None:
            raise identity_error

    def _assert_database_identity(self) -> None:
        if self._database_identity is None:
            return
        current = _inspect_session_path(self.path)
        if (current.st_dev, current.st_ino) != self._database_identity:
            raise ArtifactSecurityError(f"session path was replaced while open: {self.path}")

    def _initialize(self) -> None:
        self.connection.executescript(
            f"""
            PRAGMA application_id={SQLITE_APPLICATION_ID};
            PRAGMA user_version={SQLITE_USER_VERSION};
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS schema_info (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                wirescope_version TEXT NOT NULL,
                host_json TEXT NOT NULL,
                config_json TEXT NOT NULL,
                summary_json TEXT NOT NULL DEFAULT '{{}}'
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                source_path TEXT NOT NULL,
                source_type TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{{}}',
                UNIQUE(session_id, sha256)
            );
            CREATE INDEX IF NOT EXISTS artifacts_hash_idx ON artifacts(session_id, sha256);
            CREATE TABLE IF NOT EXISTS entities (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                entity_type TEXT NOT NULL,
                entity_key TEXT NOT NULL,
                label TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                attributes_json TEXT NOT NULL DEFAULT '{{}}',
                UNIQUE(session_id, entity_type, entity_key),
                UNIQUE(session_id, id)
            );
            CREATE INDEX IF NOT EXISTS entities_type_idx ON entities(session_id, entity_type, last_seen);
            CREATE TABLE IF NOT EXISTS relations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                source_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confidence REAL,
                rule_id TEXT NOT NULL DEFAULT 'direct-observation',
                rule_version TEXT NOT NULL DEFAULT '1',
                confidence_basis TEXT,
                evidence_json TEXT NOT NULL DEFAULT '{{}}',
                UNIQUE(session_id, source_id, relation_type, target_id),
                FOREIGN KEY(session_id, source_id) REFERENCES entities(session_id, id),
                FOREIGN KEY(session_id, target_id) REFERENCES entities(session_id, id)
            );
            CREATE INDEX IF NOT EXISTS relations_source_idx ON relations(session_id, source_id, relation_type);
            CREATE INDEX IF NOT EXISTS relations_target_idx ON relations(session_id, target_id, relation_type);
            CREATE TABLE IF NOT EXISTS events (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                schema_version INTEGER NOT NULL,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                timestamp TEXT NOT NULL,
                source TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                entity_id TEXT,
                correlation_id TEXT,
                artifact_id TEXT,
                source_index INTEGER,
                original_timestamp TEXT,
                payload_json TEXT NOT NULL,
                FOREIGN KEY(session_id, entity_id) REFERENCES entities(session_id, id),
                FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
            );
            CREATE INDEX IF NOT EXISTS events_time_idx ON events(session_id, timestamp, sequence);
            CREATE INDEX IF NOT EXISTS events_type_idx ON events(session_id, event_type, source);
            CREATE INDEX IF NOT EXISTS events_entity_idx ON events(session_id, entity_id, timestamp);
            CREATE INDEX IF NOT EXISTS events_correlation_idx ON events(session_id, correlation_id, timestamp);
            CREATE INDEX IF NOT EXISTS events_artifact_idx ON events(artifact_id, source_index);
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                timestamp TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL,
                entity_id TEXT REFERENCES entities(id),
                evidence_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                pack_id TEXT,
                pack_version TEXT,
                limitations_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'open'
            );
            INSERT INTO schema_info(component, version) VALUES('session', {SESSION_SCHEMA_VERSION});
            INSERT INTO schema_info(component, version) VALUES('event', {EVENT_SCHEMA_VERSION});
            COMMIT;
            """
        )
        self.connection.commit()

    def _validate_schema(self) -> int:
        try:
            application_id = int(self.connection.execute("PRAGMA application_id").fetchone()[0])
            user_version = int(self.connection.execute("PRAGMA user_version").fetchone()[0])
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise SessionError(f"not a valid WireScope session database: {self.path}") from exc
        if application_id != SQLITE_APPLICATION_ID:
            raise SessionError(
                f"refusing foreign SQLite database (application_id={application_id}): {self.path}"
            )
        if user_version > SQLITE_USER_VERSION:
            raise SessionError(
                f"session schema {user_version} is newer than supported schema {SQLITE_USER_VERSION}: {self.path}"
            )
        if user_version not in SUPPORTED_SESSION_SCHEMA_VERSIONS:
            raise SessionError(
                f"unsupported session schema {user_version}; supported schemas are "
                f"{', '.join(str(value) for value in SUPPORTED_SESSION_SCHEMA_VERSIONS)}: {self.path}"
            )
        try:
            versions = {
                str(row["component"]): int(row["version"])
                for row in self.connection.execute("SELECT component, version FROM schema_info LIMIT 101")
            }
        except (sqlite3.Error, TypeError, ValueError) as exc:
            raise SessionError(f"WireScope schema metadata is missing or invalid: {self.path}") from exc
        session_component = versions.get("session")
        event_component = versions.get("event")
        if session_component != user_version:
            raise SessionError(
                f"session schema metadata {session_component!r} does not match SQLite user_version {user_version}"
            )
        if event_component not in SUPPORTED_EVENT_SCHEMA_VERSIONS:
            raise SessionError(
                f"unsupported event schema {event_component}; supported schemas are "
                f"{', '.join(str(value) for value in SUPPORTED_EVENT_SCHEMA_VERSIONS)}"
            )

        required_columns = {
            "sessions": {"id", "title", "source", "status", "started_at", "ended_at"},
            "metadata": {"key", "value_json"},
            "entities": {"id", "session_id", "entity_type", "entity_key", "attributes_json"},
            "relations": {"id", "session_id", "source_id", "relation_type", "target_id"},
            "events": {"sequence", "event_id", "schema_version", "session_id", "event_type", "payload_json"},
            "findings": {"id", "session_id", "rule_id", "severity", "evidence_json"},
        }
        if user_version >= 2:
            required_columns.update(
                {
                    "artifacts": {"id", "session_id", "sha256", "source_type", "metadata_json"},
                    "events": required_columns["events"] | {"artifact_id", "source_index", "original_timestamp"},
                    "relations": required_columns["relations"] | {"rule_id", "rule_version", "confidence_basis"},
                    "findings": required_columns["findings"] | {"pack_id", "pack_version", "limitations_json"},
                }
            )
        try:
            object_types = {
                str(row["name"]): str(row["type"])
                for row in self.connection.execute(
                    "SELECT name, type FROM sqlite_schema WHERE name IN (%s)"
                    % ",".join("?" for _name in required_columns),
                    tuple(required_columns),
                )
            }
        except sqlite3.Error as exc:
            raise SessionError(f"cannot inspect WireScope schema objects: {self.path}") from exc
        invalid_objects = sorted(
            name for name in required_columns if object_types.get(name) != "table"
        )
        if invalid_objects:
            raise SessionError(
                "WireScope schema requires regular tables: " + ", ".join(invalid_objects)
            )
        for table, required in required_columns.items():
            try:
                columns = {str(row["name"]) for row in self.connection.execute(f'PRAGMA table_info("{table}")')}
            except sqlite3.Error as exc:
                raise SessionError(f"cannot inspect WireScope table {table}: {self.path}") from exc
            missing = required - columns
            if missing:
                raise SessionError(
                    f"WireScope schema v{user_version} table {table} is missing columns: {', '.join(sorted(missing))}"
                )
        return user_version

    def start_session(
        self,
        *,
        title: str = "WireScope session",
        source: str = "system",
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        session_id = f"ses_{uuid.uuid4().hex}"
        host = {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "node": platform.node(),
        }
        self.connection.execute(
            """INSERT INTO sessions
               (id, title, source, status, started_at, wirescope_version, host_json, config_json, summary_json)
               VALUES (?, ?, ?, 'recording', ?, ?, ?, ?, '{}')""",
            (session_id, title, source, utc_now(), __version__, _json(host), _json(config or {})),
        )
        self.set_metadata("active_session_id", session_id)
        self.connection.commit()
        return session_id

    def active_session_id(self) -> Optional[str]:
        value = self.get_metadata("active_session_id")
        if isinstance(value, str):
            row = self.connection.execute("SELECT id FROM sessions WHERE id=?", (value,)).fetchone()
            if row:
                return value
        row = self.connection.execute("SELECT id FROM sessions ORDER BY started_at DESC LIMIT 1").fetchone()
        return str(row["id"]) if row else None

    def _require_session_id(self, session_id: Optional[str] = None) -> str:
        active = session_id or self.active_session_id()
        if not active:
            raise SessionError("session database does not contain a recording")
        return active

    def finish_session(self, session_id: str, summary: Optional[Dict[str, Any]] = None, *, status: str = "complete") -> None:
        cursor = self.connection.execute(
            "UPDATE sessions SET ended_at=?, status=?, summary_json=? WHERE id=?",
            (utc_now(), status, _json(summary or {}), session_id),
        )
        if cursor.rowcount != 1:
            raise SessionError(f"session not found: {session_id}")
        self.connection.commit()
        self._assert_database_identity()
        _harden_sqlite_files(self.path, self._database_identity)

    def set_metadata(self, key: str, value: Any) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO metadata(key, value_json) VALUES(?, ?)",
            (key, _json(value)),
        )

    def get_metadata(self, key: str, fallback: Any = None) -> Any:
        row = self.connection.execute("SELECT value_json FROM metadata WHERE key=?", (key,)).fetchone()
        return _load_json(row["value_json"], fallback) if row else fallback

    def upsert_entity(
        self,
        entity_type: str,
        key: str,
        *,
        label: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        observed_at: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> str:
        active = self._require_session_id(session_id)
        timestamp = observed_at or utc_now()
        entity_id = _entity_id(active, entity_type, key)
        existing = self.connection.execute("SELECT attributes_json FROM entities WHERE id=?", (entity_id,)).fetchone()
        merged = _load_json(existing["attributes_json"], {}) if existing else {}
        if attributes:
            merged.update(attributes)
        self.connection.execute(
            """INSERT INTO entities(id, session_id, entity_type, entity_key, label, first_seen, last_seen, attributes_json)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   label=excluded.label,
                   first_seen=MIN(entities.first_seen, excluded.first_seen),
                   last_seen=MAX(entities.last_seen, excluded.last_seen),
                   attributes_json=excluded.attributes_json""",
            (entity_id, active, entity_type, key, label or key, timestamp, timestamp, _json(merged)),
        )
        return entity_id

    def link(
        self,
        source_id: str,
        relation_type: str,
        target_id: str,
        *,
        confidence: Optional[float] = None,
        evidence: Optional[Dict[str, Any]] = None,
        rule_id: str = "direct-observation",
        rule_version: str = "1",
        confidence_basis: Optional[str] = None,
        observed_at: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        active = self._require_session_id(session_id)
        timestamp = observed_at or utc_now()
        self.connection.execute(
            """INSERT INTO relations
               (session_id, source_id, relation_type, target_id, first_seen, last_seen, confidence,
                rule_id, rule_version, confidence_basis, evidence_json)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id, source_id, relation_type, target_id) DO UPDATE SET
                   first_seen=MIN(relations.first_seen, excluded.first_seen),
                   last_seen=MAX(relations.last_seen, excluded.last_seen),
                   confidence=COALESCE(excluded.confidence, relations.confidence),
                   rule_id=excluded.rule_id,
                   rule_version=excluded.rule_version,
                   confidence_basis=COALESCE(excluded.confidence_basis, relations.confidence_basis),
                   evidence_json=excluded.evidence_json""",
            (
                active,
                source_id,
                relation_type,
                target_id,
                timestamp,
                timestamp,
                confidence,
                rule_id,
                rule_version,
                confidence_basis,
                _json(evidence or {}),
            ),
        )

    def add_event(self, event: EventEnvelope, *, session_id: Optional[str] = None) -> int:
        active = self._require_session_id(session_id)
        event_id = f"evt_{uuid.uuid4().hex}"
        event_type = CANONICAL_EVENT_TYPES.get(event.event_type, event.event_type)
        cursor = self.connection.execute(
            """INSERT INTO events
               (event_id, schema_version, session_id, timestamp, source, event_type, severity,
                confidence, entity_id, correlation_id, artifact_id, source_index, original_timestamp,
                payload_json)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                event.schema_version,
                active,
                event.timestamp,
                event.source,
                event_type,
                event.severity,
                event.confidence,
                event.entity_id,
                event.correlation_id,
                event.artifact_id,
                event.source_index,
                event.original_timestamp,
                _json(event.payload),
            ),
        )
        return int(cast(int, cursor.lastrowid))

    def register_artifact(
        self,
        source: str,
        *,
        source_type: str,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        allow_duplicate: bool = False,
    ) -> Dict[str, Any]:
        if self.schema_version < 2:
            raise SessionError("artifact provenance requires session schema 2")
        active = self._require_session_id(session_id)
        source_path = Path(os.path.abspath(str(Path(source).expanduser())))
        if _same_file(source_path, self.path):
            raise SessionError("a session database cannot ingest itself as a source artifact")
        info = _inspect_session_path(source_path)
        artifact_limit = MAX_HAR_FILE_BYTES if source_type == "har" else MAX_JSONL_FILE_BYTES
        digest, size = _hash_file_bounded(source_path, artifact_limit)
        existing = self.connection.execute(
            "SELECT * FROM artifacts WHERE session_id=? AND sha256=?",
            (active, digest),
        ).fetchone()
        if existing is not None and not allow_duplicate:
            raise SessionError(
                f"source was already ingested into this session (sha256={digest}); "
                "pass --allow-duplicate to ingest it again"
            )
        if existing is not None:
            return {**dict(existing), "duplicate": True}
        artifact_digest = hashlib.sha256(f"{active}\0{digest}".encode()).hexdigest()[:24]
        artifact_id = f"art_{artifact_digest}"
        self.connection.execute(
            """INSERT INTO artifacts
               (id, session_id, sha256, size_bytes, source_path, source_type, imported_at, metadata_json)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                artifact_id,
                active,
                digest,
                int(info.st_size if info.st_size == size else size),
                str(source_path),
                source_type,
                utc_now(),
                _json(metadata or {}),
            ),
        )
        return {
            "id": artifact_id,
            "session_id": active,
            "sha256": digest,
            "size_bytes": size,
            "source_path": str(source_path),
            "source_type": source_type,
            "metadata": metadata or {},
            "duplicate": False,
        }

    def artifacts(self, *, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.schema_version < 2:
            return []
        where = "WHERE session_id=?" if session_id else ""
        values: List[Any] = [session_id] if session_id else []
        rows = self.connection.execute(
            f"SELECT * FROM artifacts {where} ORDER BY imported_at, id",
            values,
        ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "metadata_json"},
                "metadata": _load_json(row["metadata_json"], {}),
            }
            for row in rows
        ]

    def add_marker(self, message: str, *, session_id: Optional[str] = None) -> int:
        if not message.strip():
            raise ValueError("marker message must not be empty")
        return self.add_event(
            EventEnvelope(event_type="user.marker", source="user", payload={"message": message.strip()}),
            session_id=session_id,
        )

    def add_finding(
        self,
        *,
        rule_id: str,
        pack_id: str,
        pack_version: str,
        title: str,
        category: str,
        severity: str,
        confidence: Optional[float],
        evidence: Sequence[Dict[str, Any]],
        limitations: Sequence[str],
        explanation: str,
        recommendation: str,
        entity_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> str:
        active = self._require_session_id(session_id)
        normalized_evidence = sorted((_json(item) for item in evidence))
        identity = _json(
            {
                "session_id": active,
                "pack_id": pack_id,
                "pack_version": pack_version,
                "rule_id": rule_id,
                "evidence": normalized_evidence,
            }
        )
        finding_id = f"fnd_{hashlib.sha256(identity.encode()).hexdigest()[:32]}"
        self.connection.execute(
            """INSERT INTO findings
               (id, session_id, timestamp, rule_id, title, category, severity, confidence,
                entity_id, evidence_json, explanation, recommendation, pack_id, pack_version,
                limitations_json)
               VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO UPDATE SET
                   title=excluded.title,
                   category=excluded.category,
                   severity=excluded.severity,
                   confidence=excluded.confidence,
                   entity_id=excluded.entity_id,
                   evidence_json=excluded.evidence_json,
                   explanation=excluded.explanation,
                   recommendation=excluded.recommendation,
                   pack_id=excluded.pack_id,
                   pack_version=excluded.pack_version,
                   limitations_json=excluded.limitations_json""",
            (
                finding_id,
                active,
                utc_now(),
                rule_id,
                title,
                category,
                severity,
                confidence,
                entity_id,
                _json(list(evidence)),
                explanation,
                recommendation,
                pack_id,
                pack_version,
                _json(list(limitations)),
            ),
        )
        return finding_id

    def commit(self) -> None:
        self.connection.commit()
        if not self.read_only:
            self._assert_database_identity()
            _harden_sqlite_files(self.path, self._database_identity)

    def timeline(
        self,
        *,
        limit: int = 100,
        event_type: Optional[str] = None,
        source: Optional[str] = None,
        entity_id: Optional[str] = None,
        session_id: Optional[str] = None,
        reverse: bool = False,
    ) -> List[Dict[str, Any]]:
        conditions: List[str] = []
        values: List[Any] = []
        if event_type:
            conditions.append("event_type LIKE ?")
            values.append(event_type.replace("*", "%"))
        if source:
            conditions.append("source=?")
            values.append(source)
        if entity_id:
            conditions.append("entity_id=?")
            values.append(entity_id)
        if session_id:
            conditions.append("session_id=?")
            values.append(session_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        order = "DESC" if reverse else "ASC"
        values.append(max(1, min(limit, 10000)))
        rows = self.connection.execute(
            f"SELECT * FROM events {where} ORDER BY sequence {order} LIMIT ?",
            values,
        ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "payload_json"},
                "payload": _load_json(row["payload_json"], {}),
            }
            for row in rows
        ]

    def entities(
        self,
        *,
        entity_type: Optional[str] = None,
        query: Optional[str] = None,
        session_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        conditions: List[str] = []
        values: List[Any] = []
        if entity_type:
            conditions.append("entity_type=?")
            values.append(entity_type)
        if query:
            conditions.append("(label LIKE ? OR entity_key LIKE ?)")
            pattern = f"%{query}%"
            values.extend((pattern, pattern))
        if session_id:
            conditions.append("session_id=?")
            values.append(session_id)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        values.append(max(1, min(limit, 10000)))
        rows = self.connection.execute(
            f"SELECT * FROM entities {where} ORDER BY last_seen DESC LIMIT ?", values
        ).fetchall()
        return [
            {
                **{key: row[key] for key in row.keys() if key != "attributes_json"},
                "attributes": _load_json(row["attributes_json"], {}),
            }
            for row in rows
        ]

    def relations(self, *, session_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        where = "WHERE r.session_id=?" if session_id else ""
        values: List[Any] = [session_id] if session_id else []
        values.append(max(1, min(limit, 50000)))
        rows = self.connection.execute(
            f"""SELECT r.*, s.entity_type AS source_type, s.label AS source_label,
                      t.entity_type AS target_type, t.label AS target_label
               FROM relations r
               JOIN entities s ON s.id=r.source_id
               JOIN entities t ON t.id=r.target_id
               {where} ORDER BY r.last_seen DESC LIMIT ?""",
            values,
        ).fetchall()
        return [
            {
                "id": row["id"],
                "session_id": row["session_id"],
                "relation": row["relation_type"],
                "source": {"id": row["source_id"], "type": row["source_type"], "label": row["source_label"]},
                "target": {"id": row["target_id"], "type": row["target_type"], "label": row["target_label"]},
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "confidence": row["confidence"],
                "confidence_band": confidence_band(row["confidence"]),
                **(
                    {
                        "rule_id": row["rule_id"],
                        "rule_version": row["rule_version"],
                        "confidence_basis": row["confidence_basis"],
                    }
                    if "rule_id" in row.keys()
                    else {}
                ),
                "evidence": _load_json(row["evidence_json"], {}),
            }
            for row in rows
        ]

    def findings(self, *, session_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        where = "WHERE session_id=?" if session_id else ""
        values: List[Any] = [session_id] if session_id else []
        values.append(max(1, min(limit, 50000)))
        rows = self.connection.execute(
            f"SELECT * FROM findings {where} ORDER BY timestamp DESC LIMIT ?", values
        ).fetchall()
        return [
            {
                **{
                    key: row[key]
                    for key in row.keys()
                    if key not in ("evidence_json", "limitations_json")
                },
                "evidence": _load_json(row["evidence_json"], []),
                "limitations": _load_json(row["limitations_json"], []) if "limitations_json" in row.keys() else [],
            }
            for row in rows
        ]

    def explain(self, entity: str, *, event_limit: int = 20) -> Dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM entities WHERE id=? OR entity_key=? OR label=? ORDER BY last_seen DESC LIMIT 1",
            (entity, entity, entity),
        ).fetchone()
        if row is None:
            row = self.connection.execute(
                "SELECT * FROM entities WHERE label LIKE ? OR entity_key LIKE ? ORDER BY last_seen DESC LIMIT 1",
                (f"%{entity}%", f"%{entity}%"),
            ).fetchone()
        if row is None:
            raise SessionError(f"entity not found: {entity}")
        entity_id = str(row["id"])
        session_id = str(row["session_id"])
        relation_rows = self.connection.execute(
            """SELECT r.*, s.entity_type AS source_type, s.label AS source_label,
                      t.entity_type AS target_type, t.label AS target_label
               FROM relations r
               JOIN entities s ON s.id=r.source_id
               JOIN entities t ON t.id=r.target_id
               WHERE r.session_id=? AND (r.source_id=? OR r.target_id=?)
               ORDER BY r.last_seen DESC""",
            (session_id, entity_id, entity_id),
        ).fetchall()
        findings = self.connection.execute(
            "SELECT * FROM findings WHERE session_id=? AND entity_id=? ORDER BY timestamp DESC", (session_id, entity_id)
        ).fetchall()
        return {
            "entity": {
                **{key: row[key] for key in row.keys() if key != "attributes_json"},
                "attributes": _load_json(row["attributes_json"], {}),
            },
            "relations": [
                {
                    "relation": item["relation_type"],
                    "source": {"id": item["source_id"], "type": item["source_type"], "label": item["source_label"]},
                    "target": {"id": item["target_id"], "type": item["target_type"], "label": item["target_label"]},
                    "confidence": item["confidence"],
                    "confidence_band": confidence_band(item["confidence"]),
                    **(
                        {
                            "rule_id": item["rule_id"],
                            "rule_version": item["rule_version"],
                            "confidence_basis": item["confidence_basis"],
                        }
                        if "rule_id" in item.keys()
                        else {}
                    ),
                    "evidence": _load_json(item["evidence_json"], {}),
                    "first_seen": item["first_seen"],
                    "last_seen": item["last_seen"],
                }
                for item in relation_rows
            ],
            "events": self.timeline(limit=event_limit, entity_id=entity_id, session_id=session_id, reverse=True),
            "findings": [
                {
                    **{
                        key: item[key]
                        for key in item.keys()
                        if key not in ("evidence_json", "limitations_json")
                    },
                    "evidence": _load_json(item["evidence_json"], []),
                    "limitations": (
                        _load_json(item["limitations_json"], [])
                        if "limitations_json" in item.keys()
                        else []
                    ),
                }
                for item in findings
            ],
        }

    def what(self, entity: str, *, event_limit: int = 100) -> Dict[str, Any]:
        """Return observations and changes directly attached to an entity."""

        explanation = self.explain(entity, event_limit=event_limit)
        entity_value = explanation["entity"]
        related_ids = {entity_value["id"]}
        for relation in explanation["relations"]:
            related_ids.add(relation["source"]["id"])
            related_ids.add(relation["target"]["id"])
        placeholders = ",".join("?" for _item in sorted(related_ids))
        values: List[Any] = sorted(related_ids)
        values.append(max(1, min(int(event_limit), 10000)))
        rows = self.connection.execute(
            f"""SELECT * FROM events
                WHERE entity_id IN ({placeholders})
                ORDER BY sequence DESC LIMIT ?""",
            values,
        ).fetchall()
        events = [
            {
                **{key: row[key] for key in row.keys() if key != "payload_json"},
                "payload": _load_json(row["payload_json"], {}),
            }
            for row in rows
        ]
        return {
            "entity": entity_value,
            "related_entity_ids": sorted(related_ids - {entity_value["id"]}),
            "events": events,
            "relations": explanation["relations"],
            "findings": explanation["findings"],
        }

    def why(self, finding: str) -> Dict[str, Any]:
        """Resolve the exact evidence that produced a finding."""

        row = self.connection.execute(
            """SELECT * FROM findings
               WHERE id=? OR rule_id=? OR title=?
               ORDER BY timestamp DESC LIMIT 1""",
            (finding, finding, finding),
        ).fetchone()
        if row is None:
            raise SessionError(f"finding not found: {finding}")
        evidence = _load_json(row["evidence_json"], [])
        references = sorted(_event_references(evidence))
        if references:
            placeholders = ",".join("?" for _item in references)
            event_rows = self.connection.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY sequence",
                references,
            ).fetchall()
        else:
            event_rows = []
        events = [
            {
                **{key: item[key] for key in item.keys() if key != "payload_json"},
                "payload": _load_json(item["payload_json"], {}),
            }
            for item in event_rows
        ]
        finding_value = {
            **{
                key: row[key]
                for key in row.keys()
                if key not in ("evidence_json", "limitations_json")
            },
            "evidence": evidence,
            "limitations": _load_json(row["limitations_json"], []) if "limitations_json" in row.keys() else [],
        }
        return {
            "finding": finding_value,
            "events": events,
            "unresolved_event_ids": sorted(set(references) - {str(item["event_id"]) for item in events}),
        }

    def who(
        self,
        entity: str,
        *,
        max_depth: int = 4,
        max_paths: int = 100,
        max_nodes: int = 500,
    ) -> Dict[str, Any]:
        """Find bounded communication paths from matching endpoints to actors."""

        depth_limit = max(1, min(int(max_depth), 8))
        path_limit = max(1, min(int(max_paths), 1000))
        node_limit = max(1, min(int(max_nodes), 5000))
        seeds = self.connection.execute(
            """SELECT * FROM entities
               WHERE id=? OR entity_key=? OR label=?
               ORDER BY last_seen DESC LIMIT 20""",
            (entity, entity, entity),
        ).fetchall()
        if not seeds:
            pattern = f"%{entity}%"
            seeds = self.connection.execute(
                """SELECT * FROM entities
                   WHERE label LIKE ? OR entity_key LIKE ?
                   ORDER BY last_seen DESC LIMIT 20""",
                (pattern, pattern),
            ).fetchall()
        if not seeds:
            raise SessionError(f"entity not found: {entity}")

        def entity_value(row: sqlite3.Row) -> Dict[str, Any]:
            return {
                **{key: row[key] for key in row.keys() if key != "attributes_json"},
                "attributes": _load_json(row["attributes_json"], {}),
            }

        def relation_value(row: sqlite3.Row) -> Dict[str, Any]:
            return {
                "id": row["id"],
                "session_id": row["session_id"],
                "relation": row["relation_type"],
                "source": {"id": row["source_id"], "type": row["source_type"], "label": row["source_label"]},
                "target": {"id": row["target_id"], "type": row["target_type"], "label": row["target_label"]},
                "confidence": row["confidence"],
                "evidence": _load_json(row["evidence_json"], {}),
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
            }

        actor_types = {"process", "http_request"}
        matches = [entity_value(row) for row in seeds]
        paths: List[Dict[str, Any]] = []
        emitted: set = set()
        expanded = 0
        discovered = 0
        for seed in seeds:
            if len(paths) >= path_limit or discovered >= node_limit:
                break
            seed_id = str(seed["id"])
            session_id = str(seed["session_id"])
            queue: Deque[Tuple[str, List[Dict[str, Any]], List[Dict[str, Any]]]] = deque(
                [(seed_id, [entity_value(seed)], [])]
            )
            visited = {seed_id}
            discovered += 1
            while queue and len(paths) < path_limit and expanded < node_limit:
                current_id, nodes, edges = queue.popleft()
                expanded += 1
                if len(edges) >= depth_limit:
                    continue
                remaining_nodes = node_limit - discovered
                if remaining_nodes <= 0:
                    continue
                relation_rows = self.connection.execute(
                    """SELECT r.*, s.entity_type AS source_type, s.label AS source_label,
                              t.entity_type AS target_type, t.label AS target_label
                       FROM relations r
                       JOIN entities s ON s.id=r.source_id
                       JOIN entities t ON t.id=r.target_id
                       WHERE r.session_id=? AND (r.source_id=? OR r.target_id=?)
                       ORDER BY r.last_seen DESC LIMIT ?""",
                    (session_id, current_id, current_id, remaining_nodes),
                ).fetchall()
                for relation in relation_rows:
                    neighbor_id = str(relation["target_id"] if relation["source_id"] == current_id else relation["source_id"])
                    if neighbor_id in visited:
                        continue
                    neighbor = self.connection.execute(
                        "SELECT * FROM entities WHERE session_id=? AND id=?",
                        (session_id, neighbor_id),
                    ).fetchone()
                    if neighbor is None:
                        continue
                    visited.add(neighbor_id)
                    discovered += 1
                    neighbor_value = entity_value(neighbor)
                    next_nodes = nodes + [neighbor_value]
                    next_edges = edges + [relation_value(relation)]
                    if neighbor["entity_type"] in actor_types:
                        identity = (seed_id, neighbor_id)
                        if identity not in emitted:
                            emitted.add(identity)
                            paths.append(
                                {
                                    "session_id": session_id,
                                    "target": entity_value(seed),
                                    "actor": neighbor_value,
                                    "hops": len(next_edges),
                                    "nodes": next_nodes,
                                    "relations": next_edges,
                                }
                            )
                            if len(paths) >= path_limit:
                                break
                    queue.append((neighbor_id, next_nodes, next_edges))
                    if discovered >= node_limit:
                        break

        return {
            "query": entity,
            "matches": matches,
            "paths": paths,
            "limits": {"max_depth": depth_limit, "max_paths": path_limit, "max_nodes": node_limit},
            "truncated": len(paths) >= path_limit or discovered >= node_limit,
        }

    def summary(self) -> Dict[str, Any]:
        session_count = int(self.connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0])
        if session_count > MAX_SUMMARY_SESSIONS:
            raise SessionError(f"summary exceeds the {MAX_SUMMARY_SESSIONS}-session limit")
        summary_text_bytes = int(
            self.connection.execute(
                """SELECT COALESCE(SUM(
                       length(title) + length(source) + length(host_json) +
                       length(config_json) + length(summary_json)
                   ), 0) FROM sessions"""
            ).fetchone()[0]
        )
        if summary_text_bytes > MAX_SUMMARY_TEXT_BYTES:
            raise SessionError(
                f"summary session metadata exceeds {MAX_SUMMARY_TEXT_BYTES} characters"
            )
        session_rows = self.connection.execute("SELECT * FROM sessions ORDER BY started_at").fetchall()
        event_type_rows = self.connection.execute(
            "SELECT event_type, COUNT(*) AS count FROM events GROUP BY event_type"
        ).fetchmany(MAX_SUMMARY_GROUPS + 1)
        event_source_rows = self.connection.execute(
            "SELECT source, COUNT(*) AS count FROM events GROUP BY source"
        ).fetchmany(MAX_SUMMARY_GROUPS + 1)
        entity_type_rows = self.connection.execute(
            "SELECT entity_type, COUNT(*) AS count FROM entities GROUP BY entity_type"
        ).fetchmany(MAX_SUMMARY_GROUPS + 1)
        if any(
            len(rows) > MAX_SUMMARY_GROUPS
            for rows in (event_type_rows, event_source_rows, entity_type_rows)
        ):
            raise SessionError(f"summary exceeds the {MAX_SUMMARY_GROUPS}-group limit")
        event_counts = {
            row["event_type"]: row["count"]
            for row in event_type_rows
        }
        source_counts = {
            row["source"]: row["count"]
            for row in event_source_rows
        }
        entity_counts = {
            row["entity_type"]: row["count"]
            for row in entity_type_rows
        }
        return {
            "schema_version": self.schema_version,
            "path": str(self.path),
            "sessions": [
                {
                    **{key: row[key] for key in row.keys() if key not in ("host_json", "config_json", "summary_json")},
                    "host": _load_json(row["host_json"], {}),
                    "config": _load_json(row["config_json"], {}),
                    "summary": _load_json(row["summary_json"], {}),
                }
                for row in session_rows
            ],
            "counts": {
                "events": self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0],
                "entities": self.connection.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
                "relations": self.connection.execute("SELECT COUNT(*) FROM relations").fetchone()[0],
                "findings": self.connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
                "artifacts": (
                    self.connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
                    if self.schema_version >= 2
                    else 0
                ),
            },
            "events_by_type": event_counts,
            "events_by_source": source_counts,
            "entities_by_type": entity_counts,
        }


def _table_columns(connection: sqlite3.Connection, table: str) -> set:
    return {str(row[1]) for row in connection.execute(f'PRAGMA table_info("{table}")')}


def _migrate_v1_to_v2(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys=OFF")
    connection.execute("BEGIN IMMEDIATE")
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS artifacts (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                source_path TEXT NOT NULL,
                source_type TEXT NOT NULL,
                imported_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(session_id, sha256)
            )
            """
        )
        connection.execute("CREATE INDEX IF NOT EXISTS artifacts_hash_idx ON artifacts(session_id, sha256)")
        additions = {
            "events": {
                "artifact_id": "artifact_id TEXT REFERENCES artifacts(id)",
                "source_index": "source_index INTEGER",
                "original_timestamp": "original_timestamp TEXT",
            },
            "relations": {
                "rule_id": "rule_id TEXT NOT NULL DEFAULT 'direct-observation'",
                "rule_version": "rule_version TEXT NOT NULL DEFAULT '1'",
                "confidence_basis": "confidence_basis TEXT",
            },
            "findings": {
                "pack_id": "pack_id TEXT",
                "pack_version": "pack_version TEXT",
                "limitations_json": "limitations_json TEXT NOT NULL DEFAULT '[]'",
            },
        }
        for table, columns in additions.items():
            existing = _table_columns(connection, table)
            for name, declaration in columns.items():
                if name not in existing:
                    connection.execute(f'ALTER TABLE "{table}" ADD COLUMN {declaration}')
        connection.execute("CREATE INDEX IF NOT EXISTS events_artifact_idx ON events(artifact_id, source_index)")
        connection.execute(
            "INSERT OR REPLACE INTO schema_info(component, version) VALUES('session', ?)",
            (SESSION_SCHEMA_VERSION,),
        )
        connection.execute(
            "INSERT OR REPLACE INTO schema_info(component, version) VALUES('event', ?)",
            (EVENT_SCHEMA_VERSION,),
        )
        connection.execute(f"PRAGMA user_version={SESSION_SCHEMA_VERSION}")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.execute("PRAGMA foreign_keys=ON")


def migrate_session(source: str, destination: str, *, overwrite: bool = False) -> Dict[str, Any]:
    """Copy and migrate a session without ever modifying the source file."""

    source_path = Path(os.path.abspath(str(Path(source).expanduser())))
    destination_path = Path(os.path.abspath(str(Path(destination).expanduser())))
    if source_path == destination_path:
        raise SessionError("migration destination must differ from the source")
    source_info = _inspect_session_path(source_path)
    source_storage_bytes = int(source_info.st_size)
    for candidate in (Path(f"{source_path}-wal"), Path(f"{source_path}-journal")):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ArtifactSecurityError(f"invalid SQLite sidecar for migration: {candidate}")
        source_storage_bytes += int(info.st_size)
    if source_storage_bytes > MAX_VERIFY_SQLITE_BYTES:
        raise SessionError(
            f"source session is {source_storage_bytes} bytes; migration limit is {MAX_VERIFY_SQLITE_BYTES} bytes"
        )
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination_info = os.lstat(destination_path)
    except FileNotFoundError:
        destination_info = None
    if destination_info is not None:
        if stat.S_ISLNK(destination_info.st_mode):
            raise ArtifactSecurityError(f"refusing symlink migration destination: {destination_path}")
        if not stat.S_ISREG(destination_info.st_mode):
            raise ArtifactSecurityError(f"migration destination is not a regular file: {destination_path}")
        if not overwrite:
            raise SessionError(f"migration destination already exists: {destination_path}; pass --overwrite to replace it")
        try:
            if os.path.samefile(source_path, destination_path):
                raise SessionError("migration destination must differ from the source")
        except FileNotFoundError:
            pass

    source_content_before = _sqlite_content_state(source_path)
    source_hash_before, source_size = source_content_before["database"]
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
        dir=str(destination_path.parent),
    )
    temporary_path = Path(temporary_name)
    os.fchmod(descriptor, PRIVATE_FILE_MODE)
    os.close(descriptor)
    destination_connection: Optional[sqlite3.Connection] = None
    source_schema = 0
    try:
        with SessionStore(str(source_path), read_only=True) as source_store:
            source_schema = source_store.schema_version
            data_version_before = int(source_store.connection.execute("PRAGMA data_version").fetchone()[0])
            destination_connection = sqlite3.connect(
                _sqlite_uri(temporary_path, "rw"), uri=True, timeout=5.0
            )
            if hasattr(destination_connection, "setlimit"):
                destination_connection.setlimit(_SQLITE_LIMIT_LENGTH, MAX_SQLITE_VALUE_BYTES)
                destination_connection.setlimit(_SQLITE_LIMIT_ATTACHED, 0)
            destination_connection.execute("PRAGMA trusted_schema=OFF")
            destination_connection.execute("PRAGMA recursive_triggers=OFF")
            source_store.connection.backup(destination_connection)
            data_version_after = int(source_store.connection.execute("PRAGMA data_version").fetchone()[0])
            if data_version_after != data_version_before:
                raise SessionError("source session changed during migration; destination was not published")
            # A backup of a WAL-mode source retains WAL mode in the database
            # header.  Switch the temporary copy to a self-contained journal
            # before renaming it, otherwise a read-only open would look for
            # sidecars under the temporary filename.
            destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            destination_connection.execute("PRAGMA journal_mode=DELETE")
            if source_schema == 1:
                _migrate_v1_to_v2(destination_connection)
            destination_connection.row_factory = sqlite3.Row
            integrity = str(destination_connection.execute("PRAGMA integrity_check").fetchone()[0])
            if integrity.lower() != "ok":
                raise SessionError(f"migrated session failed integrity_check: {integrity}")
            foreign_rows = destination_connection.execute("PRAGMA foreign_key_check").fetchall()
            if foreign_rows:
                raise SessionError(f"migrated session has {len(foreign_rows)} foreign-key violations")
            destination_connection.commit()
            destination_connection.close()
            destination_connection = None
        source_content_after = _sqlite_content_state(source_path)
        if source_content_after != source_content_before:
            raise SessionError("source session changed during migration; destination was not published")
        os.chmod(temporary_path, PRIVATE_FILE_MODE)
        with temporary_path.open("rb") as stream:
            os.fsync(stream.fileno())
        verify_private_artifact(temporary_path, repair_mode=False)
        verification = verify_session(str(temporary_path))
        if not verification["passed"]:
            raise SessionError(f"migrated session failed verification: {verification['checks']}")
        if destination_info is None:
            _publish_new_private_file(temporary_path, destination_path, "migration")
        else:
            current_destination = os.lstat(destination_path)
            if stat.S_ISLNK(current_destination.st_mode) or not stat.S_ISREG(current_destination.st_mode):
                raise ArtifactSecurityError(f"migration destination changed type: {destination_path}")
            if (current_destination.st_dev, current_destination.st_ino) != (
                destination_info.st_dev,
                destination_info.st_ino,
            ):
                raise SessionError(f"migration destination changed during migration: {destination_path}")
            os.replace(temporary_path, destination_path)
        verify_private_artifact(destination_path, repair_mode=False)
    except Exception:
        if destination_connection is not None:
            destination_connection.close()
        temporary_path.unlink(missing_ok=True)
        raise

    with SessionStore(str(destination_path), read_only=True) as migrated:
        summary = migrated.summary()
    return {
        "source": str(source_path),
        "destination": str(destination_path),
        "source_schema_version": source_schema,
        "destination_schema_version": SESSION_SCHEMA_VERSION,
        "source_sha256": source_hash_before,
        "source_snapshot_sha256": _sqlite_content_fingerprint(source_content_before),
        "source_unchanged": True,
        "summary": summary,
    }


def _event_references(value: Any) -> set:
    references = set()
    pending = [value]
    visited = 0
    while pending:
        current = pending.pop()
        visited += 1
        if visited > MAX_EVIDENCE_NODES:
            raise SessionError(f"evidence structure exceeds {MAX_EVIDENCE_NODES} nodes")
        if isinstance(current, dict):
            for key, item in current.items():
                if key in ("event_id", "evidence_event_id") and isinstance(item, str) and item.startswith("evt_"):
                    references.add(item)
                elif key in ("event_ids", "evidence_ids") and isinstance(item, list):
                    for entry in item:
                        if isinstance(entry, str) and entry.startswith("evt_"):
                            references.add(entry)
                            if len(references) > MAX_EVIDENCE_REFERENCES:
                                raise SessionError(
                                    f"evidence exceeds {MAX_EVIDENCE_REFERENCES} event references"
                                )
                if len(references) > MAX_EVIDENCE_REFERENCES:
                    raise SessionError(f"evidence exceeds {MAX_EVIDENCE_REFERENCES} event references")
                if isinstance(item, (dict, list)):
                    if visited + len(pending) >= MAX_EVIDENCE_NODES:
                        raise SessionError(f"evidence structure exceeds {MAX_EVIDENCE_NODES} nodes")
                    pending.append(item)
        elif isinstance(current, list):
            for item in current:
                if not isinstance(item, (dict, list)):
                    continue
                if visited + len(pending) >= MAX_EVIDENCE_NODES:
                    raise SessionError(f"evidence structure exceeds {MAX_EVIDENCE_NODES} nodes")
                pending.append(item)
    return references


def verify_session(path: str) -> Dict[str, Any]:
    """Run non-mutating schema, integrity, permission, and provenance checks."""

    session_path = Path(os.path.abspath(str(Path(path).expanduser())))
    checks: List[Dict[str, Any]] = []

    def check(name: str, passed: bool, detail: str, *, count: Optional[int] = None) -> None:
        item: Dict[str, Any] = {"name": name, "passed": bool(passed), "detail": detail}
        if count is not None:
            item["count"] = count
        checks.append(item)

    for candidate in (
        session_path,
        Path(f"{session_path}-wal"),
        Path(f"{session_path}-shm"),
        Path(f"{session_path}-journal"),
    ):
        if candidate != session_path and not candidate.exists():
            continue
        try:
            verify_private_artifact(candidate, repair_mode=False)
            check(f"private-permissions:{candidate.name}", True, "regular owner-only file (0600)")
        except (OSError, ArtifactSecurityError) as exc:
            check(f"private-permissions:{candidate.name}", False, str(exc))

    sqlite_bytes = 0
    size_inspection_safe = True
    for candidate in (
        session_path,
        Path(f"{session_path}-wal"),
        Path(f"{session_path}-journal"),
    ):
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            size_inspection_safe = False
            continue
        sqlite_bytes += int(info.st_size)
    bounded_size = size_inspection_safe and sqlite_bytes <= MAX_VERIFY_SQLITE_BYTES
    check(
        "resource-limits",
        bounded_size,
        f"SQLite content is {sqlite_bytes} bytes (limit {MAX_VERIFY_SQLITE_BYTES})"
        if size_inspection_safe
        else "SQLite path or sidecar is not a regular file",
        count=sqlite_bytes,
    )
    if not bounded_size:
        return {
            "schema_version": None,
            "path": str(session_path),
            "passed": False,
            "checks": checks,
            "counts": {},
        }

    schema_version: Optional[int] = None
    counts: Dict[str, int] = {}
    try:
        with SessionStore(str(session_path), read_only=True) as store:
            schema_version = store.schema_version
            check("schema", True, f"supported WireScope schema {schema_version}")
            integrity_rows = store.connection.execute("PRAGMA integrity_check(100)").fetchmany(101)
            integrity_messages = [str(row[0]) for row in integrity_rows]
            integrity_ok = integrity_messages == ["ok"]
            check("sqlite-integrity", integrity_ok, "; ".join(integrity_messages[:10]))

            foreign_rows = store.connection.execute("PRAGMA foreign_key_check").fetchmany(101)
            if not foreign_rows:
                foreign_detail = "no dangling foreign keys"
            elif len(foreign_rows) == 101:
                foreign_detail = f"at least {len(foreign_rows)} violations"
            else:
                foreign_detail = f"{len(foreign_rows)} violations"
            check(
                "foreign-keys",
                not foreign_rows,
                foreign_detail,
                count=len(foreign_rows),
            )
            dangling_relations = int(
                store.connection.execute(
                    """SELECT COUNT(*) FROM relations r
                       LEFT JOIN entities s ON s.session_id=r.session_id AND s.id=r.source_id
                       LEFT JOIN entities t ON t.session_id=r.session_id AND t.id=r.target_id
                       WHERE s.id IS NULL OR t.id IS NULL"""
                ).fetchone()[0]
            )
            check(
                "relation-endpoints",
                dangling_relations == 0,
                "all relation endpoints exist" if not dangling_relations else f"{dangling_relations} dangling relations",
                count=dangling_relations,
            )

            for table in ("sessions", "artifacts", "entities", "relations", "events", "findings"):
                if table == "artifacts" and schema_version < 2:
                    counts[table] = 0
                else:
                    counts[table] = int(store.connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])

            json_columns = {
                "sessions": ("host_json", "config_json", "summary_json"),
                "metadata": ("value_json",),
                "entities": ("attributes_json",),
                "relations": ("evidence_json",),
                "events": ("payload_json",),
                "findings": ("evidence_json",),
            }
            if schema_version >= 2:
                json_columns["artifacts"] = ("metadata_json",)
                json_columns["findings"] = ("evidence_json", "limitations_json")
            invalid_json = 0
            oversized_json = 0
            try:
                json_valid_supported = bool(
                    store.connection.execute("SELECT json_valid('null')").fetchone()[0]
                )
            except sqlite3.Error:
                json_valid_supported = False
            for table, columns in json_columns.items():
                for column in columns:
                    oversized_json += int(
                        store.connection.execute(
                            f'SELECT COUNT(*) FROM "{table}" '
                            f'WHERE typeof("{column}") != \'text\' OR length("{column}") > ?',
                            (MAX_JSON_VALUE_CHARS,),
                        ).fetchone()[0]
                    )
                    if json_valid_supported:
                        invalid_json += int(
                            store.connection.execute(
                                f'SELECT COUNT(*) FROM "{table}" '
                                f'WHERE length("{column}") <= ? AND json_valid("{column}") != 1',
                                (MAX_JSON_VALUE_CHARS,),
                            ).fetchone()[0]
                        )
                    else:
                        for row in store.connection.execute(
                            f'SELECT "{column}" FROM "{table}" '
                            f'WHERE typeof("{column}") = \'text\' AND length("{column}") <= ?',
                            (MAX_JSON_VALUE_CHARS,),
                        ):
                            try:
                                json.loads(
                                    row[0],
                                    parse_constant=_reject_json_constant,
                                )
                            except (TypeError, ValueError, RecursionError):
                                invalid_json += 1
            check(
                "json-fields",
                invalid_json == 0 and oversized_json == 0,
                "all stored JSON fields are valid and bounded"
                if invalid_json == 0 and oversized_json == 0
                else f"{invalid_json} invalid and {oversized_json} oversized JSON fields",
                count=invalid_json + oversized_json,
            )

            if counts["events"] > MAX_VERIFY_REFERENCE_EVENTS:
                check(
                    "evidence-references",
                    False,
                    f"reference verification is limited to {MAX_VERIFY_REFERENCE_EVENTS} events",
                    count=counts["events"],
                )
            else:
                event_ids = {str(row[0]) for row in store.connection.execute("SELECT event_id FROM events")}
                referenced_ids = set()
                for query, fallback in (
                    ("SELECT evidence_json FROM relations", {}),
                    ("SELECT evidence_json FROM findings", []),
                ):
                    for row in store.connection.execute(query):
                        for reference in _event_references(_load_json(row[0], fallback)):
                            referenced_ids.add(reference)
                            if len(referenced_ids) > MAX_EVIDENCE_REFERENCES:
                                raise SessionError(
                                    f"verification exceeds {MAX_EVIDENCE_REFERENCES} evidence references"
                                )
                missing_evidence = sorted(referenced_ids - event_ids)
                check(
                    "evidence-references",
                    not missing_evidence,
                    "all referenced events exist"
                    if not missing_evidence
                    else f"missing: {', '.join(missing_evidence[:10])}",
                    count=len(missing_evidence),
                )
    except (SessionError, sqlite3.Error, OSError) as exc:
        check("schema", False, str(exc))

    return {
        "schema_version": schema_version,
        "path": str(session_path),
        "passed": bool(checks) and all(item["passed"] for item in checks),
        "checks": checks,
        "counts": counts,
    }


class CorrelationEngine:
    """Builds deterministic entities and relations from normalized sensor events."""

    def __init__(self, store: SessionStore, session_id: Optional[str] = None) -> None:
        self.store = store
        self.session_id = store._require_session_id(session_id)
        self._request_entities: Dict[str, str] = {}

    @staticmethod
    def _provenance(artifact_id: Optional[str], source_index: Optional[int]) -> Dict[str, Any]:
        return {
            key: value
            for key, value in {"artifact_id": artifact_id, "source_index": source_index}.items()
            if value is not None
        }

    def observe_connection(
        self,
        connection: Connection,
        event_type: str,
        *,
        timestamp: Optional[str] = None,
        artifact_id: Optional[str] = None,
        source_index: Optional[int] = None,
        original_timestamp: Optional[str] = None,
        clock_basis: Optional[str] = None,
    ) -> str:
        observed_at = timestamp or utc_now()
        provenance = self._provenance(artifact_id, source_index)
        process_key = f"{connection.pid}:{connection.process}"
        process_id = self.store.upsert_entity(
            "process",
            process_key,
            label=f"{connection.process} ({connection.pid})",
            attributes={"pid": connection.pid, "name": connection.process, "user": connection.user},
            observed_at=observed_at,
            session_id=self.session_id,
        )
        connection_id = self.store.upsert_entity(
            "connection",
            connection.key(),
            label=(connection.remote.display() if connection.remote else connection.local.display()),
            attributes=connection.to_dict(),
            observed_at=observed_at,
            session_id=self.session_id,
        )
        self.store.link(
            process_id,
            "PROCESS_OWNS_CONNECTION",
            connection_id,
            confidence=1.0,
            evidence=provenance,
            rule_id="socket-owner-exact",
            rule_version="2",
            confidence_basis="process and socket ownership observed in the same source event",
            observed_at=observed_at,
            session_id=self.session_id,
        )
        if connection.remote:
            remote_type = "ip" if _looks_like_ip(connection.remote.host) else "domain"
            remote_id = self.store.upsert_entity(
                remote_type,
                connection.remote.host,
                label=connection.remote.host,
                attributes={"port": connection.remote.port},
                observed_at=observed_at,
                session_id=self.session_id,
            )
            self.store.link(
                connection_id,
                "CONNECTION_TARGETS_ENDPOINT",
                remote_id,
                confidence=1.0,
                evidence={"remote": connection.remote.display(), **provenance},
                rule_id="socket-remote-exact",
                rule_version="2",
                confidence_basis="remote endpoint observed on the socket",
                observed_at=observed_at,
                session_id=self.session_id,
            )
        self.store.add_event(
            EventEnvelope(
                event_type=event_type,
                source="system.sockets",
                payload={"connection": connection.to_dict()},
                timestamp=observed_at,
                entity_id=connection_id,
                correlation_id=connection_id,
                artifact_id=artifact_id,
                source_index=source_index,
                original_timestamp=original_timestamp,
            ),
            session_id=self.session_id,
        )
        return connection_id

    def observe_cdp_event(
        self,
        event: Dict[str, Any],
        *,
        artifact_id: Optional[str] = None,
        source_index: Optional[int] = None,
        timestamp: Optional[str] = None,
        original_timestamp: Optional[str] = None,
        clock_basis: Optional[str] = None,
    ) -> None:
        payload_value = event.get("payload")
        method_value = event.get("method")
        if method_value is None and isinstance(payload_value, dict):
            method_value = payload_value.get("method")
        if not isinstance(method_value, str) or not method_value:
            raise ValueError("CDP event method must be a non-empty string")
        method = method_value
        params = event.get("params")
        if not isinstance(params, dict):
            params = payload_value.get("params", {}) if isinstance(payload_value, dict) else {}
        if not isinstance(params, dict):
            raise ValueError("CDP event params must be an object")
        timestamp = timestamp or str(event.get("timestamp") or utc_now())
        request_id = str(params.get("requestId") or "")
        request_key = f"{artifact_id or 'live'}:{request_id}" if request_id else ""
        provenance = self._provenance(artifact_id, source_index)
        entity_id: Optional[str] = None
        if method == "Network.requestWillBeSent":
            request = params.get("request", {}) if isinstance(params.get("request"), dict) else {}
            url = str(request.get("url") or "")
            host = urlsplit(url).hostname
            if request_id:
                entity_id = self.store.upsert_entity(
                    "http_request",
                    request_key,
                    label=f"{request.get('method', 'GET')} {url}",
                    attributes={"url": url, "method": request.get("method"), "initiator": params.get("initiator")},
                    observed_at=timestamp,
                    session_id=self.session_id,
                )
                self._request_entities[request_key] = entity_id
            if host and entity_id:
                domain_id = self.store.upsert_entity(
                    "domain", host, label=host, observed_at=timestamp, session_id=self.session_id
                )
                self.store.link(
                    entity_id,
                    "HTTP_TARGETS_DOMAIN",
                    domain_id,
                    confidence=1.0,
                    evidence=provenance,
                    rule_id="browser-request-url-exact",
                    rule_version="2",
                    confidence_basis="domain parsed from the observed request URL",
                    observed_at=timestamp,
                    session_id=self.session_id,
                )
        elif method == "Network.responseReceived" and request_id:
            entity_id = self._request_entities.get(request_key) or self.store.upsert_entity(
                "http_request", request_key, observed_at=timestamp, session_id=self.session_id
            )
            response = params.get("response", {}) if isinstance(params.get("response"), dict) else {}
            remote_ip = response.get("remoteIPAddress")
            if remote_ip:
                ip_id = self.store.upsert_entity(
                    "ip", str(remote_ip), label=str(remote_ip), observed_at=timestamp, session_id=self.session_id
                )
                self.store.link(
                    entity_id,
                    "HTTP_USES_REMOTE_IP",
                    ip_id,
                    confidence=1.0,
                    evidence={"connection_id": response.get("connectionId"), **provenance},
                    rule_id="browser-response-ip-exact",
                    rule_version="2",
                    confidence_basis="remote IP reported by the browser response",
                    observed_at=timestamp,
                    session_id=self.session_id,
                )
            security = response.get("securityDetails")
            if isinstance(security, dict):
                tls_key = f"{request_id}:{security.get('protocol')}:{security.get('cipher')}"
                tls_id = self.store.upsert_entity(
                    "tls",
                    tls_key,
                    label=str(security.get("protocol") or "TLS"),
                    attributes=security,
                    observed_at=timestamp,
                    session_id=self.session_id,
                )
                self.store.link(
                    entity_id,
                    "HTTP_USES_TLS",
                    tls_id,
                    confidence=1.0,
                    evidence=provenance,
                    rule_id="browser-security-details-exact",
                    rule_version="2",
                    confidence_basis="TLS details reported by the browser",
                    observed_at=timestamp,
                    session_id=self.session_id,
                )
        self.store.add_event(
            EventEnvelope(
                event_type=f"browser.{method}",
                source="browser.cdp",
                payload={"method": method, "params": params},
                timestamp=timestamp,
                entity_id=entity_id,
                correlation_id=request_id or None,
                artifact_id=artifact_id,
                source_index=source_index,
                original_timestamp=original_timestamp,
            ),
            session_id=self.session_id,
        )

    def observe_normalized_request(
        self,
        request: Dict[str, Any],
        *,
        source: str,
        event_type: str = "http.request.observed",
        artifact_id: Optional[str] = None,
        source_index: Optional[int] = None,
        timestamp: Optional[str] = None,
        original_timestamp: Optional[str] = None,
    ) -> str:
        observed_at = timestamp or utc_now()
        request_id = str(request.get("id") or source_index or "request")
        request_key = f"{artifact_id or source}:{request_id}"
        url = str(request.get("url") or request.get("target") or "")
        domain = str(request.get("domain") or request.get("host") or urlsplit(url).hostname or "")
        provenance = self._provenance(artifact_id, source_index)
        request_entity = self.store.upsert_entity(
            "http_request",
            request_key,
            label=f"{request.get('method', 'GET')} {url or domain}",
            attributes=request,
            observed_at=observed_at,
            session_id=self.session_id,
        )
        if domain:
            domain_entity = self.store.upsert_entity(
                "domain",
                domain,
                label=domain,
                observed_at=observed_at,
                session_id=self.session_id,
            )
            self.store.link(
                request_entity,
                "HTTP_TARGETS_DOMAIN",
                domain_entity,
                confidence=1.0,
                evidence=provenance,
                rule_id="normalized-request-domain-exact",
                rule_version="2",
                confidence_basis="domain is present in or parsed from the request",
                observed_at=observed_at,
                session_id=self.session_id,
            )
        remote_ip = request.get("remote_ip") or request.get("server_ip")
        ip_entity: Optional[str] = None
        if remote_ip and _looks_like_ip(str(remote_ip)):
            ip_entity = self.store.upsert_entity(
                "ip",
                str(remote_ip),
                label=str(remote_ip),
                observed_at=observed_at,
                session_id=self.session_id,
            )
            self.store.link(
                request_entity,
                "HTTP_USES_REMOTE_IP",
                ip_entity,
                confidence=1.0,
                evidence=provenance,
                rule_id="normalized-request-ip-exact",
                rule_version="2",
                confidence_basis="remote IP is present in the source request record",
                observed_at=observed_at,
                session_id=self.session_id,
            )
        connection_key = request.get("connection_id") or request.get("connection")
        if connection_key not in (None, ""):
            connection_entity = self.store.upsert_entity(
                "connection",
                f"{artifact_id or source}:{connection_key}",
                label=f"browser connection {connection_key}",
                attributes={"source_connection_id": connection_key},
                observed_at=observed_at,
                session_id=self.session_id,
            )
            self.store.link(
                request_entity,
                "HTTP_USES_CONNECTION",
                connection_entity,
                confidence=1.0,
                evidence=provenance,
                rule_id="source-connection-id-exact",
                rule_version="2",
                confidence_basis="request and connection share an explicit source identifier",
                observed_at=observed_at,
                session_id=self.session_id,
            )
            if ip_entity:
                self.store.link(
                    connection_entity,
                    "CONNECTION_TARGETS_ENDPOINT",
                    ip_entity,
                    confidence=1.0,
                    evidence=provenance,
                    rule_id="source-connection-ip-exact",
                    rule_version="2",
                    confidence_basis="connection identifier and remote IP occur in the same request record",
                    observed_at=observed_at,
                    session_id=self.session_id,
                )
        security = request.get("security_details")
        if isinstance(security, dict) and security:
            tls_key = f"{request_key}:{security.get('protocol')}:{security.get('cipher')}"
            tls_entity = self.store.upsert_entity(
                "tls",
                tls_key,
                label=str(security.get("protocol") or "TLS"),
                attributes=security,
                observed_at=observed_at,
                session_id=self.session_id,
            )
            self.store.link(
                request_entity,
                "HTTP_USES_TLS",
                tls_entity,
                confidence=1.0,
                evidence=provenance,
                rule_id="normalized-request-tls-exact",
                rule_version="2",
                confidence_basis="TLS details are present in the source request record",
                observed_at=observed_at,
                session_id=self.session_id,
            )
        self.store.add_event(
            EventEnvelope(
                event_type=event_type,
                source=source,
                payload={"request": request},
                timestamp=observed_at,
                entity_id=request_entity,
                correlation_id=request_id,
                artifact_id=artifact_id,
                source_index=source_index,
                original_timestamp=original_timestamp,
            ),
            session_id=self.session_id,
        )
        return request_entity

    def _observe_dns(
        self,
        event: Dict[str, Any],
        *,
        artifact_id: Optional[str],
        source_index: Optional[int],
        timestamp: str,
        original_timestamp: Optional[str],
    ) -> None:
        domain = str(event.get("domain") or "").rstrip(".")
        transaction = str(event.get("transaction_id") or source_index or "unknown")
        query_key = f"{artifact_id or 'dns'}:{transaction}:{source_index or 0}"
        provenance = self._provenance(artifact_id, source_index)
        query_entity = self.store.upsert_entity(
            "dns_query",
            query_key,
            label=f"{event.get('query_type', 'DNS')} {domain or transaction}",
            attributes={key: value for key, value in event.items() if key != "raw"},
            observed_at=timestamp,
            session_id=self.session_id,
        )
        domain_entity: Optional[str] = None
        if domain:
            domain_entity = self.store.upsert_entity(
                "domain", domain, label=domain, observed_at=timestamp, session_id=self.session_id
            )
            self.store.link(
                query_entity,
                "DNS_QUERIES_DOMAIN",
                domain_entity,
                confidence=1.0,
                evidence={"transaction_id": transaction, **provenance},
                rule_id="dns-query-name-exact",
                rule_version="2",
                confidence_basis="query name and transaction were observed in the DNS event",
                observed_at=timestamp,
                session_id=self.session_id,
            )
        answers = event.get("answers") or event.get("records") or []
        if isinstance(answers, (str, dict)):
            answers = [answers]
        if domain_entity and isinstance(answers, list):
            for answer in answers:
                if isinstance(answer, dict):
                    address = answer.get("address") or answer.get("data") or answer.get("value")
                    ttl = answer.get("ttl")
                else:
                    address = answer
                    ttl = event.get("ttl")
                if not address or not _looks_like_ip(str(address)):
                    continue
                ip_entity = self.store.upsert_entity(
                    "ip", str(address), label=str(address), observed_at=timestamp, session_id=self.session_id
                )
                self.store.link(
                    domain_entity,
                    "DNS_RESOLVED_TO_IP",
                    ip_entity,
                    confidence=0.90,
                    evidence={"transaction_id": transaction, "ttl": ttl, **provenance},
                    rule_id="dns-answer-within-ttl",
                    rule_version="2",
                    confidence_basis="IP is an explicit answer for this domain; validity is bounded by TTL",
                    observed_at=timestamp,
                    session_id=self.session_id,
                )
        self.store.add_event(
            EventEnvelope(
                event_type="dns.observed",
                source="packets.dns",
                payload={key: value for key, value in event.items() if key not in ("type", "timestamp")},
                timestamp=timestamp,
                entity_id=query_entity,
                correlation_id=transaction,
                artifact_id=artifact_id,
                source_index=source_index,
                original_timestamp=original_timestamp,
            ),
            session_id=self.session_id,
        )

    def observe_generic(
        self,
        event: Dict[str, Any],
        *,
        artifact_id: Optional[str] = None,
        source_index: Optional[int] = None,
        timestamp: Optional[str] = None,
        original_timestamp: Optional[str] = None,
        clock_basis: Optional[str] = None,
    ) -> None:
        raw_type = str(event.get("type") or "unknown")
        if raw_type == "cdp_event" or event.get("method"):
            self.observe_cdp_event(
                event,
                artifact_id=artifact_id,
                source_index=source_index,
                timestamp=timestamp,
                original_timestamp=original_timestamp,
                clock_basis=clock_basis,
            )
            return
        event_type = CANONICAL_EVENT_TYPES.get(raw_type, raw_type)
        timestamp = timestamp or str(event.get("timestamp") or utc_now())
        if raw_type == "dns_packet":
            self._observe_dns(
                event,
                artifact_id=artifact_id,
                source_index=source_index,
                timestamp=timestamp,
                original_timestamp=original_timestamp,
            )
            return
        if raw_type == "proxy_request":
            self.observe_normalized_request(
                {
                    "id": str(source_index or event.get("request_id") or "proxy"),
                    "url": event.get("target"),
                    "domain": event.get("host"),
                    "method": event.get("method"),
                    "remote_port": event.get("port"),
                    "duration_ms": event.get("duration_ms"),
                    "status": (event.get("response") or {}).get("status")
                    if isinstance(event.get("response"), dict)
                    else None,
                    "protocol": (event.get("response") or {}).get("http_version")
                    if isinstance(event.get("response"), dict)
                    else event.get("http_version"),
                    "failed": not bool(event.get("ok", False)),
                    "mode": event.get("mode"),
                },
                source="proxy",
                event_type="proxy.request",
                artifact_id=artifact_id,
                source_index=source_index,
                timestamp=timestamp,
                original_timestamp=original_timestamp,
            )
            return
        payload = {key: value for key, value in event.items() if key not in ("type", "timestamp")}
        if clock_basis:
            payload["clock"] = {"normalization": clock_basis}
        self.store.add_event(
            EventEnvelope(
                event_type=event_type,
                source=_source_for_event(event_type),
                payload=payload,
                timestamp=timestamp,
                correlation_id=str(event.get("request_id") or event.get("requestId") or "") or None,
                artifact_id=artifact_id,
                source_index=source_index,
                original_timestamp=original_timestamp,
            ),
            session_id=self.session_id,
        )


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value.split("%", 1)[0])
        return True
    except ValueError:
        return False


def _source_for_event(event_type: str) -> str:
    if event_type.startswith("proxy"):
        return "proxy"
    if event_type.startswith("dns"):
        return "packets.dns"
    if event_type.startswith("connection"):
        return "system.sockets"
    if event_type.startswith("session"):
        return "recorder"
    return "import"


def _ingest_jsonl_into_store(
    store: SessionStore,
    session_id: str,
    input_path: Path,
    *,
    allow_duplicate: bool,
) -> Dict[str, Any]:
    artifact = store.register_artifact(
        str(input_path),
        source_type="jsonl",
        session_id=session_id,
        metadata={"format": "jsonl"},
        allow_duplicate=allow_duplicate,
    )
    artifact_id = str(artifact["id"])
    correlator = CorrelationEngine(store, session_id)
    imported = 0
    malformed = 0
    nonempty_lines = 0
    errors: List[Dict[str, Any]] = []
    current_line = 0

    def rejected(line_number: int, reason: str) -> None:
        nonlocal malformed
        malformed += 1
        if len(errors) < 50:
            errors.append({"line": line_number, "reason": reason[:300]})

    try:
        with _open_regular_binary(input_path) as stream:
            while True:
                raw_line = stream.readline(MAX_JSONL_LINE_BYTES + 1)
                if not raw_line:
                    break
                current_line += 1
                oversized = len(raw_line) > MAX_JSONL_LINE_BYTES
                while oversized and raw_line and not raw_line.endswith(b"\n"):
                    raw_line = stream.readline(MAX_JSONL_LINE_BYTES + 1)
                if oversized:
                    nonempty_lines += 1
                    rejected(current_line, f"JSON line exceeds {MAX_JSONL_LINE_BYTES} bytes")
                    continue
                if not raw_line.strip():
                    continue
                nonempty_lines += 1
                if nonempty_lines > MAX_INGEST_EVENTS:
                    raise SessionError(f"recording exceeds the {MAX_INGEST_EVENTS} event import limit")
                line = raw_line.decode("utf-8", errors="replace")
                try:
                    event = json.loads(
                        line,
                        parse_constant=_reject_json_constant,
                    )
                except (ValueError, RecursionError) as exc:
                    reason = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
                    rejected(current_line, f"invalid JSON: {reason}")
                    continue
                if not isinstance(event, dict):
                    rejected(current_line, "event must be a JSON object")
                    continue

                store.connection.execute("SAVEPOINT ingest_event")
                try:
                    raw_event_type = event.get("type")
                    if raw_event_type is not None and not isinstance(raw_event_type, str):
                        raise ValueError("event type must be a string")
                    raw_name = str(raw_event_type or "unknown")
                    event_type = CANONICAL_EVENT_TYPES.get(raw_name, raw_name)
                    observed_at, original_timestamp, clock_basis = _normalize_timestamp(event.get("timestamp"))
                    connection_value = event.get("connection")
                    if event_type in ("connection.opened", "connection.closed"):
                        if not isinstance(connection_value, dict):
                            raise ValueError("connection lifecycle event requires a connection object")
                        correlator.observe_connection(
                            _connection_from_dict(connection_value),
                            event_type,
                            timestamp=observed_at,
                            artifact_id=artifact_id,
                            source_index=current_line,
                            original_timestamp=original_timestamp,
                            clock_basis=clock_basis,
                        )
                    else:
                        normalized_event = dict(event)
                        normalized_event["type"] = event_type
                        correlator.observe_generic(
                            normalized_event,
                            artifact_id=artifact_id,
                            source_index=current_line,
                            timestamp=observed_at,
                            original_timestamp=original_timestamp,
                            clock_basis=clock_basis,
                        )
                except (ValueError, TypeError, AttributeError) as exc:
                    store.connection.execute("ROLLBACK TO ingest_event")
                    store.connection.execute("RELEASE ingest_event")
                    rejected(current_line, f"invalid event: {exc}")
                    continue
                except Exception:
                    store.connection.execute("ROLLBACK TO ingest_event")
                    store.connection.execute("RELEASE ingest_event")
                    raise
                store.connection.execute("RELEASE ingest_event")
                imported += 1
    except Exception as exc:
        if isinstance(exc, SessionError):
            raise
        raise SessionError(f"ingest failed near line {current_line}: {exc}") from exc

    status = "complete"
    if malformed:
        status = "partial" if imported else "failed"
    return {
        "artifact": artifact,
        "imported_events": imported,
        "malformed_lines": malformed,
        "total_event_lines": nonempty_lines,
        "source": str(input_path),
        "errors": errors,
        "status": status,
    }


def _ingest_har_into_store(
    store: SessionStore,
    session_id: str,
    input_path: Path,
    *,
    allow_duplicate: bool,
) -> Dict[str, Any]:
    from .analyzer import analyze_recording

    artifact = store.register_artifact(
        str(input_path),
        source_type="har",
        session_id=session_id,
        metadata={"format": "har"},
        allow_duplicate=allow_duplicate,
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix="wirescope-har-", suffix=".har")
    temporary_path = Path(temporary_name)
    digest = hashlib.sha256()
    copied = 0
    try:
        os.fchmod(descriptor, PRIVATE_FILE_MODE)
        output_stream = os.fdopen(descriptor, "wb")
        descriptor = -1
        with output_stream, _open_regular_binary(input_path) as input_stream:
            for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > MAX_HAR_FILE_BYTES:
                    raise SessionError(f"HAR exceeds the {MAX_HAR_FILE_BYTES}-byte import limit")
                digest.update(chunk)
                output_stream.write(chunk)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        if copied != int(artifact["size_bytes"]) or digest.hexdigest() != str(artifact["sha256"]):
            raise SessionError("source artifact changed while the HAR snapshot was created")
        report = analyze_recording(str(temporary_path))
    except (OSError, ValueError, TypeError, AttributeError, KeyError, RecursionError) as exc:
        if isinstance(exc, SessionError):
            raise
        raise SessionError(f"cannot parse HAR recording: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)
    if not isinstance(report, dict):
        raise SessionError("HAR analysis did not produce an object")
    correlator = CorrelationEngine(store, session_id)
    requests = report.get("requests", [])
    if not isinstance(requests, list):
        raise SessionError("HAR analysis did not produce a request list")
    if len(requests) > MAX_HAR_REQUESTS:
        raise SessionError(f"HAR contains more than {MAX_HAR_REQUESTS} requests")
    imported = 0
    for index, request in enumerate(requests, 1):
        if not isinstance(request, dict):
            continue
        observed_at, original_timestamp, _clock_basis = _normalize_timestamp(request.get("started_at"))
        correlator.observe_normalized_request(
            request,
            source="browser.har",
            artifact_id=str(artifact["id"]),
            source_index=index,
            timestamp=observed_at,
            original_timestamp=original_timestamp,
        )
        imported += 1
    return {
        "artifact": artifact,
        "imported_events": imported,
        "malformed_lines": len(report.get("parse_errors", [])),
        "total_event_lines": len(requests),
        "source": str(input_path),
        "errors": list(report.get("parse_errors", []))[:50],
        "status": "partial" if report.get("parse_errors") else "complete",
    }


def _ingest_source(
    store: SessionStore,
    session_id: str,
    source: str,
    *,
    allow_duplicate: bool,
) -> Dict[str, Any]:
    input_path = Path(os.path.abspath(str(Path(source).expanduser())))
    try:
        input_info = _inspect_session_path(input_path)
    except SessionError as exc:
        raise SessionError(f"recording does not exist: {source}") from exc
    maximum_size = MAX_HAR_FILE_BYTES if input_path.suffix.lower() == ".har" else MAX_JSONL_FILE_BYTES
    if input_info.st_size > maximum_size:
        raise SessionError(
            f"recording is {input_info.st_size} bytes; maximum supported size is {maximum_size} bytes"
        )
    store.connection.execute("SAVEPOINT ingest_source")
    try:
        if input_path.suffix.lower() == ".har":
            result = _ingest_har_into_store(
                store,
                session_id,
                input_path,
                allow_duplicate=allow_duplicate,
            )
        else:
            result = _ingest_jsonl_into_store(
                store,
                session_id,
                input_path,
                allow_duplicate=allow_duplicate,
            )
        digest, size = _hash_file_bounded(input_path, maximum_size)
        artifact = result["artifact"]
        if digest != artifact["sha256"] or size != artifact["size_bytes"]:
            raise SessionError("source artifact changed during ingest; no events were committed")
    except Exception:
        store.connection.execute("ROLLBACK TO ingest_source")
        store.connection.execute("RELEASE ingest_source")
        raise
    store.connection.execute("RELEASE ingest_source")
    return result


def import_recording(source: str, destination: str, *, title: Optional[str] = None) -> Dict[str, Any]:
    input_path = Path(os.path.abspath(str(Path(source).expanduser())))
    destination_path = Path(os.path.abspath(str(Path(destination).expanduser())))
    if _same_file(input_path, destination_path):
        raise SessionError("session destination must differ from the source recording")
    with SessionStore(destination) as store:
        session_id = store.start_session(
            title=title or f"Imported {input_path.name}",
            source="import",
            config={"source": str(input_path)},
        )
        try:
            summary = _ingest_source(store, session_id, source, allow_duplicate=False)
        except Exception as exc:
            failure = {
                "imported_events": 0,
                "malformed_lines": 0,
                "total_event_lines": 0,
                "source": str(input_path),
                "errors": [],
                "failure": f"{type(exc).__name__}: {str(exc)[:300]}",
            }
            try:
                store.finish_session(session_id, failure, status="failed")
            except sqlite3.Error:
                store.connection.rollback()
            raise
        store.finish_session(session_id, summary, status=str(summary["status"]))
        return {**summary, "session": destination, "session_id": session_id, "summary": store.summary()}


def ingest_session(
    session: str,
    source: str,
    *,
    allow_duplicate: bool = False,
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    session_path = Path(os.path.abspath(str(Path(session).expanduser())))
    source_path = Path(os.path.abspath(str(Path(source).expanduser())))
    if _same_file(session_path, source_path):
        raise SessionError("a session database cannot ingest itself as a source artifact")
    with SessionStore(session) as store:
        active = store._require_session_id(session_id)
        summary = _ingest_source(store, active, source, allow_duplicate=allow_duplicate)
        row = store.connection.execute("SELECT summary_json FROM sessions WHERE id=?", (active,)).fetchone()
        session_summary = _load_json(row["summary_json"], {}) if row else {}
        ingests = session_summary.get("ingests", [])
        if not isinstance(ingests, list):
            ingests = []
        ingests.append(
            {
                "artifact_id": summary["artifact"]["id"],
                "sha256": summary["artifact"]["sha256"],
                "imported_events": summary["imported_events"],
                "status": summary["status"],
            }
        )
        session_summary["ingests"] = ingests
        store.connection.execute(
            "UPDATE sessions SET summary_json=? WHERE id=?",
            (_json(session_summary), active),
        )
        store.commit()
        return {**summary, "session": session, "session_id": active, "summary": store.summary()}


def _connection_from_dict(value: Dict[str, Any]) -> Connection:
    from .models import Endpoint

    local = value.get("local", {}) if isinstance(value.get("local"), dict) else {}
    remote = value.get("remote") if isinstance(value.get("remote"), dict) else None
    return Connection(
        process=str(value.get("process") or "unknown"),
        pid=int(value.get("pid") or 0),
        user=str(value.get("user") or ""),
        fd=str(value.get("fd") or ""),
        family=str(value.get("family") or ""),
        protocol=str(value.get("protocol") or ""),
        local=Endpoint(str(local.get("host") or ""), str(local.get("port")) if local.get("port") is not None else None),
        remote=(Endpoint(str(remote.get("host") or ""), str(remote.get("port")) if remote.get("port") is not None else None) if remote else None),
        state=str(value.get("state") or ""),
        path=str(value.get("path") or "direct"),
    )


def record_system_session(
    adapter: Any,
    output: str,
    *,
    duration: float,
    interval: float,
    process: Optional[str] = None,
    title: str = "WireScope system recording",
) -> Dict[str, Any]:
    previous: Dict[str, Connection] = {}
    opened = 0
    closed = 0
    snapshots = 0
    started = time.monotonic()
    last_network_state: Dict[str, str] = {}
    with SessionStore(output) as store:
        capabilities = adapter.capabilities() if hasattr(adapter, "capabilities") else {}
        session_id = store.start_session(
            title=title,
            source="system",
            config={"duration_seconds": duration, "interval_seconds": interval, "process_filter": process, "capabilities": capabilities},
        )
        correlator = CorrelationEngine(store, session_id)
        store.add_event(
            EventEnvelope(event_type="session.started", source="recorder", payload={"capabilities": capabilities}),
            session_id=session_id,
        )
        while time.monotonic() - started < duration:
            connections: Iterable[Connection] = adapter.connections()
            if process:
                connections = [item for item in connections if process.lower() in item.process.lower()]
            current = {item.key(): item for item in connections}
            timestamp = utc_now()
            for key in current.keys() - previous.keys():
                correlator.observe_connection(current[key], "connection.opened", timestamp=timestamp)
                opened += 1
            for key in previous.keys() - current.keys():
                correlator.observe_connection(previous[key], "connection.closed", timestamp=timestamp)
                closed += 1
            previous = current
            snapshots += 1
            if snapshots == 1 or snapshots % max(1, int(round(5.0 / interval))) == 0:
                network_values = {
                    "routes": adapter.routes(),
                    "dns": adapter.dns_resolvers(),
                    "vpn": adapter.vpn_status(),
                    "proxy": adapter.proxy_config(),
                }
                for name, value in network_values.items():
                    fingerprint = hashlib.sha256(_json(value).encode("utf-8")).hexdigest()
                    previous_fingerprint = last_network_state.get(name)
                    if previous_fingerprint != fingerprint:
                        store.add_event(
                            EventEnvelope(
                                event_type=f"network.{name}.snapshot" if previous_fingerprint is None else f"network.{name}.changed",
                                source=f"system.{name}",
                                payload={"value": value, "previous_fingerprint": previous_fingerprint, "fingerprint": fingerprint},
                                timestamp=timestamp,
                                severity="notice" if previous_fingerprint else "info",
                            ),
                            session_id=session_id,
                        )
                        last_network_state[name] = fingerprint
            if snapshots % 10 == 0:
                store.commit()
            remaining = duration - (time.monotonic() - started)
            if remaining > 0:
                time.sleep(min(interval, remaining))
        summary = {
            "snapshots": snapshots,
            "opened": opened,
            "closed": closed,
            "active_at_end": len(previous),
            "observed_seconds": round(time.monotonic() - started, 3),
        }
        store.add_event(EventEnvelope(event_type="session.finished", source="recorder", payload=summary), session_id=session_id)
        store.finish_session(session_id, summary)
        result = store.summary()
        result["recording"] = summary
        return result
