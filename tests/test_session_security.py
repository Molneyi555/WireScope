from __future__ import annotations

import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import wirescope.session as session_module
import wirescope.session_report as report_module
from wirescope.artifacts import ArtifactSecurityError
from wirescope.session import (
    EventEnvelope,
    SessionError,
    SessionStore,
    import_recording,
    migrate_session,
    verify_session,
)
from wirescope.session_report import build_session_report_data


class SessionBoundarySecurityTests(unittest.TestCase):
    def make_session(self, path: Path) -> None:
        with SessionStore(str(path)) as store:
            session_id = store.start_session(title="Synthetic session")
            store.finish_session(session_id)

    def test_sqlite_sidecar_symlink_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            target = Path(directory) / "sentinel"
            self.make_session(path)
            target.write_bytes(b"do-not-touch")
            sidecar = Path(f"{path}-wal")
            sidecar.unlink(missing_ok=True)
            sidecar.symlink_to(target)

            with self.assertRaisesRegex(ArtifactSecurityError, "sidecar"):
                SessionStore(str(path), read_only=True)
            self.assertEqual(target.read_bytes(), b"do-not-touch")

    def test_session_creation_does_not_truncate_a_raced_in_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            real_open = os.open

            def raced_open(raw_path, flags, mode=0o777):
                Path(raw_path).write_bytes(b"raced-in")
                return real_open(raw_path, flags, mode)

            with patch.object(session_module.os, "open", side_effect=raced_open):
                with self.assertRaisesRegex(ArtifactSecurityError, "appeared"):
                    session_module._ensure_sqlite_path(path)
            self.assertEqual(path.read_bytes(), b"raced-in")

    def test_open_session_detects_final_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            moved = Path(directory) / "moved.wsdb"
            self.make_session(path)
            store = SessionStore(str(path), read_only=True)
            os.replace(path, moved)
            path.write_bytes(b"replacement")

            with self.assertRaisesRegex(ArtifactSecurityError, "replaced while open"):
                store.close()
            self.assertEqual(path.read_bytes(), b"replacement")

    def test_foreign_existing_database_is_only_prevalidated_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "foreign.sqlite"
            connection = sqlite3.connect(str(path))
            connection.execute("CREATE TABLE sentinel(value TEXT)")
            connection.execute("INSERT INTO sentinel VALUES('preserved')")
            connection.commit()
            connection.close()
            real_connect = sqlite3.connect
            opened = []

            def observed_connect(database, *args, **kwargs):
                opened.append(str(database))
                return real_connect(database, *args, **kwargs)

            with patch.object(session_module.sqlite3, "connect", side_effect=observed_connect):
                with self.assertRaisesRegex(SessionError, "foreign SQLite"):
                    SessionStore(str(path))

            self.assertTrue(opened)
            self.assertTrue(all("mode=ro" in value for value in opened))
            connection = sqlite3.connect(str(path))
            self.assertEqual(connection.execute("SELECT value FROM sentinel").fetchone()[0], "preserved")
            connection.close()

    def test_jsonl_line_limit_rejects_one_logical_line_and_continues(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            destination = Path(directory) / "session.wsdb"
            oversized = b'{"type":"custom","value":"' + (b"A" * 200) + b'"}\n'
            valid = json.dumps({"type": "custom", "value": "ok"}).encode() + b"\n"
            source.write_bytes(oversized + valid)

            with patch.object(session_module, "MAX_JSONL_LINE_BYTES", 64):
                result = import_recording(str(source), str(destination))

            self.assertEqual(result["imported_events"], 1)
            self.assertEqual(result["malformed_lines"], 1)
            self.assertEqual(result["status"], "partial")
            self.assertIn("exceeds 64 bytes", result["errors"][0]["reason"])

    def test_recording_size_limit_runs_before_artifact_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            destination = Path(directory) / "session.wsdb"
            source.write_bytes(b'{"type":"custom"}\n')

            with patch.object(session_module, "MAX_JSONL_FILE_BYTES", 4):
                with self.assertRaisesRegex(SessionError, "maximum supported size"):
                    import_recording(str(source), str(destination))

            with SessionStore(str(destination), read_only=True) as store:
                self.assertEqual(store.summary()["counts"]["artifacts"], 0)

    def test_nonstandard_json_constants_are_not_imported(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            destination = Path(directory) / "session.wsdb"
            source.write_text('{"type":"custom","value":NaN}\n', encoding="utf-8")

            result = import_recording(str(source), str(destination))

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["imported_events"], 0)
            self.assertEqual(result["malformed_lines"], 1)

    def test_har_analyzer_receives_a_private_verified_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            destination = Path(directory) / "session.wsdb"
            source.write_bytes(b"synthetic-har-bytes")
            observed = {}

            def analyze(snapshot: str):
                snapshot_path = Path(snapshot)
                observed["path"] = snapshot_path
                observed["bytes"] = snapshot_path.read_bytes()
                observed["mode"] = stat.S_IMODE(snapshot_path.stat().st_mode)
                return {"requests": [], "parse_errors": []}

            with patch("wirescope.analyzer.analyze_recording", side_effect=analyze):
                result = import_recording(str(source), str(destination))

            self.assertEqual(result["status"], "complete")
            self.assertNotEqual(observed["path"], source)
            self.assertEqual(observed["bytes"], source.read_bytes())
            self.assertEqual(observed["mode"], 0o600)
            self.assertFalse(observed["path"].exists())

    def test_changed_migration_source_is_not_published(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.wsdb"
            destination = Path(directory) / "destination.wsdb"
            self.make_session(source)
            original_hash = session_module._hash_file
            source_calls = 0

            def changing_hash(path: Path, **kwargs):
                nonlocal source_calls
                if path == source:
                    source_calls += 1
                if path == source and source_calls == 2:
                    with path.open("ab") as stream:
                        stream.write(b"changed-after-backup")
                return original_hash(path, **kwargs)

            with patch.object(session_module, "_hash_file", side_effect=changing_hash):
                with self.assertRaisesRegex(SessionError, "was not published"):
                    migrate_session(str(source), str(destination))

            self.assertFalse(destination.exists())

    def test_atomic_new_file_publication_preserves_raced_in_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.wsdb"
            destination = Path(directory) / "destination.wsdb"
            self.make_session(source)
            real_link = os.link

            def raced_link(src, dst, **kwargs):
                Path(dst).write_bytes(b"raced-in")
                return real_link(src, dst, **kwargs)

            with patch.object(session_module.os, "link", side_effect=raced_link):
                with self.assertRaisesRegex(SessionError, "appeared during publication"):
                    migrate_session(str(source), str(destination))

            self.assertEqual(destination.read_bytes(), b"raced-in")

    def test_migration_fingerprints_and_copies_an_active_wal_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.wsdb"
            destination = Path(directory) / "destination.wsdb"
            with SessionStore(str(source)) as store:
                session_id = store.start_session(title="Active WAL")
                store.add_event(EventEnvelope(event_type="test.event", source="test"), session_id=session_id)
                store.commit()
                self.assertTrue(Path(f"{source}-wal").exists())

                result = migrate_session(str(source), str(destination))

            self.assertRegex(result["source_snapshot_sha256"], r"^[0-9a-f]{64}$")
            with SessionStore(str(destination), read_only=True) as migrated:
                self.assertEqual(migrated.timeline()[0]["event_type"], "test.event")

    def test_verifier_reports_invalid_stored_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            self.make_session(path)
            connection = sqlite3.connect(str(path))
            connection.execute("UPDATE sessions SET config_json='{'")
            connection.commit()
            connection.close()

            result = verify_session(str(path))

            self.assertFalse(result["passed"])
            json_check = next(item for item in result["checks"] if item["name"] == "json-fields")
            self.assertFalse(json_check["passed"])
            self.assertIn("1 invalid", json_check["detail"])

    def test_verifier_rejects_oversized_sqlite_before_integrity_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            self.make_session(path)

            with patch.object(session_module, "MAX_VERIFY_SQLITE_BYTES", 16):
                result = verify_session(str(path))

            self.assertFalse(result["passed"])
            resource_check = next(item for item in result["checks"] if item["name"] == "resource-limits")
            self.assertFalse(resource_check["passed"])
            self.assertEqual(result["counts"], {})

    def test_evidence_reference_extraction_is_bounded(self):
        evidence = {"event_ids": ["evt_one", "evt_two", "evt_three"]}
        with patch.object(session_module, "MAX_EVIDENCE_REFERENCES", 2):
            with self.assertRaisesRegex(SessionError, "2 event references"):
                session_module._event_references(evidence)

    def test_summary_refuses_unbounded_session_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            self.make_session(path)
            with SessionStore(str(path), read_only=True) as store:
                with patch.object(session_module, "MAX_SUMMARY_TEXT_BYTES", 1):
                    with self.assertRaisesRegex(SessionError, "metadata exceeds"):
                        store.summary()

    def test_report_refuses_unbounded_selected_content(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(title="Bounded report")
                store.add_event(
                    EventEnvelope(event_type="test.event", source="test", payload={"message": "payload"}),
                    session_id=session_id,
                )
                store.finish_session(session_id)

            with patch.object(report_module, "MAX_SESSION_REPORT_TEXT_CHARS", 1):
                with self.assertRaisesRegex(SessionError, "report content exceeds"):
                    build_session_report_data(str(path), share_safe=True)

    def test_share_safe_report_removes_portable_paths_and_host_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "session.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(
                    title="Synthetic session",
                    config={
                        "source": "/private/tmp/alice/secret.har",
                        "source_path": "/Volumes/Private/capture.har",
                        "username": "alice-account",
                        "device_id": "device-123-private",
                        "backup": "~/private/capture.har",
                    },
                )
                store.connection.execute(
                    "UPDATE sessions SET host_json=? WHERE id=?",
                    (json.dumps({"node": "alice-macbook", "hostname": "office-host"}), session_id),
                )
                store.finish_session(session_id)

            data = build_session_report_data(str(path), share_safe=True)
            serialized = json.dumps(data, ensure_ascii=False)

            for secret in (
                "/private/tmp/alice/secret.har",
                "/Volumes/Private/capture.har",
                "alice-account",
                "device-123-private",
                "~/private/capture.har",
                "alice-macbook",
                "office-host",
                str(path),
            ):
                self.assertNotIn(secret, serialized)
            self.assertEqual(data["summary"]["path"], "[REDACTED]")


if __name__ == "__main__":
    unittest.main()
