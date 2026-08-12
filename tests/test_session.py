from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wirescope import session as session_module
from wirescope.artifacts import ArtifactSecurityError
from wirescope.models import Connection, Endpoint
from wirescope.session import (
    CorrelationEngine,
    EventEnvelope,
    SessionError,
    SessionStore,
    SQLITE_APPLICATION_ID,
    import_recording,
    ingest_session,
    migrate_session,
    record_system_session,
    verify_session,
)


def connection(process: str = "Browser", pid: int = 42) -> Connection:
    return Connection(
        process=process,
        pid=pid,
        user="tester",
        fd="9u",
        family="IPv4",
        protocol="TCP",
        local=Endpoint("127.0.0.1", "50000"),
        remote=Endpoint("203.0.113.10", "443"),
        state="ESTABLISHED",
        path="vpn-default",
    )


class FakeAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self):
        return {"connections": {"available": True}}

    def connections(self):
        self.calls += 1
        return [connection()] if self.calls < 3 else []

    def routes(self):
        return [{"destination": "default", "gateway": "link#1", "interface": "utun1", "flags": "UG"}]

    def dns_resolvers(self):
        return [{"id": 1, "nameservers": ["10.0.0.1"]}]

    def vpn_status(self):
        return {"active": True, "interfaces": [{"name": "utun1"}]}

    def proxy_config(self):
        return {"HTTPEnable": "0"}


class SessionStoreTests(unittest.TestCase):
    def test_session_is_private_and_summarized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.wsdb"
            previous = os.umask(0)
            try:
                with SessionStore(str(path)) as store:
                    session_id = store.start_session(title="Test")
                    store.add_event(EventEnvelope(event_type="test.event", source="test", payload={"ok": True}))
                    store.finish_session(session_id, {"ok": True})
                    summary = store.summary()
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(summary["counts"]["events"], 1)
            self.assertEqual(summary["events_by_type"]["test.event"], 1)
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(store.summary()["sessions"][0]["status"], "complete")

    def test_entity_relations_timeline_and_explain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "entities.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                correlator = CorrelationEngine(store, session_id)
                entity_id = correlator.observe_connection(connection(), "connection.opened")
                store.add_marker("Application became slow")
                store.finish_session(session_id)
                explanation = store.explain(entity_id)
                timeline = store.timeline(event_type="connection.*")
                processes = store.entities(entity_type="process")
            self.assertEqual(len(timeline), 1)
            self.assertEqual(timeline[0]["event_type"], "connection.opened")
            self.assertEqual(processes[0]["attributes"]["pid"], 42)
            relation_names = {item["relation"] for item in explanation["relations"]}
            self.assertIn("PROCESS_OWNS_CONNECTION", relation_names)
            self.assertIn("CONNECTION_TARGETS_ENDPOINT", relation_names)

    def test_import_jsonl_builds_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "connections.jsonl"
            destination = Path(directory) / "imported.wsdb"
            events = [
                {"type": "session_start", "timestamp": "2026-01-01T00:00:00+00:00"},
                {"type": "connection_open", "timestamp": "2026-01-01T00:00:01+00:00", "connection": connection().to_dict()},
                {"type": "connection_close", "timestamp": "2026-01-01T00:00:02+00:00", "connection": connection().to_dict()},
            ]
            source.write_text("\n".join(json.dumps(item) for item in events) + "\n", encoding="utf-8")
            result = import_recording(str(source), str(destination))
            self.assertEqual(result["imported_events"], 3)
            with SessionStore(str(destination), read_only=True) as store:
                summary = store.summary()
                self.assertEqual(summary["entities_by_type"]["connection"], 1)
                self.assertEqual(summary["entities_by_type"]["process"], 1)
                self.assertEqual(summary["events_by_type"]["connection.opened"], 1)

    def test_application_identity_and_future_or_foreign_schemas_are_refused_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            valid = Path(directory) / "valid.wsdb"
            with SessionStore(str(valid)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)
            connection_value = sqlite3.connect(str(valid))
            self.assertEqual(connection_value.execute("PRAGMA application_id").fetchone()[0], SQLITE_APPLICATION_ID)
            connection_value.execute("UPDATE schema_info SET version=99 WHERE component='session'")
            connection_value.execute("PRAGMA user_version=99")
            connection_value.commit()
            connection_value.close()
            with self.assertRaisesRegex(SessionError, "newer than supported"):
                SessionStore(str(valid))
            connection_value = sqlite3.connect(str(valid))
            self.assertEqual(connection_value.execute("PRAGMA user_version").fetchone()[0], 99)
            self.assertEqual(
                connection_value.execute("SELECT version FROM schema_info WHERE component='session'").fetchone()[0],
                99,
            )
            connection_value.close()

            foreign = Path(directory) / "foreign.sqlite"
            connection_value = sqlite3.connect(str(foreign))
            connection_value.execute("CREATE TABLE sentinel(value TEXT)")
            connection_value.execute("INSERT INTO sentinel VALUES('preserved')")
            connection_value.commit()
            connection_value.close()
            with self.assertRaisesRegex(SessionError, "foreign SQLite"):
                SessionStore(str(foreign))
            connection_value = sqlite3.connect(str(foreign))
            self.assertEqual(connection_value.execute("SELECT value FROM sentinel").fetchone()[0], "preserved")
            self.assertIsNone(
                connection_value.execute("SELECT name FROM sqlite_master WHERE name='schema_info'").fetchone()
            )
            connection_value.close()

    def test_read_only_uri_escapes_filename_delimiters(self):
        for name in ("question?.wsdb", "fragment#.wsdb", "percent%.wsdb"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / name
                with SessionStore(str(path)) as store:
                    session_id = store.start_session(title=name)
                    store.finish_session(session_id)
                before = {item.name for item in Path(directory).iterdir()}
                with SessionStore(str(path), read_only=True) as store:
                    self.assertEqual(store.summary()["sessions"][0]["title"], name)
                self.assertEqual({item.name for item in Path(directory).iterdir()}, before)

    def test_entities_and_relations_are_scoped_to_each_session(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "multi.wsdb"
            with SessionStore(str(path)) as store:
                first = store.start_session(title="First")
                first_connection = connection()
                first_id = CorrelationEngine(store, first).observe_connection(first_connection, "connection.opened")
                store.finish_session(first)

                second = store.start_session(title="Second")
                second_connection = Connection(
                    **{**first_connection.__dict__, "user": "different-user"}
                )
                second_id = CorrelationEngine(store, second).observe_connection(second_connection, "connection.opened")
                store.finish_session(second)

                self.assertNotEqual(first_id, second_id)
                self.assertEqual(len(store.entities(entity_type="process")), 2)
                first_entity = store.explain(first_id)["entity"]
                second_entity = store.explain(second_id)["entity"]
                self.assertEqual(first_entity["session_id"], first)
                self.assertEqual(second_entity["session_id"], second)
                self.assertEqual(first_entity["attributes"]["user"], "tester")
                self.assertEqual(second_entity["attributes"]["user"], "different-user")

    def test_who_traverses_from_endpoint_to_process(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "who.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                CorrelationEngine(store, session_id).observe_connection(connection(), "connection.opened")
                store.finish_session(session_id)
                result = store.who("203.0.113.10")
            self.assertEqual(result["paths"][0]["actor"]["entity_type"], "process")
            self.assertIn("Browser", result["paths"][0]["actor"]["label"])
            self.assertEqual(result["paths"][0]["hops"], 2)

    def test_import_skips_invalid_structures_and_marks_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "partial.jsonl"
            destination = Path(directory) / "partial.wsdb"
            good = {"type": "connection_open", "connection": connection().to_dict()}
            bad = {"type": "connection_close", "connection": {"pid": "not-an-integer"}}
            source.write_text("\n".join((json.dumps(good), json.dumps(bad), "{broken")) + "\n", encoding="utf-8")
            result = import_recording(str(source), str(destination))
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["imported_events"], 1)
            self.assertEqual(result["malformed_lines"], 2)
            with SessionStore(str(destination), read_only=True) as store:
                summary = store.summary()
                self.assertEqual(summary["sessions"][0]["status"], "partial")
                self.assertEqual(summary["events_by_type"], {"connection.opened": 1})

    def test_marker_requires_a_session(self):
        with tempfile.TemporaryDirectory() as directory:
            with SessionStore(str(Path(directory) / "empty.wsdb")) as store:
                with self.assertRaisesRegex(SessionError, "does not contain a recording"):
                    store.add_marker("orphan")

    def test_system_recording_captures_state_and_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recorded.wsdb"
            result = record_system_session(FakeAdapter(), str(path), duration=0.04, interval=0.01)
            self.assertGreaterEqual(result["recording"]["snapshots"], 2)
            self.assertEqual(result["recording"]["opened"], 1)
            self.assertEqual(result["recording"]["closed"], 1)
            with SessionStore(str(path), read_only=True) as store:
                types = store.summary()["events_by_type"]
                self.assertIn("network.routes.snapshot", types)
                self.assertIn("connection.opened", types)
                self.assertIn("connection.closed", types)

    def test_symlink_destination_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.wsdb"
            target.write_bytes(b"not sqlite")
            link = Path(directory) / "link.wsdb"
            link.symlink_to(target)
            with self.assertRaises(ArtifactSecurityError):
                SessionStore(str(link))

    def test_missing_entity_explanation_is_clear(self):
        with tempfile.TemporaryDirectory() as directory:
            with SessionStore(str(Path(directory) / "empty.wsdb")) as store:
                store.start_session()
                with self.assertRaisesRegex(SessionError, "entity not found"):
                    store.explain("does-not-exist")

    def test_schema_v1_is_readable_and_copy_migrates_without_touching_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "legacy.wsdb"
            destination = Path(directory) / "migrated.wsdb"
            with SessionStore(str(source)) as store:
                session_id = store.start_session(title="Legacy")
                store.add_event(EventEnvelope(event_type="legacy.event", source="test"))
                store.finish_session(session_id)
            connection_value = sqlite3.connect(str(source))
            connection_value.execute("UPDATE schema_info SET version=1 WHERE component IN ('session', 'event')")
            connection_value.execute("UPDATE events SET schema_version=1")
            connection_value.execute("PRAGMA user_version=1")
            connection_value.commit()
            connection_value.close()
            before = hashlib.sha256(source.read_bytes()).hexdigest()

            with SessionStore(str(source), read_only=True) as store:
                self.assertEqual(store.summary()["schema_version"], 1)
                self.assertEqual(store.timeline()[0]["event_type"], "legacy.event")
            with self.assertRaisesRegex(SessionError, "migrate it"):
                SessionStore(str(source))

            result = migrate_session(str(source), str(destination))
            self.assertTrue(result["source_unchanged"])
            self.assertEqual(result["source_schema_version"], 1)
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            verification = verify_session(str(destination))
            self.assertTrue(verification["passed"], verification)
            self.assertEqual(verification["schema_version"], 2)
            with SessionStore(str(destination), read_only=True) as store:
                self.assertEqual(store.timeline()[0]["schema_version"], 1)

    def test_ingest_is_hash_idempotent_and_records_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "session.wsdb"
            source = Path(directory) / "events.jsonl"
            source.write_text(
                json.dumps(
                    {
                        "type": "connection_open",
                        "timestamp": "2026-01-01T03:00:00+03:00",
                        "connection": connection().to_dict(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with SessionStore(str(session)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)

            first = ingest_session(str(session), str(source))
            self.assertEqual(first["imported_events"], 1)
            with self.assertRaisesRegex(SessionError, "already ingested"):
                ingest_session(str(session), str(source))
            second = ingest_session(str(session), str(source), allow_duplicate=True)
            self.assertTrue(second["artifact"]["duplicate"])
            with SessionStore(str(session), read_only=True) as store:
                self.assertEqual(store.summary()["counts"]["artifacts"], 1)
                events = store.timeline(event_type="connection.opened")
                self.assertEqual(len(events), 2)
                self.assertEqual(events[0]["source_index"], 1)
                self.assertTrue(events[0]["artifact_id"].startswith("art_"))
                self.assertEqual(events[0]["timestamp"], "2026-01-01T00:00:00.000+00:00")
                self.assertEqual(events[0]["original_timestamp"], "2026-01-01T03:00:00+03:00")

    def test_har_ingest_builds_request_domain_ip_and_connection_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "har.wsdb"
            source = Path(directory) / "capture.har"
            source.write_text(
                json.dumps(
                    {
                        "log": {
                            "version": "1.2",
                            "entries": [
                                {
                                    "startedDateTime": "2026-01-01T00:00:00Z",
                                    "time": 42,
                                    "request": {"method": "GET", "url": "https://example.com/app.js"},
                                    "response": {
                                        "status": 200,
                                        "httpVersion": "h2",
                                        "bodySize": 12,
                                        "headersSize": 3,
                                        "content": {"mimeType": "application/javascript"},
                                    },
                                    "serverIPAddress": "203.0.113.10",
                                    "connection": "17",
                                    "timings": {"dns": 1, "connect": 2, "wait": 5, "receive": 3},
                                    "cache": {},
                                }
                            ],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with SessionStore(str(session)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)
            result = ingest_session(str(session), str(source))
            self.assertEqual(result["imported_events"], 1)
            with SessionStore(str(session), read_only=True) as store:
                relation_names = {item["relation"] for item in store.relations()}
                self.assertIn("HTTP_TARGETS_DOMAIN", relation_names)
                self.assertIn("HTTP_USES_REMOTE_IP", relation_names)
                self.assertIn("HTTP_USES_CONNECTION", relation_names)
                self.assertIn("CONNECTION_TARGETS_ENDPOINT", relation_names)
                who = store.who("example.com")
                self.assertEqual(who["paths"][0]["actor"]["entity_type"], "http_request")

    def test_verify_detects_dangling_evidence_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                CorrelationEngine(store, session_id).observe_connection(connection(), "connection.opened")
                store.finish_session(session_id)
            connection_value = sqlite3.connect(str(path))
            connection_value.execute(
                "UPDATE relations SET evidence_json=? WHERE id=(SELECT MIN(id) FROM relations)",
                (json.dumps({"event_id": "evt_missing"}),),
            )
            connection_value.commit()
            connection_value.close()
            result = verify_session(str(path))
            self.assertFalse(result["passed"])
            evidence_check = next(item for item in result["checks"] if item["name"] == "evidence-references")
            self.assertFalse(evidence_check["passed"])

    def test_import_and_ingest_refuse_source_destination_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            empty_source = Path(directory) / "empty.jsonl"
            empty_source.write_bytes(b"")
            with self.assertRaisesRegex(SessionError, "destination must differ"):
                import_recording(str(empty_source), str(empty_source))
            self.assertEqual(empty_source.read_bytes(), b"")

            session = Path(directory) / "self.wsdb"
            with SessionStore(str(session)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)
            before = session.read_bytes()
            with self.assertRaisesRegex(SessionError, "cannot ingest itself"):
                ingest_session(str(session), str(session))
            self.assertEqual(session.read_bytes(), before)

    def test_changed_source_rolls_back_the_entire_ingest(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "atomic.wsdb"
            source = Path(directory) / "events.jsonl"
            source.write_text(json.dumps({"type": "user.marker", "message": "atomic"}) + "\n", encoding="utf-8")
            with SessionStore(str(session)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)

            real_hash_file = session_module._hash_file
            hash_calls = 0

            def changing_hash(path):
                nonlocal hash_calls
                hash_calls += 1
                digest, size = real_hash_file(path)
                return (("0" * 64) if hash_calls == 2 else digest, size)

            with mock.patch("wirescope.session._hash_file", side_effect=changing_hash):
                with self.assertRaisesRegex(SessionError, "changed during ingest"):
                    ingest_session(str(session), str(source))

            with SessionStore(str(session), read_only=True) as store:
                summary = store.summary()
                self.assertEqual(summary["counts"]["events"], 0)
                self.assertEqual(summary["counts"]["entities"], 0)
                self.assertEqual(summary["counts"]["artifacts"], 0)


if __name__ == "__main__":
    unittest.main()
