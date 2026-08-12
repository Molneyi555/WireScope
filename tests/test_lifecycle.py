from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from wirescope.lifecycle import (
    MAX_TAG_LENGTH,
    create_support_bundle,
    export_session,
    merge_sessions,
    prune_session,
    session_tags,
    tag_session,
    verify_support_bundle,
)
from wirescope.session import EventEnvelope, SessionError, SessionStore, _hash_file, verify_session


def make_session(path: Path, timestamp: str, event_type: str = "test.event") -> str:
    with SessionStore(str(path)) as store:
        session_id = store.start_session(title=path.stem)
        store.add_event(
            EventEnvelope(
                event_type=event_type,
                source="fixture",
                timestamp=timestamp,
                payload={"address": "203.0.113.8", "path": "/Users/example/private"},
            )
        )
        store.finish_session(session_id)
    return session_id


class LifecycleTests(unittest.TestCase):
    def test_tags_are_typed_bounded_sorted_and_corruption_is_not_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tags.wsdb"
            session_id = make_session(path, "2026-01-01T00:00:00Z")
            self.assertEqual(
                tag_session(str(path), [" vpn ", "regression", "vpn"])["tags"],
                ["regression", "vpn"],
            )
            self.assertEqual(session_tags(str(path))["tags"], ["regression", "vpn"])
            with self.assertRaisesRegex(SessionError, "array of strings"):
                tag_session(str(path), "not-an-array")
            with self.assertRaisesRegex(SessionError, "must not exceed"):
                tag_session(str(path), ["x" * (MAX_TAG_LENGTH + 1)])
            with self.assertRaisesRegex(SessionError, "session not found"):
                tag_session(str(path), ["tag"], session_id="missing")

            with SessionStore(str(path)) as store:
                store.set_metadata(f"session_tags:{session_id}", ["valid", 7])
            with self.assertRaisesRegex(SessionError, "only strings"):
                session_tags(str(path))

    def test_merge_is_order_independent_uses_utc_order_and_validates_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.wsdb"
            second = root / "two.wsdb"
            first_session = make_session(first, "2026-01-01T01:00:00+01:00", "event.one")
            make_session(second, "2026-01-01T00:00:00Z", "event.two")
            with SessionStore(str(first)) as store:
                store.set_metadata(
                    f"rule_pack_versions:{first_session}", ["example.pack@1.0.0"]
                )
            hash_before = {_hash_file(first), _hash_file(second)}

            merged_a = root / "merged-a.wsdb"
            merged_b = root / "merged-b.wsdb"
            merge_sessions([str(first), str(second)], str(merged_a))
            merge_sessions([str(second), str(first)], str(merged_b))

            def event_ids(path: Path):
                with SessionStore(str(path), read_only=True) as store:
                    return [row["event_id"] for row in store.connection.execute("SELECT event_id FROM events ORDER BY sequence")]

            self.assertEqual(event_ids(merged_a), event_ids(merged_b))
            self.assertEqual(hash_before, {_hash_file(first), _hash_file(second)})
            with SessionStore(str(merged_a), read_only=True) as store:
                self.assertEqual(
                    store.get_metadata(f"rule_pack_versions:{first_session}"),
                    ["example.pack@1.0.0"],
                )

            with self.assertRaisesRegex(SessionError, "finite"):
                merge_sessions(
                    [str(first), str(second)],
                    str(root / "nan.wsdb"),
                    clock_offsets_ms={str(first): float("nan")},
                )
            with self.assertRaisesRegex(SessionError, "unknown sources"):
                merge_sessions(
                    [str(first), str(second)],
                    str(root / "unknown.wsdb"),
                    clock_offsets_ms={str(root / "missing.wsdb"): 1},
                )

    def test_merge_rejects_invalid_timestamps_and_unbounded_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.wsdb"
            second = root / "two.wsdb"
            make_session(first, "2026-01-01T00:00:00Z")
            make_session(second, "2026-01-02T00:00:00Z")
            with SessionStore(str(second)) as store:
                store.connection.execute("UPDATE events SET timestamp='not-a-timestamp'")
            with self.assertRaisesRegex(SessionError, "invalid event timestamp"):
                merge_sessions([str(first), str(second)], str(root / "invalid.wsdb"))
            self.assertFalse((root / "invalid.wsdb").exists())
            with SessionStore(str(second)) as store:
                store.connection.execute(
                    "UPDATE events SET timestamp='2026-01-02T00:00:00Z'"
                )

            with mock.patch("wirescope.lifecycle.MAX_MERGE_ROWS", 1):
                with self.assertRaisesRegex(SessionError, "row limit"):
                    merge_sessions([str(first), str(second)], str(root / "bounded.wsdb"))
            with mock.patch("wirescope.lifecycle.MAX_MERGE_TOTAL_BYTES", 1):
                with self.assertRaisesRegex(SessionError, "byte limit"):
                    merge_sessions([str(first), str(second)], str(root / "byte-bounded.wsdb"))

            calls = [0]

            def changed_hash(path):
                calls[0] += 1
                digest, size = _hash_file(path)
                if calls[0] >= 5:
                    return "0" * 64, size
                return digest, size

            changed_destination = root / "changed.wsdb"
            with mock.patch("wirescope.lifecycle._hash_file", side_effect=changed_hash):
                with self.assertRaisesRegex(SessionError, "changed before destination publication"):
                    merge_sessions([str(first), str(second)], str(changed_destination))
            self.assertFalse(changed_destination.exists())

            active_wal = Path(f"{first}-wal")
            active_wal.write_bytes(b"active")
            with self.assertRaisesRegex(SessionError, "active SQLite wal"):
                merge_sessions([str(first), str(second)], str(root / "wal.wsdb"))

    def test_prune_compares_instants_and_preserves_markers_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prune.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                old_sequence = store.add_event(
                    EventEnvelope(
                        event_type="old.unreferenced",
                        source="fixture",
                        timestamp="2026-01-01T00:30:00+01:00",
                    )
                )
                referenced_sequence = store.add_event(
                    EventEnvelope(
                        event_type="old.referenced",
                        source="fixture",
                        timestamp="2025-12-31T23:40:00Z",
                    )
                )
                store.add_event(
                    EventEnvelope(
                        event_type="user.marker",
                        source="user",
                        timestamp="2025-12-31T23:50:00Z",
                    )
                )
                store.add_event(
                    EventEnvelope(
                        event_type="new.event",
                        source="fixture",
                        timestamp="2025-12-31T23:45:00-01:00",
                    )
                )
                old_id = str(store.connection.execute("SELECT event_id FROM events WHERE sequence=?", (old_sequence,)).fetchone()[0])
                referenced_id = str(
                    store.connection.execute(
                        "SELECT event_id FROM events WHERE sequence=?", (referenced_sequence,)
                    ).fetchone()[0]
                )
                store.add_finding(
                    rule_id="fixture",
                    pack_id="tests",
                    pack_version="1.0.0",
                    title="Evidence",
                    category="test",
                    severity="notice",
                    confidence=1.0,
                    evidence=[{"event_id": referenced_id}],
                    limitations=["fixture"],
                    explanation="fixture",
                    recommendation="fixture",
                    session_id=session_id,
                )
                store.finish_session(session_id)

            preview = prune_session(str(path), before="2026-01-01T00:00:00Z")
            self.assertEqual(preview["candidate_count"], 1)
            self.assertEqual(preview["deleted_count"], 0)
            self.assertIn(referenced_id, preview["preserved_event_ids"])
            applied = prune_session(str(path), before="2026-01-01T00:00:00Z", apply=True)
            self.assertEqual(applied["deleted_count"], 1)
            with SessionStore(str(path), read_only=True) as store:
                remaining = {str(row[0]) for row in store.connection.execute("SELECT event_id FROM events")}
            self.assertNotIn(old_id, remaining)
            self.assertIn(referenced_id, remaining)

    def test_export_refuses_to_overwrite_the_source(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.wsdb"
            make_session(path, "2026-01-01T00:00:00Z")
            before = _hash_file(path)
            with self.assertRaisesRegex(SessionError, "cannot overwrite"):
                export_session(str(path), str(path), export_format="json")
            self.assertEqual(_hash_file(path), before)
            with self.assertRaisesRegex(SessionError, "unsupported"):
                export_session(str(path), str(Path(directory) / "unused"), export_format="yaml")
            jsonl = Path(directory) / "timeline.jsonl"
            result = export_session(str(path), str(jsonl), export_format="jsonl", private=True)
            self.assertEqual(result["events"], 1)
            self.assertEqual(len(jsonl.read_text(encoding="utf-8").splitlines()), 1)

    def test_prune_fails_closed_on_corrupt_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corrupt-evidence.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(
                    EventEnvelope(
                        event_type="old.event",
                        source="fixture",
                        timestamp="2020-01-01T00:00:00Z",
                    )
                )
                store.add_finding(
                    rule_id="fixture",
                    pack_id="tests",
                    pack_version="1.0.0",
                    title="Evidence",
                    category="test",
                    severity="notice",
                    confidence=1.0,
                    evidence=[{"event_id": "evt_unknown"}],
                    limitations=["fixture"],
                    explanation="fixture",
                    recommendation="fixture",
                    session_id=session_id,
                )
                store.connection.execute(
                    "UPDATE findings SET evidence_json='{broken' WHERE session_id=?", (session_id,)
                )
                store.finish_session(session_id)
            with self.assertRaisesRegex(SessionError, "finding evidence contains invalid JSON"):
                prune_session(str(path), before="2025-01-01T00:00:00Z", apply=True)
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(store.summary()["counts"]["events"], 1)

    def test_prune_preserves_cross_session_evidence_references(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cross-session.wsdb"
            with SessionStore(str(path)) as store:
                first = store.start_session(title="evidence source")
                sequence = store.add_event(
                    EventEnvelope(
                        event_type="old.cross-referenced",
                        source="fixture",
                        timestamp="2020-01-01T00:00:00Z",
                    )
                )
                event_id = str(
                    store.connection.execute(
                        "SELECT event_id FROM events WHERE sequence=?", (sequence,)
                    ).fetchone()[0]
                )
                store.finish_session(first)
                second = store.start_session(title="evidence owner")
                store.add_finding(
                    rule_id="cross-session",
                    pack_id="tests",
                    pack_version="1.0.0",
                    title="Cross-session evidence",
                    category="test",
                    severity="notice",
                    confidence=1.0,
                    evidence=[{"event_id": event_id}],
                    limitations=["fixture"],
                    explanation="fixture",
                    recommendation="fixture",
                    session_id=second,
                )
                store.finish_session(second)

            result = prune_session(
                str(path),
                before="2025-01-01T00:00:00Z",
                apply=True,
                session_id=first,
            )
            self.assertEqual(result["deleted_count"], 0)
            self.assertIn(event_id, result["preserved_event_ids"])
            self.assertTrue(verify_session(str(path))["passed"])

    def test_outputs_never_collide_with_sqlite_families(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "source.wsdb"
            second = root / "second.wsdb"
            make_session(first, "2026-01-01T00:00:00Z")
            make_session(second, "2026-01-02T00:00:00Z")
            before = _hash_file(first)
            for suffix in ("-wal", "-shm", "-journal"):
                collision = Path(f"{first}{suffix}")
                with self.assertRaisesRegex(SessionError, "SQLite|sidecar|destination"):
                    export_session(str(first), str(collision), export_format="json")
                with self.assertRaisesRegex(SessionError, "SQLite|sidecar|destination"):
                    create_support_bundle(str(first), str(collision))
                with self.assertRaisesRegex(SessionError, "SQLite|family|destination"):
                    merge_sessions([str(first), str(second)], str(collision))
            self.assertEqual(_hash_file(first), before)

            destination = root / "merged.wsdb"
            companion = Path(f"{destination}-wal")
            companion.write_bytes(b"pre-existing")
            with self.assertRaisesRegex(SessionError, "companion"):
                merge_sessions([str(first), str(second)], str(destination))
            self.assertFalse(destination.exists())

    def test_publication_rejects_destination_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "one.wsdb"
            second = root / "two.wsdb"
            destination = root / "merged.wsdb"
            make_session(first, "2026-01-01T00:00:00Z")
            make_session(second, "2026-01-02T00:00:00Z")
            real_link = os.link

            def replace_after_link(source, output, **kwargs):
                real_link(source, output, **kwargs)
                Path(output).unlink()
                Path(output).write_bytes(b"replacement")
                Path(output).chmod(0o600)

            with mock.patch("wirescope.lifecycle.os.link", side_effect=replace_after_link):
                with self.assertRaisesRegex(OSError, "changed during publication"):
                    merge_sessions([str(first), str(second)], str(destination))
            self.assertEqual(destination.read_bytes(), b"replacement")

    def test_support_bundles_are_deterministic_streamed_and_strictly_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wsdb"
            make_session(source, "2026-01-01T00:00:00Z")
            before = _hash_file(source)
            first = root / "first.zip"
            second = root / "second.zip"
            create_support_bundle(str(source), str(first), include_raw_private=True)
            create_support_bundle(str(source), str(second), include_raw_private=True)
            self.assertEqual(_hash_file(source), before)
            self.assertEqual(hashlib.sha256(first.read_bytes()).digest(), hashlib.sha256(second.read_bytes()).digest())
            self.assertTrue(verify_support_bundle(str(first))["passed"])
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), sorted(archive.namelist()))
                raw_payload = archive.read("raw/session.wsdb")
                bundle_manifest = json.loads(archive.read("manifest.json"))
                raw_descriptor = next(
                    item for item in bundle_manifest["files"]
                    if item["path"] == "raw/session.wsdb"
                )
                self.assertEqual(
                    hashlib.sha256(raw_payload).hexdigest(), raw_descriptor["sha256"]
                )
                extracted = root / "extracted.wsdb"
                extracted.write_bytes(raw_payload)
                extracted.chmod(0o600)
                self.assertTrue(verify_session(str(extracted))["passed"])
                payloads = {name: archive.read(name) for name in archive.namelist()}
                for info in archive.infolist():
                    mode = info.external_attr >> 16
                    self.assertTrue(stat.S_ISREG(mode))
                    self.assertEqual(stat.S_IMODE(mode), 0o600)
                    self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))

            with mock.patch("wirescope.lifecycle.MAX_GENERATED_BUNDLE_BYTES", 1):
                bounded = verify_support_bundle(str(first))
            self.assertFalse(bounded["passed"])
            self.assertFalse(
                next(
                    item for item in bounded["checks"]
                    if item["name"] == "bounded-entry-metadata"
                )["passed"]
            )

            session_data = json.loads(payloads["session.json"])
            session_data["sharing_safety"]["mode"] = "share-safe"
            payloads["session.json"] = (
                json.dumps(session_data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            manifest = json.loads(payloads["manifest.json"])
            session_descriptor = next(
                item for item in manifest["files"] if item["path"] == "session.json"
            )
            session_descriptor["size_bytes"] = len(payloads["session.json"])
            session_descriptor["sha256"] = hashlib.sha256(
                payloads["session.json"]
            ).hexdigest()
            payloads["manifest.json"] = (
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            inconsistent = root / "inconsistent-mode.zip"
            with zipfile.ZipFile(inconsistent, "w") as archive:
                for name in sorted(payloads):
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    info.compress_type = (
                        zipfile.ZIP_STORED
                        if name == "raw/session.wsdb"
                        else zipfile.ZIP_DEFLATED
                    )
                    archive.writestr(info, payloads[name])
            inconsistent.chmod(0o600)
            inconsistent_result = verify_support_bundle(str(inconsistent))
            self.assertFalse(inconsistent_result["passed"])
            self.assertFalse(
                next(
                    item for item in inconsistent_result["checks"]
                    if item["name"] == "session-sharing-mode"
                )["passed"]
            )

    def test_bundle_verifier_fails_closed_for_malformed_or_unbounded_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            malformed = root / "malformed.zip"
            malformed.write_bytes(b"not a zip")
            malformed.chmod(0o600)
            self.assertFalse(verify_support_bundle(str(malformed))["passed"])

            non_object = root / "non-object.zip"
            with zipfile.ZipFile(non_object, "w") as archive:
                archive.writestr("manifest.json", "[]")
            non_object.chmod(0o600)
            result = verify_support_bundle(str(non_object))
            self.assertFalse(result["passed"])
            self.assertFalse(next(item for item in result["checks"] if item["name"] == "manifest")["passed"])

            oversized = root / "oversized.zip"
            with zipfile.ZipFile(oversized, "w") as archive:
                archive.writestr("manifest.json", "{}")
                archive.writestr("payload.bin", b"12")
            oversized.chmod(0o600)
            with mock.patch("wirescope.lifecycle.MAX_BUNDLE_ENTRY_BYTES", 1):
                bounded = verify_support_bundle(str(oversized))
            self.assertFalse(bounded["passed"])
            self.assertFalse(
                next(item for item in bounded["checks"] if item["name"] == "bounded-entry-metadata")["passed"]
            )

            def zip_info(name):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                return info

            unsafe_names = root / "unsafe-names.zip"
            with zipfile.ZipFile(unsafe_names, "w") as archive:
                archive.writestr(zip_info("C:/drive.txt"), b"drive")
                archive.writestr(zip_info("control\nname.txt"), b"control")
                archive.writestr(zip_info("manifest.json"), b"{}")
            unsafe_names.chmod(0o600)
            unsafe = verify_support_bundle(str(unsafe_names))
            self.assertFalse(unsafe["passed"])
            self.assertFalse(
                next(item for item in unsafe["checks"] if item["name"] == "safe-entry-paths")["passed"]
            )

            ratio_bomb = root / "ratio.zip"
            with zipfile.ZipFile(ratio_bomb, "w") as archive:
                archive.writestr(zip_info("payload.bin"), b"0" * (2 * 1024 * 1024))
                archive.writestr(zip_info("manifest.json"), b"{}")
            ratio_bomb.chmod(0o600)
            ratio = verify_support_bundle(str(ratio_bomb))
            self.assertFalse(ratio["passed"])
            self.assertFalse(
                next(item for item in ratio["checks"] if item["name"] == "bounded-entry-metadata")["passed"]
            )

            too_many = root / "too-many.zip"
            with zipfile.ZipFile(too_many, "w") as archive:
                for index in range(65):
                    archive.writestr(zip_info(f"entry-{index}.txt"), b"")
            too_many.chmod(0o600)
            with mock.patch(
                "wirescope.lifecycle.zipfile.ZipFile",
                side_effect=AssertionError("ZipFile must not parse an oversized directory"),
            ):
                too_many_result = verify_support_bundle(str(too_many))
            self.assertFalse(too_many_result["passed"])
            self.assertIn(
                "declares 65 entries",
                next(
                    item for item in too_many_result["checks"]
                    if item["name"] == "zip-integrity"
                )["detail"],
            )

            incomplete = root / "incomplete.zip"
            review_payload = b"review first\n"
            incomplete_manifest = {
                "schema_version": 1,
                "kind": "wirescope-support-bundle",
                "sharing_mode": "share-safe",
                "human_review_required": True,
                "visible_evidence_warning": "Review visible evidence.",
                "files": [
                    {
                        "path": "REVIEW.md",
                        "size_bytes": len(review_payload),
                        "sha256": hashlib.sha256(review_payload).hexdigest(),
                    }
                ],
            }
            with zipfile.ZipFile(incomplete, "w") as archive:
                archive.writestr(zip_info("REVIEW.md"), review_payload)
                archive.writestr(
                    zip_info("manifest.json"),
                    json.dumps(incomplete_manifest, sort_keys=True).encode("utf-8"),
                )
            incomplete.chmod(0o600)
            incomplete_result = verify_support_bundle(str(incomplete))
            self.assertFalse(incomplete_result["passed"])
            self.assertFalse(
                next(
                    item for item in incomplete_result["checks"] if item["name"] == "manifest"
                )["passed"]
            )

    def test_bundle_is_not_published_when_temporary_verification_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wsdb"
            destination = root / "support.zip"
            make_session(source, "2026-01-01T00:00:00Z")
            with mock.patch(
                "wirescope.lifecycle.verify_support_bundle",
                return_value={"passed": False, "checks": [{"name": "fixture", "passed": False}]},
            ):
                with self.assertRaisesRegex(SessionError, "temporary bundle failed verification"):
                    create_support_bundle(str(source), str(destination))
            self.assertFalse(destination.exists())

    def test_bundle_contract_rejects_boolean_schema_and_capability_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.wsdb"
            original = root / "original.zip"
            make_session(source, "2026-01-01T00:00:00Z")
            create_support_bundle(str(source), str(original))
            with zipfile.ZipFile(original) as archive:
                original_payloads = {
                    name: archive.read(name) for name in archive.namelist()
                }

            def write_archive(path, payloads):
                with zipfile.ZipFile(path, "w") as archive:
                    for name in sorted(payloads):
                        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | 0o600) << 16
                        info.compress_type = zipfile.ZIP_DEFLATED
                        archive.writestr(info, payloads[name])
                path.chmod(0o600)

            boolean_payloads = dict(original_payloads)
            boolean_manifest = json.loads(boolean_payloads["manifest.json"])
            boolean_manifest["schema_version"] = True
            boolean_payloads["manifest.json"] = json.dumps(
                boolean_manifest, sort_keys=True
            ).encode("utf-8")
            boolean_bundle = root / "boolean-schema.zip"
            write_archive(boolean_bundle, boolean_payloads)
            boolean_result = verify_support_bundle(str(boolean_bundle))
            self.assertFalse(boolean_result["passed"])
            self.assertFalse(
                next(
                    item for item in boolean_result["checks"] if item["name"] == "manifest"
                )["passed"]
            )

            capability_payloads = dict(original_payloads)
            capability_payloads["capability.json"] = json.dumps(
                {"schema_version": 1, "sessions": []}, sort_keys=True
            ).encode("utf-8")
            capability_manifest = json.loads(capability_payloads["manifest.json"])
            descriptor = next(
                item for item in capability_manifest["files"]
                if item["path"] == "capability.json"
            )
            descriptor["size_bytes"] = len(capability_payloads["capability.json"])
            descriptor["sha256"] = hashlib.sha256(
                capability_payloads["capability.json"]
            ).hexdigest()
            capability_payloads["manifest.json"] = json.dumps(
                capability_manifest, sort_keys=True
            ).encode("utf-8")
            capability_bundle = root / "capability-mismatch.zip"
            write_archive(capability_bundle, capability_payloads)
            capability_result = verify_support_bundle(str(capability_bundle))
            self.assertFalse(capability_result["passed"])
            self.assertFalse(
                next(
                    item for item in capability_result["checks"]
                    if item["name"] == "capability-contract"
                )["passed"]
            )


if __name__ == "__main__":
    unittest.main()
