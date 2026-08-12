from __future__ import annotations

import contextlib
import io
import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from wirescope import cli
from wirescope.models import Connection, Endpoint
from wirescope.session import CorrelationEngine, EventEnvelope, SessionStore


class FakeAdapter:
    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self):
        return {"schema_version": 1, "capabilities": {"connections": {"available": True}}}

    def connections(self):
        self.calls += 1
        if self.calls > 1:
            return []
        return [
            Connection(
                process="Example",
                pid=7,
                user="tester",
                fd="3u",
                family="IPv4",
                protocol="TCP",
                local=Endpoint("127.0.0.1", "5000"),
                remote=Endpoint("198.51.100.2", "443"),
                state="ESTABLISHED",
            )
        ]

    def routes(self):
        return []

    def dns_resolvers(self):
        return []

    def vpn_status(self):
        return {"active": False}

    def proxy_config(self):
        return {}


class SessionCLITests(unittest.TestCase):
    def run_cli(self, arguments):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            cli.main(arguments)
        return stdout.getvalue(), stderr.getvalue()

    def make_session(self, directory, name="test.wsdb", *, title="CLI lifecycle"):
        path = Path(directory) / name
        with SessionStore(str(path)) as store:
            session_id = store.start_session(title=title)
            store.add_event(
                EventEnvelope(
                    event_type="test.event",
                    source="test",
                    payload={"address": "203.0.113.10", "path": "/Users/alice/private"},
                    timestamp="2026-01-02T00:00:00.000+00:00",
                )
            )
            store.finish_session(session_id)
        return path, session_id

    def test_session_show_timeline_and_mark(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(title="CLI")
                store.add_event(EventEnvelope(event_type="dns.changed", source="test", payload={"resolver": "1.1.1.1"}))
                store.finish_session(session_id)

            output, _ = self.run_cli(["session", "show", str(path), "--json"])
            self.assertEqual(json.loads(output)["counts"]["events"], 1)
            output, _ = self.run_cli(["session", "timeline", str(path), "--type", "dns.*"])
            self.assertIn("dns.changed", output)
            output, _ = self.run_cli(["session", "mark", str(path), "user noticed a delay"])
            self.assertIn("Marker", output)
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(store.summary()["events_by_type"]["user.marker"], 1)

    def test_record_auto_selects_private_wsdb(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recording.wsdb"
            fake = FakeAdapter()
            with mock.patch("wirescope.cli.MacOSAdapter", return_value=fake):
                output, _ = self.run_cli(
                    ["record", "--duration", "0.02", "--interval", "0.01", "--output", str(path)]
                )
            self.assertIn("events", output)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with SessionStore(str(path), read_only=True) as store:
                self.assertGreater(store.summary()["counts"]["events"], 0)

    def test_share_safe_flags_and_session_actions_parse(self):
        parser = cli.build_parser({})
        args = parser.parse_args(
            ["report", "input.jsonl", "--share-safe", "--redact-header", "X-Private-*", "--redact-key", "customer_id"]
        )
        self.assertTrue(args.share_safe)
        rules = cli.redaction_rules_from_args(args)
        self.assertIn("X-Private-*", rules.header_patterns)
        self.assertIn("customer_id", rules.key_patterns)
        action = parser.parse_args(["session", "who", "capture.wsdb", "example.com"])
        self.assertEqual(action.session_action, "who")
        action = parser.parse_args(["session", "ingest", "capture.wsdb", "browser.har"])
        self.assertEqual(action.session_action, "ingest")
        action = parser.parse_args(["session", "migrate", "old.wsdb", "-o", "new.wsdb", "--overwrite"])
        self.assertTrue(action.overwrite)
        action = parser.parse_args(["session", "verify", "capture.wsdb", "--json"])
        self.assertTrue(action.json)
        action = parser.parse_args(
            [
                "session",
                "merge",
                "--source",
                "one.wsdb",
                "--source",
                "two.wsdb",
                "--clock-offset",
                "two.wsdb=125.5",
                "-o",
                "merged.wsdb",
            ]
        )
        self.assertEqual(action.source_files, ["one.wsdb", "two.wsdb"])
        self.assertEqual(action.clock_offsets, ["two.wsdb=125.5"])
        action = parser.parse_args(["session", "prune", "capture.wsdb", "--before", "2026-01-01"])
        self.assertFalse(action.apply)
        action = parser.parse_args(["session", "export", "capture.wsdb", "-o", "safe.json"])
        self.assertFalse(action.private)
        action = parser.parse_args(
            ["session", "bundle", "create", "capture.wsdb", "-o", "support.zip", "--include-raw-private"]
        )
        self.assertTrue(action.include_raw_private)

    def test_who_reports_the_owning_process(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "who.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                connection = Connection(
                    process="Example",
                    pid=7,
                    user="tester",
                    fd="3u",
                    family="IPv4",
                    protocol="TCP",
                    local=Endpoint("127.0.0.1", "5000"),
                    remote=Endpoint("198.51.100.2", "443"),
                    state="ESTABLISHED",
                )
                CorrelationEngine(store, session_id).observe_connection(connection, "connection.opened")
                store.finish_session(session_id)
            output, _ = self.run_cli(["session", "who", str(path), "198.51.100.2", "--json"])
            value = json.loads(output)
            self.assertEqual(value["paths"][0]["actor"]["label"], "Example (7)")
            self.assertEqual(value["paths"][0]["hops"], 2)

    def test_mark_does_not_create_a_session_for_a_missing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "typo.wsdb"
            with self.assertRaises(SystemExit) as raised:
                self.run_cli(["session", "mark", str(path), "marker"])
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse(path.exists())

    def test_verify_cli_is_machine_readable_and_uses_exit_one_for_failed_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "verify.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)

            output, _ = self.run_cli(["session", "verify", str(path), "--json"])
            self.assertTrue(json.loads(output)["passed"])

            path.chmod(0o644)
            with self.assertRaises(SystemExit) as raised:
                self.run_cli(["session", "verify", str(path), "--json"])
            self.assertEqual(raised.exception.code, 1)

    def test_tag_and_list_tags_are_sorted_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path, session_id = self.make_session(directory)
            output, _ = self.run_cli(
                ["session", "tag", str(path), "regression", "vpn", "regression", "--json"]
            )
            result = json.loads(output)
            self.assertEqual(result["session_id"], session_id)
            self.assertEqual(result["tags"], ["regression", "vpn"])
            output, _ = self.run_cli(["session", "list-tags", str(path), "--json"])
            self.assertEqual(json.loads(output)["tags"], ["regression", "vpn"])

    def test_mutating_lifecycle_commands_do_not_create_missing_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.wsdb"
            for arguments in (
                ["session", "tag", str(missing), "test"],
                ["session", "prune", str(missing), "--before", "2026-01-01", "--apply"],
            ):
                with self.assertRaises(SystemExit) as raised:
                    self.run_cli(arguments)
                self.assertEqual(raised.exception.code, 2)
                self.assertFalse(missing.exists())

    def test_merge_accepts_repeatable_sources_and_checked_clock_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            first, _ = self.make_session(directory, "one.wsdb", title="One")
            second, _ = self.make_session(directory, "two.wsdb", title="Two")
            destination = Path(directory) / "merged.wsdb"
            output, _ = self.run_cli(
                [
                    "session",
                    "merge",
                    "--source",
                    str(first),
                    "--source",
                    str(second),
                    "--clock-offset",
                    f"{second}=1500",
                    "--output",
                    str(destination),
                    "--json",
                ]
            )
            result = json.loads(output)
            self.assertEqual(result["sessions"], 2)
            self.assertEqual(result["events"], 2)
            self.assertTrue(result["source_files_unchanged"])
            self.assertIn(1500.0, [item["clock_offset_ms"] for item in result["sources"]])
            with SessionStore(str(destination), read_only=True) as store:
                self.assertEqual(store.summary()["counts"]["events"], 2)

            invalid = Path(directory) / "invalid.wsdb"
            with self.assertRaises(SystemExit) as raised:
                self.run_cli(
                    [
                        "session",
                        "merge",
                        str(first),
                        str(second),
                        "--clock-offset",
                        f"{invalid}=1",
                        "-o",
                        str(Path(directory) / "unused.wsdb"),
                    ]
                )
            self.assertEqual(raised.exception.code, 2)

    def test_prune_is_dry_run_by_default_and_preserves_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "prune.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(
                    EventEnvelope(
                        event_type="old.unreferenced",
                        source="test",
                        timestamp="2020-01-01T00:00:00.000+00:00",
                    )
                )
                store.add_event(
                    EventEnvelope(
                        event_type="user.marker",
                        source="user",
                        payload={"message": "keep"},
                        timestamp="2020-01-01T00:00:01.000+00:00",
                    )
                )
                store.add_event(
                    EventEnvelope(
                        event_type="new.event",
                        source="test",
                        timestamp="2030-01-01T00:00:00.000+00:00",
                    )
                )
                store.finish_session(session_id)

            output, _ = self.run_cli(
                ["session", "prune", str(path), "--before", "2025-01-01", "--json"]
            )
            preview = json.loads(output)
            self.assertEqual(preview["mode"], "dry-run")
            self.assertEqual(preview["candidate_count"], 1)
            self.assertEqual(preview["deleted_count"], 0)
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(store.summary()["counts"]["events"], 3)

            output, _ = self.run_cli(
                ["session", "prune", str(path), "--before", "2025-01-01", "--apply", "--json"]
            )
            applied = json.loads(output)
            self.assertEqual(applied["deleted_count"], 1)
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(store.summary()["counts"]["events"], 2)
                self.assertEqual(len(store.timeline(event_type="user.marker")), 1)

    def test_session_export_defaults_share_safe_and_private_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.make_session(directory)
            safe_json = Path(directory) / "safe.json"
            private_json = Path(directory) / "private.json"
            safe_html = Path(directory) / "safe.html"

            output, _ = self.run_cli(
                ["session", "export", str(path), "-o", str(safe_json), "--json"]
            )
            self.assertEqual(json.loads(output)["sharing_mode"], "share-safe")
            safe_payload = json.loads(safe_json.read_text(encoding="utf-8"))
            self.assertEqual(safe_payload["sharing_safety"]["mode"], "share-safe")
            self.assertNotIn("203.0.113.10", safe_json.read_text(encoding="utf-8"))
            self.assertNotIn("/Users/alice/private", safe_json.read_text(encoding="utf-8"))

            output, _ = self.run_cli(
                ["session", "export", str(path), "-o", str(private_json), "--private", "--json"]
            )
            self.assertEqual(json.loads(output)["sharing_mode"], "private")
            self.assertIn("203.0.113.10", private_json.read_text(encoding="utf-8"))

            output, _ = self.run_cli(
                ["session", "export", str(path), "-o", str(safe_html), "--json"]
            )
            self.assertEqual(json.loads(output)["format"], "html")
            self.assertNotIn("203.0.113.10", safe_html.read_text(encoding="utf-8"))

    def test_support_bundle_create_verify_and_private_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _ = self.make_session(directory)
            safe_bundle = Path(directory) / "support-safe.zip"
            private_bundle = Path(directory) / "support-private.zip"

            output, _ = self.run_cli(
                ["session", "bundle", "create", str(path), "-o", str(safe_bundle), "--json"]
            )
            created = json.loads(output)
            self.assertEqual(created["sharing_mode"], "share-safe")
            self.assertTrue(created["verified"])
            with zipfile.ZipFile(safe_bundle) as archive:
                self.assertNotIn("raw/session.wsdb", archive.namelist())

            output, _ = self.run_cli(
                ["session", "bundle", "verify", str(safe_bundle), "--json"]
            )
            self.assertTrue(json.loads(output)["passed"])

            safe_bundle.chmod(0o644)
            with self.assertRaises(SystemExit) as raised:
                self.run_cli(["session", "bundle", "verify", str(safe_bundle), "--json"])
            self.assertEqual(raised.exception.code, 1)
            safe_bundle.chmod(0o600)

            output, _ = self.run_cli(
                [
                    "session",
                    "bundle",
                    "create",
                    str(path),
                    "-o",
                    str(private_bundle),
                    "--include-raw-private",
                    "--json",
                ]
            )
            self.assertEqual(json.loads(output)["sharing_mode"], "private")
            with zipfile.ZipFile(private_bundle) as archive:
                self.assertIn("raw/session.wsdb", archive.namelist())


if __name__ == "__main__":
    unittest.main()
