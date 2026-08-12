from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path

from wirescope.models import Connection, Endpoint
from wirescope.redact import RedactionRules
from wirescope.session import CorrelationEngine, SessionError, SessionStore
from wirescope.session_report import build_session_report_data, generate_session_html


class SessionReportTests(unittest.TestCase):
    def make_session(self, directory: str) -> Path:
        path = Path(directory) / "input.wsdb"
        with SessionStore(str(path)) as store:
            session_id = store.start_session(title="Private /Users/alice/project")
            connection = Connection(
                process="Example",
                pid=123,
                user="alice",
                fd="9u",
                family="IPv4",
                protocol="TCP",
                local=Endpoint("192.168.1.5", "50000"),
                remote=Endpoint("203.0.113.10", "443"),
                state="ESTABLISHED",
            )
            CorrelationEngine(store, session_id).observe_connection(connection, "connection.opened")
            store.finish_session(session_id)
        return path

    def test_report_is_offline_private_and_contains_timeline(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.make_session(directory)
            output = Path(directory) / "report.html"
            data = generate_session_html(str(session), str(output))
            document = output.read_text(encoding="utf-8")
            self.assertEqual(data["summary"]["counts"]["events"], 1)
            self.assertIn("connection.opened", document)
            self.assertNotIn("https://", document)
            self.assertNotIn("<script src=", document)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_share_safe_report_redacts_machine_identifiers(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.make_session(directory)
            data = build_session_report_data(str(session), share_safe=True)
            serialized = json.dumps(data, ensure_ascii=False)
            self.assertNotIn("203.0.113.10", serialized)
            self.assertNotIn("192.168.1.5", serialized)
            self.assertNotIn("/Users/alice/project", serialized)
            self.assertEqual(data["sharing_safety"]["mode"], "share-safe")
            self.assertFalse(data["sharing_safety"]["safe_to_publish_without_review"])
            self.assertIsInstance(data["summary"]["sessions"], list)
            self.assertIsInstance(data["summary"]["events_by_type"], dict)
            self.assertIsInstance(data["timeline"], list)
            self.assertEqual(data["summary"]["events_by_type"]["connection.opened"], 1)

    def test_report_refuses_to_replace_source_database(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.make_session(directory)
            with self.assertRaisesRegex(SessionError, "must not replace"):
                generate_session_html(str(session), str(session))
            self.assertEqual(session.read_bytes()[:16], b"SQLite format 3\x00")

    def test_custom_share_safe_rules_redact_content_without_breaking_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            session = self.make_session(directory)
            data = build_session_report_data(
                str(session),
                share_safe=True,
                redaction_rules=RedactionRules(key_patterns=("sessions", "timeline")),
            )
            self.assertEqual(data["summary"]["sessions"], [])
            self.assertEqual(data["timeline"], [])
            self.assertIsInstance(data["entities"], list)


if __name__ == "__main__":
    unittest.main()
