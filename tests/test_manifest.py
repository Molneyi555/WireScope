from __future__ import annotations

import copy
import json
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wirescope.manifest import (
    ManifestError,
    check_manifest,
    discover_manifest,
    load_manifest,
    validate_manifest,
    write_junit,
)
from wirescope.session import CorrelationEngine, SessionStore


def write_har(path: Path, domain: str = "api.example.com") -> None:
    path.write_text(
        json.dumps(
            {
                "log": {
                    "version": "1.2",
                    "entries": [
                        {
                            "startedDateTime": "2026-01-01T00:00:00Z",
                            "time": 20,
                            "request": {"method": "GET", "url": f"https://{domain}/v1/data"},
                            "response": {
                                "status": 200,
                                "httpVersion": "h2",
                                "bodySize": 10,
                                "headersSize": 5,
                                "content": {"mimeType": "application/json"},
                            },
                            "serverIPAddress": "203.0.113.20",
                            "timings": {"dns": 1, "connect": 2, "wait": 4, "receive": 2},
                            "cache": {},
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )


class ManifestTests(unittest.TestCase):
    def test_discover_is_unapproved_and_cannot_self_approve(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            output = Path(directory) / "network-manifest.json"
            write_har(source)
            manifest = discover_manifest(str(source), str(output), profile="ci")
            self.assertEqual(manifest["mode"], "proposal")
            self.assertFalse(manifest["approved"])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(manifest["profiles"]["ci"]["domains"]["allowed"], ["api.example.com"])
            with self.assertRaisesRegex(ManifestError, "unapproved proposal"):
                check_manifest(manifest, str(source), profile_name="ci")

            self_approved = copy.deepcopy(manifest)
            self_approved["approved"] = True
            with self.assertRaisesRegex(ManifestError, "cannot approve itself"):
                validate_manifest(self_approved)

    def test_reviewed_policy_passes_and_results_are_stably_ordered(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            write_har(source)
            manifest = discover_manifest(str(source), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            first = check_manifest(manifest, str(source), profile_name="ci")
            second = check_manifest(manifest, str(source), profile_name="ci")
            self.assertTrue(first["passed"])
            self.assertEqual(first["exit_code"], 0)
            self.assertEqual(
                json.dumps(first, sort_keys=True, separators=(",", ":")),
                json.dumps(second, sort_keys=True, separators=(",", ":")),
            )
            identifiers = [item["id"] for item in first["checks"]]
            self.assertEqual(identifiers, sorted(identifiers))

    def test_violation_and_required_unevaluable_are_not_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            write_har(source)
            manifest = discover_manifest(str(source), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            profile = manifest["profiles"]["ci"]
            profile["domains"]["allowed"] = ["other.example.net"]
            profile["domains"]["allowed_registrable"] = []
            profile["resolvers"] = ["1.1.1.1"]
            profile["budgets"] = {"request_count": 0}
            result = check_manifest(manifest, str(source), profile_name="ci")
            self.assertFalse(result["passed"])
            self.assertEqual(result["exit_code"], 1)
            statuses = {item["id"]: item["status"] for item in result["checks"]}
            self.assertEqual(statuses["domains.allowed"], "violation")
            self.assertEqual(statuses["budget.request_count"], "violation")
            self.assertEqual(statuses["resolvers"], "unevaluable")

    def test_optional_capability_gap_is_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            write_har(source)
            manifest = discover_manifest(str(source), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            manifest["profiles"]["ci"]["resolvers"] = ["1.1.1.1"]
            manifest["profiles"]["ci"]["optional_checks"] = ["resolvers"]
            result = check_manifest(manifest, str(source), profile_name="ci")
            self.assertTrue(result["passed"])
            self.assertEqual(result["summary"]["warnings"], 1)

    def test_typos_remote_references_and_unknown_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            write_har(source)
            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["unknown_operator"] = "ignore-me"
            with self.assertRaisesRegex(ManifestError, "unknown fields"):
                validate_manifest(manifest)
            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["baseline"] = "https://example.com/policy.wsbaseline"
            with self.assertRaisesRegex(ManifestError, "remote"):
                validate_manifest(manifest)

    def test_junit_output_represents_failure_and_is_private(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.xml"
            result = {
                "summary": {"violations": 1, "required_unevaluable": 0, "warnings": 0},
                "checks": [
                    {
                        "id": "domains.allowed",
                        "status": "violation",
                        "required": True,
                        "expected": [],
                        "actual": ["example.com"],
                        "evidence": ["example.com"],
                    }
                ],
            }
            write_junit(result, str(output))
            self.assertIn("<failure", output.read_text(encoding="utf-8"))
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_partial_session_evidence_is_unevaluable_not_a_false_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partial.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(config={"capabilities": {}})
                engine = CorrelationEngine(store, session_id)
                engine.observe_normalized_request(
                    {
                        "id": "complete",
                        "url": "https://api.example.com/one",
                        "domain": "api.example.com",
                        "scheme": "https",
                        "method": "GET",
                        "duration_ms": 20,
                        "transfer_bytes": 10,
                        "status": 200,
                        "failed": False,
                        "protocol": "h2",
                        "remote_port": 443,
                        "timing": {"ttfb_ms": 4},
                        "security_details": {"protocol": "TLS 1.3"},
                        "tracker_match": None,
                    },
                    source="fixture",
                )
                engine.observe_normalized_request(
                    {
                        "id": "partial",
                        "url": "https://unknown.invalid/two",
                        "scheme": "https",
                        "method": "GET",
                        "duration_ms": 20,
                        "status": 200,
                        "failed": False,
                        "protocol": "h2",
                        "remote_port": 443,
                        "timing": {"ttfb_ms": 4},
                        "tracker_match": None,
                    },
                    source="fixture",
                )
                store.finish_session(session_id)

            manifest = discover_manifest(str(path), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            profile = manifest["profiles"]["ci"]
            profile["domains"]["allowed"] = ["api.example.com"]
            profile["domains"]["allowed_registrable"] = ["example.com"]
            profile["domains"]["denied"] = ["blocked.example"]
            profile["tls_minimum"] = "TLS 1.2"
            profile["budgets"] = {"transfer_bytes": 100}
            result = check_manifest(manifest, str(path), profile_name="ci")
            statuses = {item["id"]: item["status"] for item in result["checks"]}
            self.assertEqual(statuses["domains.allowed"], "unevaluable")
            self.assertEqual(statuses["domains.denied"], "unevaluable")
            self.assertEqual(statuses["tls"], "unevaluable")
            self.assertEqual(statuses["budget.transfer_bytes"], "unevaluable")
            self.assertFalse(result["passed"])

    def test_finding_codes_are_preserved_for_policy_and_required_checks(self):
        report = {
            "requests": [
                {
                    "domain": "api.example.com",
                    "scheme": "https",
                    "protocol": "h2",
                    "remote_port": 443,
                    "duration_ms": 10,
                    "transfer_bytes": 20,
                    "status": 200,
                    "failed": False,
                    "timing": {"ttfb_ms": 2},
                    "security_details": {"protocol": "TLS 1.3"},
                    "tracker_match": None,
                }
            ],
            "findings": [{"code": "privacy.exposure"}],
        }
        with mock.patch("wirescope.manifest.analyze_recording", return_value=report):
            manifest = discover_manifest("fixture.har", profile="ci")
            self.assertEqual(manifest["profiles"]["ci"]["allowed_rule_ids"], ["privacy.exposure"])
            manifest["mode"] = "policy"
            manifest["approved"] = True
            manifest["profiles"]["ci"]["required_findings"] = ["privacy.exposure"]
            result = check_manifest(manifest, "fixture.har", profile_name="ci")
        statuses = {item["id"]: item["status"] for item in result["checks"]}
        self.assertEqual(statuses["finding.required.privacy.exposure"], "pass")
        self.assertEqual(statuses["rules.allowed"], "pass")
        self.assertTrue(result["passed"])

    def test_manifest_rejects_nonfinite_unknown_and_ambiguous_policy_values(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            write_har(source)
            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["budgets"] = {"request_count": float("nan")}
            with self.assertRaisesRegex(ManifestError, "finite JSON"):
                validate_manifest(manifest)

            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["budgets"] = {"request_cout": 1}
            with self.assertRaisesRegex(ManifestError, "budgets"):
                validate_manifest(manifest)

            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["domains"]["allowed_registrable"] = ["com"]
            with self.assertRaisesRegex(ManifestError, "registrable domains"):
                validate_manifest(manifest)

            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["domains"]["allowed"] = ["API.EXAMPLE.COM"]
            manifest["profiles"]["ci"]["domains"]["denied"] = ["api.example.com."]
            with self.assertRaisesRegex(ManifestError, "allow and deny"):
                validate_manifest(manifest)

            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "duplicate"):
                load_manifest(str(duplicate))

            manifest = discover_manifest(str(source), profile="ci")
            manifest["schema_version"] = True
            with self.assertRaisesRegex(ManifestError, "unsupported"):
                validate_manifest(manifest)

            manifest = discover_manifest(str(source), profile="ci")
            manifest["profiles"]["ci"]["budgets"] = {"request_count": 10**10000}
            with self.assertRaisesRegex(ManifestError, "budgets"):
                validate_manifest(manifest)

    def test_public_suffix_apex_is_exact_only_in_discovered_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "capture.har"
            write_har(source, domain="github.io")
            manifest = discover_manifest(str(source), profile="ci")
            domains = manifest["profiles"]["ci"]["domains"]
            self.assertEqual(domains["allowed"], ["github.io"])
            self.assertEqual(domains["allowed_registrable"], [])

    def test_insecure_tls_metadata_cannot_hide_missing_https_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tls-evidence.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(config={"capabilities": {}})
                engine = CorrelationEngine(store, session_id)
                engine.observe_normalized_request(
                    {
                        "id": "secure-without-tls",
                        "url": "https://secure.example/",
                        "domain": "secure.example",
                        "scheme": "https",
                        "method": "GET",
                        "duration_ms": 10,
                        "transfer_bytes": 10,
                        "status": 200,
                        "failed": False,
                        "protocol": "h2",
                        "remote_port": 443,
                        "timing": {"ttfb_ms": 1},
                        "tracker_match": None,
                    },
                    source="fixture",
                )
                engine.observe_normalized_request(
                    {
                        "id": "insecure-with-spurious-tls",
                        "url": "http://insecure.example/",
                        "domain": "insecure.example",
                        "scheme": "http",
                        "method": "GET",
                        "duration_ms": 10,
                        "transfer_bytes": 10,
                        "status": 200,
                        "failed": False,
                        "protocol": "http/1.1",
                        "remote_port": 80,
                        "timing": {"ttfb_ms": 1},
                        "security_details": {"protocol": "TLS 1.3"},
                        "tracker_match": None,
                    },
                    source="fixture",
                )
                store.finish_session(session_id)

            manifest = discover_manifest(str(path), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            manifest["profiles"]["ci"]["tls_minimum"] = "TLS 1.2"
            result = check_manifest(manifest, str(path), profile_name="ci")
            tls = next(item for item in result["checks"] if item["id"] == "tls")
            self.assertEqual(tls["status"], "unevaluable")
            self.assertFalse(result["passed"])

    def test_request_domains_cannot_be_hidden_by_stale_entities(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "domain-disagreement.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(config={"capabilities": {}})
                CorrelationEngine(store, session_id).observe_normalized_request(
                    {
                        "id": "request",
                        "url": "https://good.example/",
                        "domain": "good.example",
                        "scheme": "https",
                        "method": "GET",
                        "duration_ms": 10,
                        "transfer_bytes": 10,
                        "status": 200,
                        "failed": False,
                        "protocol": "h2",
                        "remote_port": 443,
                        "timing": {"ttfb_ms": 1},
                        "security_details": {"protocol": "TLS 1.3"},
                        "tracker_match": None,
                    },
                    source="fixture",
                )
                store.finish_session(session_id)
            connection = sqlite3.connect(str(path))
            payload = json.loads(
                connection.execute("SELECT payload_json FROM events LIMIT 1").fetchone()[0]
            )
            payload["request"]["domain"] = "evil.example"
            connection.execute(
                "UPDATE events SET payload_json=?", (json.dumps(payload, sort_keys=True),)
            )
            connection.commit()
            connection.close()

            manifest = discover_manifest(str(path), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            domains = manifest["profiles"]["ci"]["domains"]
            domains["allowed"] = ["good.example"]
            domains["allowed_registrable"] = []
            result = check_manifest(manifest, str(path), profile_name="ci")
            allowed = next(
                item for item in result["checks"] if item["id"] == "domains.allowed"
            )
            self.assertEqual(allowed["status"], "violation")
            self.assertEqual(allowed["actual"], ["evil.example"])

    def test_absent_finding_is_unknown_until_a_rule_pack_was_applied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unanalyzed.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session(config={"capabilities": {}})
                store.finish_session(session_id)
            manifest = discover_manifest(str(path), profile="ci")
            manifest["mode"] = "policy"
            manifest["approved"] = True
            manifest["profiles"]["ci"]["forbidden_findings"] = ["dns-failure"]
            result = check_manifest(manifest, str(path), profile_name="ci")
            finding = next(
                item for item in result["checks"]
                if item["id"] == "finding.forbidden.dns-failure"
            )
            self.assertEqual(finding["status"], "unevaluable")
            self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
