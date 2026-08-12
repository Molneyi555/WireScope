from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wirescope.rules import (
    MAX_RULE_PACK_BYTES,
    RulePackError,
    analyze_session_with_rules,
    builtin_rule_pack,
    load_rule_pack,
    show_rule,
    validate_rule_pack,
)
from wirescope.session import EventEnvelope, SessionError, SessionStore, verify_session


def custom_pack(predicate):
    return {
        "schema_version": 1,
        "id": "example.tests",
        "version": "1.0.0",
        "min_wirescope_version": "0.3.0rc1",
        "rules": [
            {
                "id": "example-rule",
                "title": "Example rule",
                "category": "test",
                "severity": "warning",
                "confidence": 0.65,
                "when": predicate,
                "evidence": {
                    "source": "events",
                    "where": {"field": "event_type", "op": "eq", "value": "test.observed"},
                    "limit": 5,
                },
                "limitations": ["This fixture intentionally represents ambiguous evidence."],
                "explanation": "The bounded test predicate matched.",
                "remediation": "Inspect the referenced event.",
            }
        ],
    }


class RulePackTests(unittest.TestCase):
    def test_builtin_analysis_is_idempotent_and_every_finding_is_explainable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(
                    EventEnvelope(
                        event_type="http.request.observed",
                        source="test",
                        payload={"request": {"duration_ms": 1500, "scheme": "http"}},
                    )
                )
                store.finish_session(session_id)

            first = analyze_session_with_rules(str(path))
            second = analyze_session_with_rules(str(path))

            def stable(value):
                return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

            self.assertEqual(stable(first), stable(second))
            self.assertEqual(first["finding_count"], 3)
            self.assertTrue(all(item["evidence"] for item in first["findings"]))
            self.assertTrue(all(item["limitations"] for item in first["findings"]))
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(len(store.findings()), 3)
                why = store.why("slow-load-path")
                self.assertEqual(why["finding"]["rule_id"], "slow-load-path")
                self.assertEqual(why["events"][0]["event_type"], "http.request.observed")
            self.assertTrue(verify_session(str(path))["passed"])

    def test_positive_negative_and_ambiguous_custom_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custom.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(EventEnvelope(event_type="test.observed", source="fixture", payload={"value": 7}))
                store.finish_session(session_id)

            positive = custom_pack(
                {
                    "count": {
                        "source": "events",
                        "where": {"field": "payload.value", "op": "gte", "value": 7},
                    },
                    "op": "eq",
                    "value": 1,
                }
            )
            result = analyze_session_with_rules(str(path), [positive])
            self.assertEqual(result["finding_count"], 1)
            self.assertEqual(result["findings"][0]["confidence"], 0.65)

            negative = custom_pack(
                {
                    "count": {
                        "source": "events",
                        "where": {"field": "payload.value", "op": "gt", "value": 100},
                    },
                    "op": "gte",
                    "value": 1,
                }
            )
            self.assertEqual(analyze_session_with_rules(str(path), [negative])["finding_count"], 0)

    def test_unknown_operator_and_executable_fields_are_rejected(self):
        pack = custom_pack({"field": "event_type", "op": "regex", "value": ".*"})
        with self.assertRaisesRegex(RulePackError, "unknown"):
            validate_rule_pack(pack)
        executable = builtin_rule_pack()
        executable["rules"][0]["python"] = "import os"
        with self.assertRaisesRegex(RulePackError, "unknown fields"):
            validate_rule_pack(executable)

    def test_oversized_pack_is_rejected_before_json_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b"{" + b"x" * MAX_RULE_PACK_BYTES)
            with self.assertRaisesRegex(RulePackError, "exceeds"):
                load_rule_pack(str(path))

    def test_missing_values_and_incomplete_aggregates_are_unknown_not_matches(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unknown.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(EventEnvelope(event_type="test.observed", source="fixture", payload={"value": 7}))
                store.finish_session(session_id)

            predicates = [
                {"field": "summary.missing", "op": "ne", "value": 1},
                {"not": {"field": "summary.missing", "op": "eq", "value": 1}},
                {
                    "ratio": {
                        "source": "events",
                        "where": {"field": "event_type", "op": "eq", "value": "test.observed"},
                        "denominator_where": {"field": "event_type", "op": "eq", "value": "absent"},
                    },
                    "op": "eq",
                    "value": 0,
                },
                {
                    "duration": {
                        "source": "events",
                        "where": {"field": "event_type", "op": "eq", "value": "test.observed"},
                    },
                    "op": "eq",
                    "value": 0,
                },
            ]
            for predicate in predicates:
                self.assertEqual(
                    analyze_session_with_rules(str(path), [custom_pack(predicate)])["finding_count"],
                    0,
                )

    def test_analysis_is_session_scoped_and_reconciles_stale_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scoped.wsdb"
            with SessionStore(str(path)) as store:
                first = store.start_session(title="first")
                store.add_event(EventEnvelope(event_type="test.observed", source="fixture", payload={"value": 7}))
                store.finish_session(first)
                second = store.start_session(title="second")
                store.finish_session(second)

            pack = custom_pack(
                {
                    "count": {
                        "source": "events",
                        "where": {"field": "event_type", "op": "eq", "value": "test.observed"},
                    },
                    "op": "eq",
                    "value": 1,
                }
            )
            self.assertEqual(
                analyze_session_with_rules(str(path), [pack], session_id=first)["finding_count"],
                1,
            )
            self.assertEqual(
                analyze_session_with_rules(str(path), [pack], session_id=second)["finding_count"],
                0,
            )
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(
                    store.get_metadata(f"rule_pack_versions:{second}"),
                    ["example.tests@1.0.0"],
                )
            with SessionStore(str(path)) as store:
                store.connection.execute("DELETE FROM events WHERE session_id=?", (first,))
            self.assertEqual(
                analyze_session_with_rules(str(path), [pack], session_id=first)["finding_count"],
                0,
            )
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(store.findings(session_id=first), [])
                self.assertEqual(store.findings(session_id=second), [])

    def test_pack_validation_is_strict_bounded_and_rule_lookup_is_unambiguous(self):
        invalid_version = custom_pack({"field": "summary.counts.events", "op": "eq", "value": 0})
        invalid_version["version"] = "1.0.0-bad..suffix"
        with self.assertRaisesRegex(RulePackError, "semantic version"):
            validate_rule_pack(invalid_version)

        invalid_domain = custom_pack(
            {"domain": {"field": "payload.domain", "mode": "registrable", "value": "com"}}
        )
        with self.assertRaisesRegex(RulePackError, "registrable domain"):
            validate_rule_pack(invalid_domain)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "empty.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.finish_session(session_id)
            with self.assertRaisesRegex(RulePackError, "at least one"):
                analyze_session_with_rules(str(path), [])
            release_only = custom_pack(
                {"field": "summary.counts.events", "op": "eq", "value": 0}
            )
            release_only["min_wirescope_version"] = "0.3.0"
            with self.assertRaisesRegex(RulePackError, "requires WireScope 0.3.0"):
                analyze_session_with_rules(str(path), [release_only])
            with self.assertRaisesRegex(SessionError, "session not found"):
                analyze_session_with_rules(str(path), [custom_pack({"field": "summary.counts.events", "op": "eq", "value": 0})], session_id="missing")

        first = custom_pack({"field": "summary.counts.events", "op": "eq", "value": 0})
        second = custom_pack({"field": "summary.counts.events", "op": "eq", "value": 0})
        second["id"] = "example.other"
        with self.assertRaisesRegex(SessionError, "ambiguous"):
            show_rule("example-rule", [first, second])
        with mock.patch("wirescope.rules.MAX_PACKS", 1):
            with self.assertRaisesRegex(RulePackError, "at most"):
                show_rule("example-rule", [first, second])

        invalid_schema = custom_pack(
            {"field": "summary.counts.events", "op": "eq", "value": 0}
        )
        invalid_schema["schema_version"] = True
        with self.assertRaisesRegex(RulePackError, "unsupported"):
            validate_rule_pack(invalid_schema)

        huge_numeric = custom_pack(
            {"field": "summary.counts.events", "op": "gt", "value": 10**10000}
        )
        with self.assertRaisesRegex(RulePackError, "finite number"):
            validate_rule_pack(huge_numeric)

    def test_duplicate_keys_and_nonfinite_constants_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "duplicate.json"
            duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(RulePackError, "duplicate"):
                load_rule_pack(str(duplicate))
            nonfinite = Path(directory) / "nonfinite.json"
            nonfinite.write_text('{"value":NaN}', encoding="utf-8")
            with self.assertRaisesRegex(RulePackError, "numeric constant"):
                load_rule_pack(str(nonfinite))

    def test_evaluation_budget_aborts_before_replacing_existing_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bounded.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(EventEnvelope(event_type="test.observed", source="fixture", payload={"value": 7}))
                store.finish_session(session_id)
            pack = custom_pack(
                {
                    "count": {
                        "source": "events",
                        "where": {"field": "payload.value", "op": "eq", "value": 7},
                    },
                    "op": "eq",
                    "value": 1,
                }
            )
            self.assertEqual(analyze_session_with_rules(str(path), [pack])["finding_count"], 1)
            with mock.patch("wirescope.rules.MAX_EVALUATION_STEPS", 1):
                with self.assertRaisesRegex(RulePackError, "step limit"):
                    analyze_session_with_rules(str(path), [pack])
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(len(store.findings(session_id=session_id)), 1)

            unfiltered = custom_pack(
                {
                    "count": {"source": "events"},
                    "op": "eq",
                    "value": 1,
                }
            )
            with mock.patch("wirescope.rules.MAX_EVALUATION_STEPS", 1):
                with self.assertRaisesRegex(RulePackError, "step limit"):
                    analyze_session_with_rules(str(path), [unfiltered])
            with SessionStore(str(path), read_only=True) as store:
                self.assertEqual(len(store.findings(session_id=session_id)), 1)

    def test_corrupt_stored_json_aborts_before_reconciling_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "corrupt.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(
                    EventEnvelope(
                        event_type="test.observed",
                        source="fixture",
                        payload={"value": 7},
                    )
                )
                store.finish_session(session_id)
            pack = custom_pack(
                {
                    "count": {
                        "source": "events",
                        "where": {"field": "payload.value", "op": "eq", "value": 7},
                    },
                    "op": "eq",
                    "value": 1,
                }
            )
            self.assertEqual(analyze_session_with_rules(str(path), [pack])["finding_count"], 1)
            connection = sqlite3.connect(str(path))
            connection.execute("UPDATE events SET payload_json='{broken'")
            connection.commit()
            connection.close()

            with self.assertRaisesRegex(RulePackError, "event payload contains invalid JSON"):
                analyze_session_with_rules(str(path), [pack])
            connection = sqlite3.connect(str(path))
            try:
                finding_count = connection.execute(
                    "SELECT COUNT(*) FROM findings WHERE session_id=?", (session_id,)
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(finding_count, 1)

    def test_json_boolean_and_number_comparisons_are_type_aware(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "json-types.wsdb"
            with SessionStore(str(path)) as store:
                session_id = store.start_session()
                store.add_event(
                    EventEnvelope(
                        event_type="test.observed",
                        source="fixture",
                        payload={"value": 1},
                    )
                )
                store.finish_session(session_id)

            predicates = [
                ({"field": "payload.value", "op": "eq", "value": True}, 0),
                ({"field": "payload.value", "op": "ne", "value": True}, 1),
                ({"field": "payload.value", "op": "in", "value": [True]}, 0),
                ({"field": "payload.value", "op": "not_in", "value": [True]}, 1),
            ]
            for where, expected_count in predicates:
                pack = custom_pack(
                    {
                        "count": {"source": "events", "where": where},
                        "op": "eq",
                        "value": 1,
                    }
                )
                self.assertEqual(
                    analyze_session_with_rules(str(path), [pack])["finding_count"],
                    expected_count,
                )


if __name__ == "__main__":
    unittest.main()
