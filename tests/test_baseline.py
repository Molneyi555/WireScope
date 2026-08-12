from __future__ import annotations

import json
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from typing import Optional
from unittest import mock

from wirescope.baseline import (
    BaselineError,
    build_baseline,
    compare_baseline,
    load_baseline,
    session_snapshot,
    validate_baseline,
)
from wirescope.session import CorrelationEngine, SessionStore


def make_session(
    path: Path,
    *,
    duration_ms: float,
    transfer_bytes: int,
    ttfb_ms: Optional[float] = 20,
    capabilities=None,
    domain: str = "example.com",
) -> None:
    with SessionStore(str(path)) as store:
        session_id = store.start_session(config={"capabilities": capabilities or {}})
        request = {
            "id": path.stem,
            "url": f"https://{domain}/resource",
            "domain": domain,
            "scheme": "https",
            "method": "GET",
            "duration_ms": duration_ms,
            "transfer_bytes": transfer_bytes,
            "status": 200,
            "failed": False,
            "protocol": "h2",
            "remote_port": 443,
            "timing": {"ttfb_ms": ttfb_ms} if ttfb_ms is not None else {},
        }
        CorrelationEngine(store, session_id).observe_normalized_request(request, source="fixture")
        store.finish_session(session_id)
    connection = sqlite3.connect(str(path))
    connection.execute(
        "UPDATE sessions SET started_at='2026-01-01T00:00:00+00:00', ended_at='2026-01-01T00:00:01+00:00'"
    )
    connection.commit()
    connection.close()


class BaselineTests(unittest.TestCase):
    def test_baseline_is_order_independent_private_and_noise_tolerant(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = []
            for index, duration in enumerate((95, 100, 105)):
                path = root / f"sample-{index}.wsdb"
                make_session(path, duration_ms=duration, transfer_bytes=1000 + index * 10)
                sessions.append(str(path))
            output = root / "normal.wsbaseline"
            first = build_baseline(sessions, str(output))
            second = build_baseline(list(reversed(sessions)))
            self.assertEqual(
                json.dumps(first, sort_keys=True, separators=(",", ":")),
                json.dumps(second, sort_keys=True, separators=(",", ":")),
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(load_baseline(str(output))["sample_count"], 3)

            noisy = root / "noisy.wsdb"
            make_session(noisy, duration_ms=108, transfer_bytes=1025)
            comparison = compare_baseline(first, str(noisy))
            self.assertEqual(comparison["state"], "pass")
            duration = next(item for item in comparison["metrics"] if item["metric"] == "request_duration_p90_ms")
            self.assertEqual(duration["status"], "stable")
            self.assertIn("AND", duration["formula"])

    def test_real_regression_and_new_domain_are_distinct(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = []
            for index, duration in enumerate((95, 100, 105)):
                path = root / f"sample-{index}.wsdb"
                make_session(path, duration_ms=duration, transfer_bytes=1000)
                sessions.append(str(path))
            baseline = build_baseline(sessions)
            slow = root / "slow.wsdb"
            make_session(slow, duration_ms=140, transfer_bytes=1400, domain="new.example.net")
            comparison = compare_baseline(baseline, str(slow))
            self.assertEqual(comparison["state"], "regression")
            self.assertGreaterEqual(comparison["summary"]["regressions"], 2)
            self.assertEqual(comparison["changes"]["domains"]["new"], ["new.example.net"])
            self.assertEqual(comparison["changes"]["domains"]["policy_effect"], "change-only")

    def test_missing_metric_and_capability_gap_never_become_false_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = []
            for index in range(3):
                path = root / f"sample-{index}.wsdb"
                make_session(path, duration_ms=100, transfer_bytes=1000)
                sessions.append(str(path))
            baseline = build_baseline(sessions)

            missing = root / "missing.wsdb"
            make_session(missing, duration_ms=100, transfer_bytes=1000, ttfb_ms=None)
            missing_result = compare_baseline(baseline, str(missing))
            self.assertEqual(missing_result["state"], "unknown")
            self.assertFalse(missing_result["passed"])

            incompatible = root / "incompatible.wsdb"
            make_session(
                incompatible,
                duration_ms=100,
                transfer_bytes=1000,
                capabilities={"dns": {"available": False}},
            )
            incompatible_result = compare_baseline(baseline, str(incompatible))
            self.assertEqual(incompatible_result["state"], "incompatible")
            self.assertFalse(incompatible_result["capability"]["compatible"])

    def test_single_run_requires_and_uses_absolute_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "sample.wsdb"
            make_session(sample, duration_ms=100, transfer_bytes=1000)
            with self.assertRaisesRegex(BaselineError, "absolute budget"):
                build_baseline([str(sample)], allow_single=True)
            statistical = []
            for index in range(3):
                path = root / f"statistical-{index}.wsdb"
                make_session(path, duration_ms=100, transfer_bytes=1000)
                statistical.append(str(path))
            with self.assertRaisesRegex(BaselineError, "only for a single-run"):
                build_baseline(
                    statistical,
                    absolute_budgets={"transfer_bytes": 1100},
                )
            baseline = build_baseline(
                [str(sample)],
                allow_single=True,
                absolute_budgets={"transfer_bytes": 1100},
            )
            after = root / "after.wsdb"
            make_session(after, duration_ms=100, transfer_bytes=1200)
            result = compare_baseline(baseline, str(after))
            self.assertEqual(result["state"], "regression")
            self.assertEqual(result["metrics"][0]["formula"], "actual <= absolute_limit")

    def test_snapshot_selects_latest_instant_and_never_mixes_recordings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "multi.wsdb"
            with SessionStore(str(path)) as store:
                first = store.start_session(config={"capabilities": {}})
                CorrelationEngine(store, first).observe_normalized_request(
                    {
                        "id": "first",
                        "url": "https://old.example/",
                        "domain": "old.example",
                        "scheme": "https",
                        "method": "GET",
                        "duration_ms": 10,
                        "transfer_bytes": 10,
                        "status": 200,
                        "failed": False,
                        "protocol": "h2",
                        "remote_port": 443,
                        "timing": {"ttfb_ms": 1},
                    },
                    source="fixture",
                )
                store.finish_session(first)
                second = store.start_session(config={"capabilities": {}})
                engine = CorrelationEngine(store, second)
                for index in range(2):
                    engine.observe_normalized_request(
                        {
                            "id": f"second-{index}",
                            "url": "https://new.example/",
                            "domain": "new.example",
                            "scheme": "https",
                            "method": "GET",
                            "duration_ms": 20,
                            "transfer_bytes": 20,
                            "status": 200,
                            "failed": False,
                            "protocol": "h2",
                            "remote_port": 443,
                            "timing": {"ttfb_ms": 2},
                        },
                        source="fixture",
                    )
                store.finish_session(second)
            connection = sqlite3.connect(str(path))
            connection.execute(
                "UPDATE sessions SET started_at=?, ended_at=? WHERE id=?",
                ("2026-01-02T00:00:00+14:00", "2026-01-02T00:00:01+14:00", first),
            )
            connection.execute(
                "UPDATE sessions SET started_at=?, ended_at=? WHERE id=?",
                ("2026-01-01T23:00:00-12:00", "2026-01-01T23:00:01-12:00", second),
            )
            connection.commit()
            connection.close()

            snapshot = session_snapshot(str(path))
            self.assertEqual(snapshot["session_id"], second)
            self.assertEqual(snapshot["metrics"]["request_count"], 2.0)
            self.assertEqual(snapshot["sets"]["domains"], ["new.example"])

    def test_incomplete_training_coverage_and_mixed_capabilities_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = []
            for index, ttfb in enumerate((20, 20, None)):
                path = root / f"partial-{index}.wsdb"
                make_session(path, duration_ms=100, transfer_bytes=1000, ttfb_ms=ttfb)
                sessions.append(str(path))
            baseline = build_baseline(sessions)
            current = root / "current.wsdb"
            make_session(current, duration_ms=100, transfer_bytes=1000, ttfb_ms=20)
            comparison = compare_baseline(baseline, str(current))
            self.assertEqual(comparison["state"], "unknown")
            ttfb_result = next(item for item in comparison["metrics"] if item["metric"] == "ttfb_p90_ms")
            self.assertEqual(ttfb_result["status"], "unknown")

            mixed = []
            for index, available in enumerate((True, True, False)):
                path = root / f"capability-{index}.wsdb"
                make_session(
                    path,
                    duration_ms=100,
                    transfer_bytes=1000,
                    capabilities={"dns": {"available": available}},
                )
                mixed.append(str(path))
            with self.assertRaisesRegex(BaselineError, "same capability profile"):
                build_baseline(mixed)

    def test_tampered_schema_duplicate_keys_and_nonfinite_values_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = []
            for index in range(3):
                path = root / f"sample-{index}.wsdb"
                make_session(path, duration_ms=100, transfer_bytes=1000)
                sessions.append(str(path))
            baseline = build_baseline(sessions)

            tampered = json.loads(json.dumps(baseline))
            tampered["capability_profiles"][0]["profile"]["invented"] = True
            with self.assertRaisesRegex(BaselineError, "signature"):
                validate_baseline(tampered)

            tampered = json.loads(json.dumps(baseline))
            tampered["sets"]["domains"]["stable"] = []
            with self.assertRaisesRegex(BaselineError, "frequencies"):
                validate_baseline(tampered)

            duplicate = root / "duplicate.wsbaseline"
            duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "duplicate"):
                load_baseline(str(duplicate))
            nonfinite = root / "nonfinite.wsbaseline"
            nonfinite.write_text('{"value":Infinity}', encoding="utf-8")
            with self.assertRaisesRegex(BaselineError, "numeric constant"):
                load_baseline(str(nonfinite))
            with self.assertRaisesRegex(BaselineError, "finite"):
                compare_baseline(baseline, sessions[0], relative_threshold=float("nan"))

            tampered = json.loads(json.dumps(baseline))
            tampered["schema_version"] = True
            with self.assertRaisesRegex(BaselineError, "unsupported"):
                validate_baseline(tampered)

            tampered = json.loads(json.dumps(baseline))
            tampered["absolute_budgets"] = {"request_count": 10**10000}
            with self.assertRaisesRegex(BaselineError, "absolute_budgets"):
                validate_baseline(tampered)

            connection = sqlite3.connect(sessions[0])
            connection.execute("UPDATE events SET payload_json='{broken'")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(BaselineError, "event payload contains invalid JSON"):
                session_snapshot(sessions[0])

    def test_snapshot_is_bounded_and_rejects_live_or_changed_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "stable.wsdb"
            make_session(path, duration_ms=100, transfer_bytes=1000)

            with mock.patch("wirescope.baseline.MAX_SNAPSHOT_ROWS", 1):
                with self.assertRaisesRegex(BaselineError, "row baseline limit"):
                    session_snapshot(str(path))

            original = session_snapshot(str(path))["fingerprint"]
            with mock.patch(
                "wirescope.baseline._file_fingerprint",
                side_effect=[original, "0" * 64],
            ):
                with self.assertRaisesRegex(BaselineError, "changed while"):
                    session_snapshot(str(path))

            Path(f"{path}-wal").write_bytes(b"active")
            with self.assertRaisesRegex(BaselineError, "active SQLite wal"):
                session_snapshot(str(path))

    def test_snapshot_remains_compatible_with_readable_schema_v1_sessions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.wsdb"
            make_session(path, duration_ms=100, transfer_bytes=1000)
            connection = sqlite3.connect(str(path))
            connection.execute(
                "UPDATE schema_info SET version=1 WHERE component IN ('session', 'event')"
            )
            connection.execute("UPDATE events SET schema_version=1")
            connection.execute("PRAGMA user_version=1")
            connection.commit()
            connection.close()
            snapshot = session_snapshot(str(path))
            self.assertEqual(snapshot["schema_version"], 1)
            self.assertEqual(snapshot["metrics"]["request_count"], 1.0)
            self.assertEqual(snapshot["rule_pack_versions"], [])


if __name__ == "__main__":
    unittest.main()
