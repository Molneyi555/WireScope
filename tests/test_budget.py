import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from wirescope.budget import evaluate_budgets, load_budget_policy, merge_budget_policy, parse_byte_size
from wirescope.cli import main


def sample_report():
    return {
        "source_type": "har",
        "summary": {
            "requests": 12,
            "transfer_bytes": 2_000_000,
            "page_span_ms": 2_400,
            "failed": 1,
            "http_errors": 2,
            "third_party_percent": 25.0,
            "trackers": 1,
            "cache_percent": 40.0,
        },
        "scores": {
            "overall": 82,
            "performance": 75,
            "reliability": 76,
            "privacy": 88,
            "security": 100,
        },
    }


def sample_har():
    return {
        "log": {
            "version": "1.2",
            "entries": [
                {
                    "startedDateTime": "2026-01-01T00:00:00Z",
                    "time": 100,
                    "request": {"method": "GET", "url": "https://example.com/", "httpVersion": "HTTP/2"},
                    "response": {
                        "status": 200,
                        "httpVersion": "HTTP/2",
                        "bodySize": 100,
                        "headersSize": 20,
                        "content": {"mimeType": "text/html"},
                    },
                    "timings": {"wait": 50},
                }
            ],
        }
    }


class BudgetTests(unittest.TestCase):
    def test_parse_human_byte_sizes(self):
        self.assertEqual(parse_byte_size("2MB"), 2_000_000)
        self.assertEqual(parse_byte_size("2.5 MiB"), 2_621_440)
        self.assertEqual(parse_byte_size(1234), 1234)
        with self.assertRaises(ValueError):
            parse_byte_size("a lot")

    def test_budget_evaluation_reports_every_violation(self):
        result = evaluate_budgets(
            sample_report(),
            {
                "max_requests": 12,
                "max_transfer_bytes": "1MB",
                "max_errors": 2,
                "min_overall_score": 90,
            },
        )
        self.assertFalse(result["passed"])
        self.assertEqual(result["checked"], 4)
        self.assertEqual(
            {item["policy"] for item in result["violations"]},
            {"max_transfer_bytes", "max_errors", "min_overall_score"},
        )

    def test_policy_file_and_inline_override_are_merged(self):
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / "budget.json"
            policy_path.write_text(json.dumps({"budgets": {"max_requests": 20, "min_cache_percent": 30}}), encoding="utf-8")
            policy = load_budget_policy(str(policy_path))
        merged = merge_budget_policy(policy, {"max_requests": 10, "max_trackers": None})
        self.assertEqual(merged, {"max_requests": 10, "min_cache_percent": 30})
        with self.assertRaises(ValueError):
            merge_budget_policy({}, {"max_reqeusts": 10})

    def test_cli_uses_exit_one_only_for_budget_violations(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "page.har"
            source.write_text(json.dumps(sample_har()), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                main(["budget", str(source), "--max-requests", "1", "--max-transfer", "1MB"])
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["budget", str(source), "--max-requests", "0"])
        self.assertEqual(raised.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
