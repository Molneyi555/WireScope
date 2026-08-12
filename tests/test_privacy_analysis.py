import unittest

from wirescope.analyzer import base_domain, build_report, finalize_report, normalize_requests
from wirescope.tracker import classify_tracker, is_tracker
from wirescope.tracker_data import TRACKER_DATASET


def request(url, domain, document_url="https://shop.example.co.uk/", duration=20, status=200):
    return {
        "url": url,
        "domain": domain,
        "document_url": document_url,
        "scheme": url.split(":", 1)[0],
        "started_monotonic": 1.0,
        "started_wall_time": None,
        "duration_ms": duration,
        "status": status,
        "transfer_bytes": 100,
        "body_bytes": 200,
        "resource_type": "Script",
        "protocol": "h2",
        "mime_type": "application/javascript",
        "method": "GET",
        "failed": False,
        "from_cache": False,
        "security_details": {"protocol": "TLS 1.3"} if url.startswith("https:") else None,
    }


class TrackerClassifierTests(unittest.TestCase):
    def test_domain_matching_observes_label_boundaries(self):
        match = classify_tracker("https://www.google-analytics.com/collect", "www.google-analytics.com")
        self.assertEqual(match["rule_id"], "google-analytics")
        self.assertEqual(match["owner"], "Google")
        self.assertEqual(match["category"], "analytics")
        self.assertEqual(match["dataset_version"], TRACKER_DATASET["version"])
        self.assertFalse(is_tracker("https://notgoogle-analytics.com/collect", "notgoogle-analytics.com"))

    def test_path_rules_do_not_scan_query_values(self):
        self.assertEqual(
            classify_tracker("https://www.facebook.com/tr?id=1", "www.facebook.com")["rule_id"],
            "meta-pixel",
        )
        self.assertIsNone(classify_tracker("https://www.facebook.com/tree", "www.facebook.com"))
        self.assertIsNone(classify_tracker("https://example.com/?next=/matomo.php", "example.com"))
        matomo = classify_tracker("https://metrics.example.com/site/matomo.php", "metrics.example.com")
        self.assertEqual(matomo["confidence"], "medium")
        self.assertEqual(matomo["matched_on"], "path")

    def test_dataset_has_stable_explainable_metadata(self):
        self.assertRegex(TRACKER_DATASET["version"], r"^\d{4}\.\d{2}\.\d{2}\.\d+$")
        self.assertIn("limitations", TRACKER_DATASET)
        self.assertIn("provenance", TRACKER_DATASET)


class EvidenceBackedAnalysisTests(unittest.TestCase):
    def test_psl_party_classification_and_tracker_evidence(self):
        requests = [
            request("https://static.example.co.uk/app.js", "static.example.co.uk"),
            request("https://api.other.co.uk/data", "api.other.co.uk"),
            request("https://www.google-analytics.com/collect", "www.google-analytics.com"),
        ]
        normalize_requests(requests)
        self.assertEqual(base_domain("a.b.example.co.uk"), "example.co.uk")
        self.assertFalse(requests[0]["third_party"])
        self.assertTrue(requests[1]["third_party"])
        self.assertTrue(requests[2]["tracker"])
        self.assertEqual(requests[2]["tracker_match"]["rule_id"], "google-analytics")

        report = finalize_report(build_report(requests, "chrome-cdp", {}, []))
        self.assertIsInstance(report["scores"]["privacy"], int)
        self.assertEqual(report["facts"]["tracker_signature_matches"], 1)
        self.assertEqual(report["aggregates"]["tracker_categories"], {"analytics": 1})
        self.assertEqual(report["analysis_metadata"]["datasets"]["public_suffix_list"]["runtime_network"], False)
        self.assertEqual(report["assessments"]["privacy"]["confidence"], "medium")
        self.assertTrue(report["assessments"]["privacy"]["limitations"])
        privacy_factors = {item["code"]: item for item in report["assessments"]["privacy"]["factors"]}
        self.assertEqual(privacy_factors["tracker-signatures"]["deduction"], 7)
        self.assertIn("signature matches", privacy_factors["tracker-signatures"]["evidence"])

        tracking = next(item for item in report["findings"] if item["code"] == "tracking-requests")
        self.assertEqual(tracking["basis"], "heuristic")
        self.assertEqual(tracking["confidence"], "medium")
        self.assertIn("google-analytics", tracking["evidence"][0])
        self.assertTrue(tracking["evidence_details"])
        self.assertTrue(tracking["limitations"])

    def test_private_suffixes_do_not_collapse_unrelated_tenants(self):
        requests = [
            request("https://foo.github.io/app.js", "foo.github.io", "https://foo.github.io/"),
            request("https://bar.github.io/widget.js", "bar.github.io", "https://foo.github.io/"),
        ]
        normalize_requests(requests)
        self.assertEqual(requests[0]["registrable_domain"], "foo.github.io")
        self.assertEqual(requests[1]["registrable_domain"], "bar.github.io")
        self.assertFalse(requests[0]["third_party"])
        self.assertTrue(requests[1]["third_party"])

    def test_inferred_primary_domain_lowers_confidence(self):
        requests = [
            request("https://first.example/a", "first.example", document_url=""),
            request("https://second.example/b", "second.example", document_url=""),
        ]
        normalize_requests(requests)
        report = finalize_report(build_report(requests, "proxy-jsonl", {}, []))
        finding = next(item for item in report["findings"] if item["code"] == "third-party-heavy")
        self.assertEqual(finding["confidence"], "low")
        self.assertTrue(finding["limitations"])
        self.assertEqual(report["assessments"]["privacy"]["confidence"], "low")
        self.assertIn("inferred primary domain", " ".join(report["assessments"]["privacy"]["limitations"]).lower())


if __name__ == "__main__":
    unittest.main()
