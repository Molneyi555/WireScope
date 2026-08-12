import unittest

from benchmarks.benchmark_core import run


class BenchmarkSmokeTests(unittest.TestCase):
    def test_quick_benchmark_covers_release_paths(self):
        result = run(events=25, har_entries=10)
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["measurements"]["session"]["events"], 25)
        self.assertEqual(result["measurements"]["jsonl_import"]["imported_events"], 25)
        self.assertEqual(result["measurements"]["har_analysis"]["entries"], 10)
        self.assertGreater(result["max_rss_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
