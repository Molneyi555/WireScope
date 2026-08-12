import hashlib
from importlib import resources
import socket
import unittest
from unittest import mock

from wirescope._psl_snapshot import RULE_COUNT, RULES_SHA256, SNAPSHOT_RESOURCE, rules
from wirescope.public_suffix import PublicSuffixList, canonical_host, default_public_suffix_list, registrable_domain


class PublicSuffixAlgorithmTests(unittest.TestCase):
    def setUp(self):
        self.psl = PublicSuffixList.from_text(
            """
            // test fixture
            com
            uk
            co.uk
            *.ck
            !www.ck
            jp
            *.kawasaki.jp
            !city.kawasaki.jp
            """
        )

    def test_exact_rule_and_longest_match(self):
        parts = self.psl.split("A.B.Example.CO.UK.")
        self.assertEqual(parts.host, "a.b.example.co.uk")
        self.assertEqual(parts.public_suffix, "co.uk")
        self.assertEqual(parts.registrable_domain, "example.co.uk")
        self.assertEqual(parts.rule_type, "exact")
        self.assertEqual(parts.matched_rule, "co.uk")

    def test_wildcard_rule(self):
        parts = self.psl.split("a.b.ck")
        self.assertEqual(parts.public_suffix, "b.ck")
        self.assertEqual(parts.registrable_domain, "a.b.ck")
        self.assertEqual(parts.rule_type, "wildcard")
        self.assertEqual(parts.matched_rule, "*.ck")

    def test_exception_rule(self):
        parts = self.psl.split("a.www.ck")
        self.assertEqual(parts.public_suffix, "ck")
        self.assertEqual(parts.registrable_domain, "www.ck")
        self.assertEqual(parts.rule_type, "exception")
        self.assertEqual(parts.matched_rule, "!www.ck")

        city = self.psl.split("www.city.kawasaki.jp")
        self.assertEqual(city.public_suffix, "kawasaki.jp")
        self.assertEqual(city.registrable_domain, "city.kawasaki.jp")

    def test_prevailing_default_and_atomic_addresses(self):
        self.assertEqual(self.psl.registrable_domain("a.b.unknown"), "b.unknown")
        self.assertEqual(self.psl.registrable_domain("localhost"), "localhost")
        self.assertEqual(self.psl.registrable_domain("192.0.2.1"), "192.0.2.1")
        self.assertEqual(self.psl.registrable_domain("2001:db8::1"), "2001:db8::1")
        self.assertEqual(self.psl.split("bad..example.com").rule_type, "invalid")


class BundledPublicSuffixTests(unittest.TestCase):
    def test_source_form_matches_pinned_integrity_metadata(self):
        payload = resources.files("wirescope.data").joinpath(SNAPSHOT_RESOURCE).read_bytes()
        self.assertEqual(hashlib.sha256(payload).hexdigest(), RULES_SHA256)
        self.assertEqual(len(payload.decode("utf-8").splitlines()), RULE_COUNT)

    def test_snapshot_is_complete_and_loads_without_network(self):
        default_public_suffix_list.cache_clear()
        with mock.patch.object(socket, "create_connection", side_effect=AssertionError("network access attempted")):
            psl = default_public_suffix_list()
            self.assertEqual(len(rules()), RULE_COUNT)
            self.assertGreater(RULE_COUNT, 8_000)
            self.assertEqual(psl.registrable_domain("a.b.example.com"), "example.com")

    def test_private_suffix_and_real_wildcard_exception(self):
        psl = default_public_suffix_list()
        self.assertEqual(psl.registrable_domain("assets.project.github.io"), "project.github.io")
        self.assertEqual(psl.public_suffix("a.b.ck"), "b.ck")
        self.assertEqual(psl.registrable_domain("a.www.ck"), "www.ck")

    def test_idn_is_compared_in_ascii_form(self):
        self.assertEqual(canonical_host("食狮.公司.cn"), "xn--85x722f.xn--55qx5d.cn")
        self.assertEqual(registrable_domain("食狮.公司.cn"), "xn--85x722f.xn--55qx5d.cn")


if __name__ == "__main__":
    unittest.main()
