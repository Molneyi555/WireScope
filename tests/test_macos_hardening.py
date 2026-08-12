import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from wirescope.macos import (
    CommandError,
    CommandSpec,
    MacOSAdapter,
    ParseResult,
    parse_arp,
    parse_ifconfig,
    parse_interface_counters,
    parse_lsof,
    parse_ndp,
    parse_routes,
    parse_scutil_dns,
    run_command,
)


FIXTURES = Path(__file__).parent / "fixtures" / "macos"


def fixture(name):
    return (FIXTURES / name).read_text(encoding="utf-8")


class CommandContractTests(unittest.TestCase):
    @patch("wirescope.macos.subprocess.run")
    def test_nonzero_is_rejected_by_default(self, mocked_run):
        mocked_run.return_value = subprocess.CompletedProcess(
            ["/usr/bin/example"], 1, stdout="partial output", stderr="not available"
        )
        diagnostics = []
        with self.assertRaises(CommandError) as raised:
            run_command(["/usr/bin/example"], diagnostics=diagnostics)
        self.assertEqual(raised.exception.diagnostic.returncode, 1)
        self.assertEqual(raised.exception.diagnostic.error_kind, "exit_status")
        self.assertEqual(len(diagnostics), 1)
        self.assertFalse(diagnostics[0].ok)

    @patch("wirescope.macos.subprocess.run")
    def test_command_spec_can_explicitly_accept_one(self, mocked_run):
        mocked_run.return_value = subprocess.CompletedProcess(
            ["/usr/sbin/lsof"], 1, stdout="", stderr=""
        )
        diagnostics = []
        spec = CommandSpec(
            ("/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP"),
            name="connections",
            valid_returncodes=(0, 1),
        )
        self.assertEqual(run_command(spec, diagnostics=diagnostics), "")
        self.assertEqual(diagnostics[0].name, "connections")
        self.assertTrue(diagnostics[0].ok)
        self.assertEqual(diagnostics[0].valid_returncodes, (0, 1))

    @patch("wirescope.macos.subprocess.run")
    def test_timeout_has_structured_diagnostic(self, mocked_run):
        mocked_run.side_effect = subprocess.TimeoutExpired(["/usr/bin/example"], 0.1)
        diagnostics = []
        with self.assertRaises(CommandError) as raised:
            run_command(["/usr/bin/example"], timeout=0.1, diagnostics=diagnostics)
        self.assertEqual(raised.exception.diagnostic.error_kind, "timeout")
        self.assertIsNone(raised.exception.diagnostic.returncode)
        self.assertEqual(diagnostics[0].error_kind, "timeout")

    @patch("wirescope.macos.subprocess.run")
    def test_success_with_permission_warning_is_not_silent(self, mocked_run):
        mocked_run.return_value = subprocess.CompletedProcess(
            ["/usr/sbin/netstat"],
            0,
            stdout="Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes\n",
            stderr="netstat: sysctl: Operation not permitted\n",
        )
        diagnostics = []
        run_command(["/usr/sbin/netstat"], diagnostics=diagnostics)
        self.assertTrue(diagnostics[0].ok)
        self.assertEqual(diagnostics[0].warning_kind, "permission-denied")
        self.assertGreater(diagnostics[0].stderr_bytes, 0)

    def test_capabilities_are_machine_readable(self):
        result = MacOSAdapter().capabilities()
        self.assertEqual(result["schema_version"], 1)
        self.assertIn("connections", result["capabilities"])
        self.assertIn("available", result["capabilities"]["connections"])
        self.assertIn("/usr/sbin/lsof", result["tools"])


class ParserFixtureTests(unittest.TestCase):
    def test_default_parser_api_remains_unchanged(self):
        result = parse_lsof(fixture("lsof_variants.txt"))
        self.assertIsInstance(result, list)
        self.assertEqual(result[0].process, "Google Chrome")

    def test_lsof_variants_report_skipped_rows(self):
        result = parse_lsof(fixture("lsof_variants.txt"), with_metadata=True)
        self.assertIsInstance(result, ParseResult)
        self.assertEqual(len(result.data), 3)
        self.assertEqual(result.data[0].remote.host, "2606:4700:4700::1111")
        self.assertEqual(result.metadata.parsed_records, 3)
        self.assertEqual(result.metadata.skipped_lines, 2)
        self.assertIn("columns", result.metadata.missing_fields)
        self.assertEqual(result.metadata.confidence, "low")

    def test_route_headers_with_refs_and_use_are_mapped(self):
        result = parse_routes(fixture("routes_variants.txt"), with_metadata=True)
        self.assertEqual(len(result.data), 4)
        self.assertEqual(result.data[0]["interface"], "en0")
        self.assertEqual(result.data[2]["interface"], "utun4")
        self.assertEqual(result.metadata.skipped_lines, 1)

    def test_ifconfig_variants_preserve_addresses_and_warn_on_missing_flags(self):
        result = parse_ifconfig(fixture("ifconfig_variants.txt"), with_metadata=True)
        self.assertEqual([item.name for item in result.data], ["lo0", "en0", "bridge0"])
        self.assertEqual(result.data[1].ipv4, ["192.168.50.20"])
        self.assertIn("flags", result.metadata.missing_fields)
        self.assertTrue(any(item.code == "missing-flags" for item in result.metadata.warnings))

    def test_scutil_supports_supplemental_resolver_without_nameserver(self):
        result = parse_scutil_dns(fixture("scutil_dns_variants.txt"), with_metadata=True)
        self.assertEqual(len(result.data), 2)
        self.assertEqual(result.data[0]["nameservers"], ["192.168.50.1"])
        self.assertEqual(result.data[1]["nameservers"], [])
        self.assertEqual(result.metadata.missing_fields["nameservers"], 1)

    def test_counter_variants_aggregate_duplicate_rows(self):
        result = parse_interface_counters(fixture("counters_variants.txt"), with_metadata=True)
        self.assertEqual(result.data["en0"]["rx_bytes"], 10000)
        self.assertEqual(result.data["en0"]["tx_errors"], 1)
        self.assertEqual(result.data["en5"]["tx_bytes"], 600)
        self.assertEqual(result.data["lo0"]["tx_bytes"], 50000)
        self.assertEqual(result.metadata.skipped_lines, 1)

    def test_neighbor_variants_include_incomplete_entries(self):
        arp = parse_arp(fixture("arp_variants.txt"), with_metadata=True)
        ndp = parse_ndp(fixture("ndp_variants.txt"), with_metadata=True)
        self.assertEqual(len(arp.data), 2)
        self.assertEqual(arp.data[1]["mac"], "(incomplete)")
        self.assertEqual(len(ndp.data), 2)
        self.assertEqual(ndp.data[1]["mac"], "(incomplete)")
        self.assertEqual(arp.metadata.skipped_lines, 1)
        self.assertEqual(ndp.metadata.skipped_lines, 1)

    @patch.object(MacOSAdapter, "_run")
    def test_adapter_accumulates_parser_diagnostics(self, mocked_run):
        mocked_run.return_value = fixture("ifconfig_variants.txt")
        adapter = MacOSAdapter()
        self.assertEqual(len(adapter.interfaces()), 3)
        diagnostics = adapter.parser_diagnostics()
        self.assertEqual(diagnostics[0]["parser"], "ifconfig")
        self.assertIn("confidence", diagnostics[0])
        self.assertEqual(adapter.parser_diagnostics(clear=True), diagnostics)
        self.assertEqual(adapter.parser_diagnostics(), [])


if __name__ == "__main__":
    unittest.main()
