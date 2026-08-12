import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from wirescope.cdp import sanitize
from wirescope.cli import command_connections, command_routes, main
from wirescope.config import DEFAULT_CONFIG, deep_merge, write_default_config
from wirescope.har import load_har
from wirescope.macos import (
    parse_endpoint,
    parse_ifconfig,
    parse_interface_counters,
    parse_lsof,
    parse_arp,
    parse_ndp,
    parse_route_get,
    parse_routes,
    parse_scutil_proxy,
    parse_scutil_dns,
)
from wirescope.proxy import parse_host_port, validate_bind
from wirescope.redact import redact_headers, redact_url
from wirescope.models import Connection, Endpoint
from wirescope.tui import process_rows, sparkline


class ParserTests(unittest.TestCase):
    def test_parse_endpoint_ipv4_and_ipv6(self):
        self.assertEqual(parse_endpoint("10.0.0.2:443").display(), "10.0.0.2:443")
        self.assertEqual(parse_endpoint("[fe80::1]:5353").display(), "[fe80::1]:5353")

    def test_parse_lsof(self):
        sample = """COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
Chrome\\x20 42 me 9u IPv4 0x1 0t0 TCP 10.0.0.2:50000->1.1.1.1:443 (ESTABLISHED)
server 43 me 5u IPv6 0x2 0t0 TCP [::1]:8080 (LISTEN)
"""
        values = parse_lsof(sample, vpn_default=True)
        self.assertEqual(len(values), 2)
        self.assertEqual(values[0].process, "Chrome ")
        self.assertEqual(values[0].remote.host, "1.1.1.1")
        self.assertEqual(values[0].state, "ESTABLISHED")
        self.assertEqual(values[0].path, "vpn-default")
        self.assertIsNone(values[1].remote)

    def test_parse_ifconfig(self):
        sample = """en0: flags=8863<UP,RUNNING> mtu 1500
\tinet 192.168.1.8 netmask 0xffffff00
\tinet6 fe80::123%en0 prefixlen 64
\tstatus: active
utun2: flags=8051<UP,RUNNING> mtu 1380
\tinet 10.8.0.2 --> 10.8.0.2 netmask 0xffffff00
"""
        values = parse_ifconfig(sample)
        self.assertEqual(values[0].status, "active")
        self.assertEqual(values[0].ipv4, ["192.168.1.8"])
        self.assertTrue(values[1].is_vpn)

    def test_parse_routes(self):
        sample = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.1.1        UGScg                 en0
1.1.1.1            link#20            UHWIig              utun6
"""
        values = parse_routes(sample)
        self.assertEqual(values[0]["interface"], "en0")
        self.assertEqual(values[1]["destination"], "1.1.1.1")

    def test_parse_dns(self):
        sample = """DNS configuration

resolver #1
  nameserver[0] : 1.1.1.1
  nameserver[1] : 1.0.0.1
  if_index : 12 (en0)
  flags    : Request A records
"""
        values = parse_scutil_dns(sample)
        self.assertEqual(values[0]["nameservers"], ["1.1.1.1", "1.0.0.1"])
        self.assertEqual(values[0]["if_index"], "12 (en0)")

    def test_interface_counters_are_not_multiplied_by_address_rows(self):
        sample = """Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll Drop
en0 1500 <Link#4> aa:bb 10 0 1000 20 0 2000 0 1
en0 1500 192.168.1 192.168.1.2 10 0 1000 20 0 2000 - -
"""
        values = parse_interface_counters(sample)
        self.assertEqual(values["en0"]["rx_bytes"], 1000)
        self.assertEqual(values["en0"]["tx_packets"], 20)

    def test_parse_proxy_and_effective_route(self):
        proxy = parse_scutil_proxy("<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : 127.0.0.1\n}")
        self.assertEqual(proxy["HTTPEnable"], 1)
        route = parse_route_get("route to: 1.1.1.1\ndestination: 1.1.1.1\ngateway: 10.0.0.1\ninterface: en0\n")
        self.assertEqual(route["interface"], "en0")

    def test_parse_neighbors(self):
        arp = parse_arp("? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]")
        self.assertEqual(arp[0]["address"], "192.168.1.1")
        self.assertEqual(arp[0]["interface"], "en0")
        ndp = parse_ndp("Neighbor Linklayer Address Netif Expire St\nfe80::1%en0 aa:bb:cc:dd:ee:ff en0 23h S")
        self.assertEqual(ndp[0]["family"], "IPv6")


class PrivacyTests(unittest.TestCase):
    def test_url_redaction(self):
        value = redact_url("https://user:pass@example.com/api?token=abc&q=test")
        self.assertNotIn("pass", value)
        self.assertNotIn("abc", value)
        self.assertIn("q=test", value)

    def test_header_redaction(self):
        value = redact_headers([("Authorization", "Bearer secret"), ("Accept", "application/json")])
        self.assertEqual(value["Authorization"], "[REDACTED]")
        self.assertEqual(value["Accept"], "application/json")

    def test_cdp_recursive_redaction(self):
        value = sanitize(
            {
                "documentURL": "https://example.com/?token=secret",
                "request": {"headers": {"Cookie": "secret"}, "postData": "password=bad"},
                "headersText": "HTTP/1.1 200 OK\r\nSet-Cookie: secret\r\nContent-Type: text/plain",
            },
            False,
        )
        self.assertEqual(value["request"]["headers"]["Cookie"], "[REDACTED]")
        self.assertNotIn("password=bad", value["request"]["postData"])
        self.assertNotIn("token=secret", value["documentURL"])
        self.assertNotIn("Set-Cookie: secret", value["headersText"])
        payload = sanitize({"response": {"payloadData": "secret websocket message"}}, False)
        self.assertNotIn("secret websocket", payload["response"]["payloadData"])


class HarTests(unittest.TestCase):
    def test_har_summary(self):
        har = {
            "log": {
                "entries": [
                    {
                        "startedDateTime": "2026-01-01T00:00:00Z",
                        "time": 123.4,
                        "request": {"method": "GET", "url": "https://example.com/a?token=secret", "httpVersion": "HTTP/2"},
                        "response": {
                            "status": 200,
                            "httpVersion": "HTTP/2",
                            "bodySize": 100,
                            "headersSize": 20,
                            "content": {"mimeType": "text/html; charset=utf-8"},
                        },
                        "timings": {"dns": 4, "connect": 10, "ssl": 5, "wait": 50},
                    }
                ]
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.har"
            path.write_text(json.dumps(har), encoding="utf-8")
            report = load_har(str(path))
        self.assertEqual(report["summary"]["requests"], 1)
        self.assertEqual(report["summary"]["total_transfer_bytes"], 120)
        self.assertNotIn("secret", report["requests"][0]["url"])


class ProxyTests(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(parse_host_port("example.com:8443", 443), ("example.com", 8443))
        self.assertEqual(parse_host_port("[::1]:443", 80), ("::1", 443))

    def test_remote_bind_requires_acknowledgement(self):
        validate_bind("127.0.0.1", False)
        with self.assertRaises(ValueError):
            validate_bind("0.0.0.0", False)
        validate_bind("0.0.0.0", True)


class ConvenienceTests(unittest.TestCase):
    def test_json_limits_apply_to_connections_and_routes(self):
        class Adapter:
            @staticmethod
            def connections():
                return [
                    Connection("app", 7, "me", str(index), "IPv4", "TCP", Endpoint("127.0.0.1", str(index)), None)
                    for index in range(3)
                ]

            @staticmethod
            def routes():
                return [
                    {"destination": str(index), "gateway": "192.0.2.1", "interface": "en0", "flags": "UG"}
                    for index in range(3)
                ]

        args = Namespace(process=None, remote_only=False, state=None, json=True, limit=1, default=False)
        output = StringIO()
        with redirect_stdout(output):
            command_connections(args, Adapter())
        connections = json.loads(output.getvalue())
        self.assertEqual(connections["count"], 1)
        self.assertEqual(connections["total_count"], 3)
        self.assertTrue(connections["truncated"])

        output = StringIO()
        with redirect_stdout(output):
            command_routes(args, Adapter())
        self.assertEqual(len(json.loads(output.getvalue())), 1)

        with self.assertRaises(SystemExit):
            main(["connections", "--limit", "-1"])

    def test_config_deep_merge_preserves_defaults(self):
        value = deep_merge(DEFAULT_CONFIG, {"browser": {"duration": 42}})
        self.assertEqual(value["browser"]["duration"], 42)
        self.assertIn("port", value["browser"])
        self.assertEqual(DEFAULT_CONFIG["browser"]["duration"], 20.0)

    def test_default_config_is_written_privately(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            write_default_config(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), DEFAULT_CONFIG)

    def test_tui_helpers(self):
        values = parse_lsof(
            "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\napp 7 me 1u IPv4 0x1 0t0 TCP 10.0.0.2:5000->1.1.1.1:443 (ESTABLISHED)\n"
        )
        rows = process_rows(values)
        self.assertEqual(rows[0]["remote"], 1)
        self.assertEqual(len(sparkline([0, 1, 2, 3])), 4)


if __name__ == "__main__":
    unittest.main()
