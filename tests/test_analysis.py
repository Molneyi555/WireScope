import json
import struct
import tempfile
import unittest
from pathlib import Path

from wirescope.analyzer import analyze_cdp_events, analyze_recording, export_har, export_requests_csv
from wirescope.capture import parse_dns_tcpdump_line, parse_packet_line
from wirescope.diagnostics import encode_dns_name, parse_dns_response
from wirescope.report import generate_html_report


def cdp(method, params):
    return {"type": "cdp_event", "timestamp": "2026-01-01T00:00:00Z", "method": method, "params": params}


def synthetic_events():
    timing = {
        "requestTime": 1.0,
        "dnsStart": 0,
        "dnsEnd": 5,
        "connectStart": 5,
        "connectEnd": 15,
        "sslStart": 7,
        "sslEnd": 14,
        "sendStart": 15,
        "sendEnd": 16,
        "receiveHeadersEnd": 45,
    }
    return [
        {"type": "session_start", "timestamp": "2026-01-01T00:00:00Z", "source": "chrome_cdp"},
        cdp(
            "Network.requestWillBeSent",
            {
                "requestId": "1",
                "timestamp": 1.0,
                "wallTime": 1767225600.0,
                "documentURL": "https://example.com/",
                "type": "Document",
                "request": {"url": "https://example.com/", "method": "GET", "headers": {}},
                "initiator": {"type": "other"},
            },
        ),
        cdp(
            "Network.responseReceived",
            {
                "requestId": "1",
                "type": "Document",
                "response": {
                    "url": "https://example.com/",
                    "status": 200,
                    "protocol": "h2",
                    "mimeType": "text/html",
                    "remoteIPAddress": "93.184.216.34",
                    "remotePort": 443,
                    "timing": timing,
                    "securityState": "secure",
                    "securityDetails": {"protocol": "TLS 1.3"},
                },
            },
        ),
        cdp("Network.dataReceived", {"requestId": "1", "dataLength": 1000}),
        cdp("Network.loadingFinished", {"requestId": "1", "timestamp": 1.08, "encodedDataLength": 500}),
        cdp(
            "Network.requestWillBeSent",
            {
                "requestId": "2",
                "timestamp": 1.02,
                "wallTime": 1767225600.02,
                "documentURL": "https://example.com/",
                "type": "Script",
                "request": {"url": "https://www.google-analytics.com/collect", "method": "POST", "headers": {}},
                "initiator": {"type": "script"},
            },
        ),
        cdp(
            "Network.responseReceived",
            {
                "requestId": "2",
                "type": "Script",
                "response": {"status": 404, "protocol": "h2", "mimeType": "text/plain", "timing": timing},
            },
        ),
        cdp("Network.loadingFinished", {"requestId": "2", "timestamp": 2.5, "encodedDataLength": 1_500_000}),
        cdp("Page.lifecycleEvent", {"name": "load", "timestamp": 2.6}),
        cdp("Network.webSocketCreated", {"requestId": "ws1", "url": "wss://example.com/socket"}),
        cdp("Network.webSocketFrameSent", {"requestId": "ws1", "response": {"payloadData": "hello"}}),
        {
            "type": "cdp_command_result",
            "timestamp": "2026-01-01T00:00:03Z",
            "command": "Performance.getMetrics",
            "result": {"metrics": [{"name": "JSHeapUsedSize", "value": 1234}]},
        },
        {"type": "session_end", "summary": {"requests": 2}},
    ]


class AnalyzerTests(unittest.TestCase):
    def test_cdp_correlation_findings_and_scores(self):
        report = analyze_cdp_events(synthetic_events())
        self.assertEqual(report["summary"]["requests"], 2)
        self.assertEqual(report["summary"]["http_errors"], 1)
        self.assertEqual(report["summary"]["trackers"], 1)
        self.assertEqual(report["summary"]["large_requests"], 1)
        self.assertEqual(report["browser"]["performance_metrics"]["JSHeapUsedSize"], 1234)
        self.assertEqual(report["browser"]["websocket"]["sent_frames"], 1)
        self.assertLess(report["scores"]["overall"], 100)

    def test_recording_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "session.jsonl"
            source.write_text("\n".join(json.dumps(item) for item in synthetic_events()), encoding="utf-8")
            report = analyze_recording(str(source))
            html_path = Path(directory) / "report.html"
            csv_path = Path(directory) / "requests.csv"
            har_path = Path(directory) / "requests.har"
            generate_html_report(report, str(html_path))
            export_requests_csv(report, str(csv_path))
            export_har(report, str(har_path))
            self.assertIn("WireScope Network Report", html_path.read_text(encoding="utf-8"))
            self.assertIn("google-analytics", csv_path.read_text(encoding="utf-8"))
            self.assertEqual(len(json.loads(har_path.read_text(encoding="utf-8"))["log"]["entries"]), 2)

    def test_report_escapes_script_termination(self):
        report = analyze_cdp_events(synthetic_events())
        report["requests"][0]["url"] = "https://example.com/</script><script>alert(1)</script>"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "safe.html"
            generate_html_report(report, str(output))
            text = output.read_text(encoding="utf-8")
        self.assertNotIn("https://example.com/</script><script>", text)


class DNSPacketTests(unittest.TestCase):
    def test_parse_dns_response(self):
        query_id = 123
        name = encode_dns_name("example.com")
        packet = (
            struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
            + name
            + struct.pack("!HH", 1, 1)
            + b"\xc0\x0c"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + bytes([93, 184, 216, 34])
        )
        result = parse_dns_response(packet, query_id)
        self.assertEqual(result["rcode_name"], "NOERROR")
        self.assertEqual(result["records"][0]["value"], "93.184.216.34")

    def test_tcpdump_parsers(self):
        dns = parse_dns_tcpdump_line("2026-01-01 IP 192.168.1.2.50000 > 1.1.1.1.53: 1234+ A? example.com. (29)")
        self.assertEqual(dns["domain"], "example.com")
        self.assertEqual(dns["destination"]["host"], "1.1.1.1")
        packet = parse_packet_line("2026-01-01 IP 10.0.0.1.50000 > 1.1.1.1.443: Flags [S], length 0")
        self.assertEqual(packet["protocol"], "tcp")
        self.assertEqual(packet["destination"], "1.1.1.1:443")


if __name__ == "__main__":
    unittest.main()
