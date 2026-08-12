from __future__ import annotations

import base64
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from wirescope.cdp import CDPError, WebSocket, _bounded_body
from wirescope.redact import (
    DEFAULT_REDACTION_RULES,
    REDACTED,
    SHARE_SAFE_REDACTION_RULES,
    contains_secret,
    redact_headers,
    redact_structure,
    redact_text,
    redact_url,
    safe_error,
)
from wirescope.report import generate_html_report, prepare_share_safe_report


class BufferSocket:
    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)
        self.sent = bytearray()
        self.closed = False

    def recv(self, size: int) -> bytes:
        if not self.data:
            return b""
        value = bytes(self.data[:size])
        del self.data[:size]
        return value

    def sendall(self, value: bytes) -> None:
        self.sent.extend(value)

    def close(self) -> None:
        self.closed = True

    def settimeout(self, _value: float) -> None:
        pass


def server_frame(payload: bytes, opcode: int = 0x1, final: bool = True, rsv: int = 0) -> bytes:
    first = (0x80 if final else 0) | rsv | opcode
    if len(payload) < 126:
        return bytes((first, len(payload))) + payload
    if len(payload) < 65536:
        return bytes((first, 126)) + struct.pack("!H", len(payload)) + payload
    return bytes((first, 127)) + struct.pack("!Q", len(payload)) + payload


def websocket(data: bytes, *, frame: int = 1024, message: int = 2048, event: int = 2048) -> WebSocket:
    value = WebSocket.__new__(WebSocket)
    value.socket = BufferSocket(data)
    value.max_frame_bytes = frame
    value.max_message_bytes = message
    value.max_event_bytes = event
    value._receive_buffer = bytearray()
    value._closed = False
    return value


class ValueRedactionTests(unittest.TestCase):
    def test_recognizes_known_secret_formats_inside_ordinary_values(self):
        secrets = [
            "Bearer abcdefghijklmnopqrstuvwxyz012345",
            "Basic YWRtaW46cGFzc3dvcmQ=",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.deadbeef",
            "ghp_" + "A1b2" * 9,
            "github_pat_" + "A1_b2" * 7,
            "AKIA" + "A1B2C3D4E5F6G7H8",
            "sk_live_" + "A1b2" * 6,
            "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
        ]
        for value in secrets:
            with self.subTest(value=value[:20]):
                self.assertTrue(contains_secret(value))
                self.assertNotIn(value, redact_text(f"prefix {value} suffix"))
        self.assertEqual(safe_error("request failed: token=abc"), "request failed: token=[REDACTED]")

    def test_entropy_detection_is_bounded_and_avoids_plain_hashes(self):
        token = "aB3/9xQ_kLmN2+pR7sT0vWzY4cD6eF8gH1jK5nP"
        self.assertTrue(contains_secret(token))
        self.assertIn("HIGH-ENTROPY", redact_text(token))
        plain_hex_digest = "a3" * 32
        self.assertFalse(contains_secret(plain_hex_digest))
        self.assertEqual(redact_text(plain_hex_digest), plain_hex_digest)

    def test_additive_key_header_and_path_rules(self):
        rules = DEFAULT_REDACTION_RULES.extend(
            keys=("account_id",),
            headers=("x-private-*",),
            paths=("payload.customer.*", "/private/*"),
        )
        value = redact_structure(
            {
                "account_id": "42",
                "headers": {"X-Private-Trace": "abc", "Accept": "application/json"},
                "payload": {"customer": {"name": "Mihail"}},
            },
            rules,
        )
        self.assertEqual(value["account_id"], REDACTED)
        self.assertEqual(value["headers"]["X-Private-Trace"], REDACTED)
        self.assertEqual(value["headers"]["Accept"], "application/json")
        self.assertEqual(value["payload"]["customer"]["name"], REDACTED)
        self.assertIn("[REDACTED PATH]", redact_url("https://example.com/private/person", rules=rules))
        self.assertEqual(
            redact_headers({"X-Private-Trace": "abc"}, rules=rules)["X-Private-Trace"],
            REDACTED,
        )

    def test_share_safe_policy_removes_common_identifiers(self):
        text = "user@example.com 192.168.1.2 aa:bb:cc:dd:ee:ff /Users/mihail/report.json"
        redacted = redact_text(text, SHARE_SAFE_REDACTION_RULES)
        for sensitive in ("user@example.com", "192.168.1.2", "aa:bb:cc:dd:ee:ff", "/Users/mihail"):
            self.assertNotIn(sensitive, redacted)
        self.assertEqual(
            redact_url("https://user:secret@192.168.1.2:8443/private", rules=SHARE_SAFE_REDACTION_RULES),
            "https://[REDACTED]@[REDACTED-IP]:8443/[REDACTED PATH]",
        )
        self.assertNotIn(
            "2001:db8::1",
            redact_url("https://[2001:db8::1]/private", rules=SHARE_SAFE_REDACTION_RULES),
        )


class ShareSafeReportTests(unittest.TestCase):
    def report(self):
        return {
            "generated_at": "2026-01-01T00:00:00Z",
            "source_type": "chrome-cdp",
            "source_metadata": {"path": "/Users/mihail/private/network.jsonl"},
            "summary": {"requests": 1, "domains": 1},
            "scores": {},
            "aggregates": {
                "domains": {
                    "example.com": {"requests": 1, "bytes": 10},
                    "192.168.1.2": {"requests": 1, "bytes": 1},
                }
            },
            "requests": [
                {
                    "url": "https://example.com/private/customer/42?q=value&token=secret#person",
                    "path": "/private/customer/42",
                    "domain": "example.com",
                    "method": "GET",
                    "status": 200,
                    "remote_ip": "192.168.1.2",
                    "request_headers": {"Accept": "text/html", "Authorization": "Bearer secret"},
                    "response_headers": [{"name": "Content-Type", "value": "text/html"}],
                }
            ],
            "findings": [{"evidence": ["contact user@example.com from 192.168.1.2"]}],
        }

    def test_share_safe_copy_is_strict_and_does_not_mutate_source(self):
        source = self.report()
        safe = prepare_share_safe_report(source)
        self.assertIn("/private/customer/42", source["requests"][0]["url"])
        serialized = json.dumps(safe)
        for sensitive in (
            "/Users/mihail",
            "/private/customer/42",
            "q=value",
            "token=secret",
            "192.168.1.2",
            "user@example.com",
            "Bearer secret",
        ):
            self.assertNotIn(sensitive, serialized)
        self.assertIn("example.com", serialized)
        self.assertIn("Content-Type", serialized)
        self.assertNotIn("text/html", serialized)
        self.assertTrue(safe["sharing_safety"]["share_safe"])
        self.assertTrue(safe["sharing_safety"]["review_recommended"])

    def test_html_embeds_explicit_sharing_safety_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            safe_path = Path(directory) / "safe.html"
            private_path = Path(directory) / "private.html"
            generate_html_report(self.report(), str(safe_path), share_safe=True)
            generate_html_report(self.report(), str(private_path))
            safe = safe_path.read_text(encoding="utf-8")
            private = private_path.read_text(encoding="utf-8")
        self.assertNotIn("Bearer secret", safe)
        self.assertNotIn("/Users/mihail", safe)
        self.assertIn('"mode":"share-safe"', safe)
        self.assertIn("review before publishing", safe)
        self.assertIn('"mode":"private"', private)


class WebSocketProtocolTests(unittest.TestCase):
    def test_handshake_validation_preserves_bytes_after_headers(self):
        nonce = b"0" * 16
        key = base64.b64encode(nonce).decode("ascii")
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode("ascii")
        event = server_frame(b'{"ready":true}')
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: keep-alive, Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode() + event
        transport = BufferSocket(response)
        with mock.patch("wirescope.cdp.socket.create_connection", return_value=transport), mock.patch(
            "wirescope.cdp.secrets.token_bytes", return_value=nonce
        ):
            client = WebSocket("ws://127.0.0.1/devtools/page/test")
        self.assertEqual(client.recv_json(), {"ready": True})

    def test_bad_handshake_accept_is_rejected_and_socket_closed(self):
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: wrong\r\n\r\n"
        )
        transport = BufferSocket(response)
        with mock.patch("wirescope.cdp.socket.create_connection", return_value=transport), self.assertRaisesRegex(
            CDPError, "Accept mismatch"
        ):
            WebSocket("ws://127.0.0.1/devtools/page/test")
        self.assertTrue(transport.closed)

    def test_fragmented_text_with_interleaved_ping(self):
        payload = json.dumps({"method": "Network.event", "params": {"ok": True}}).encode()
        wire = (
            server_frame(payload[:12], opcode=0x1, final=False)
            + server_frame(b"ping", opcode=0x9)
            + server_frame(payload[12:], opcode=0x0)
        )
        client = websocket(wire)
        self.assertEqual(client.recv_json()["method"], "Network.event")
        self.assertTrue(client.socket.sent)  # masked pong was returned

    def test_rejects_protocol_violations(self):
        cases = {
            "RSV": server_frame(b"{}", rsv=0x40),
            "binary": server_frame(b"{}", opcode=0x2),
            "continuation": server_frame(b"{}", opcode=0x0),
            "fragmented control": server_frame(b"x", opcode=0x9, final=False),
            "masked server": bytes((0x81, 0x80)) + b"mask",
            "non-minimal": bytes((0x81, 126)) + struct.pack("!H", 2) + b"{}",
        }
        for name, wire in cases.items():
            with self.subTest(name=name), self.assertRaises(CDPError):
                websocket(wire).recv_json()

    def test_rejects_oversize_before_reading_payload(self):
        wire = bytes((0x81, 126)) + struct.pack("!H", 500)
        with self.assertRaisesRegex(CDPError, "max_frame_bytes"):
            websocket(wire, frame=100).recv_json()

    def test_enforces_fragmented_message_and_event_limits(self):
        wire = server_frame(b'{"x":"', final=False) + server_frame(b"a" * 80 + b'"}', opcode=0x0)
        with self.assertRaisesRegex(CDPError, "max_message_bytes"):
            websocket(wire, frame=100, message=50, event=50).recv_json()

        event = server_frame(json.dumps({"value": "x" * 50}).encode())
        with self.assertRaisesRegex(CDPError, "max_event_bytes"):
            websocket(event, frame=100, message=100, event=30).recv_json()

    def test_rejects_invalid_utf8_json_and_close_payloads(self):
        with self.assertRaisesRegex(CDPError, "UTF-8"):
            websocket(server_frame(b"\xff")).recv_json()
        with self.assertRaisesRegex(CDPError, "invalid JSON"):
            websocket(server_frame(b"{bad")).recv_json()
        with self.assertRaisesRegex(CDPError, "non-finite"):
            websocket(server_frame(b'{"value":NaN}')).recv_json()
        with self.assertRaisesRegex(CDPError, "one-byte"):
            websocket(server_frame(b"x", opcode=0x8)).recv_json()
        with self.assertRaisesRegex(CDPError, "close code"):
            websocket(server_frame(struct.pack("!H", 1005), opcode=0x8)).recv_json()


class BoundedBodyTests(unittest.TestCase):
    def test_text_body_uses_utf8_byte_limit(self):
        body, size, truncated = _bounded_body("ёжик", False, 5)
        self.assertEqual(size, len("ёжик".encode("utf-8")))
        self.assertTrue(truncated)
        self.assertTrue(body.endswith("[TRUNCATED]"))
        self.assertLessEqual(len(body.removesuffix("[TRUNCATED]").encode("utf-8")), 5)

    def test_base64_body_reports_decoded_size_and_bounds_prefix(self):
        encoded = base64.b64encode(b"0123456789").decode()
        body, size, truncated = _bounded_body(encoded, True, 4)
        self.assertEqual(size, 10)
        self.assertTrue(truncated)
        prefix = body.removesuffix("[TRUNCATED]")
        self.assertLessEqual(len(base64.b64decode(prefix or b"")), 4)

    def test_invalid_base64_is_rejected(self):
        with self.assertRaisesRegex(CDPError, "invalid base64"):
            _bounded_body("not base64!", True, 10)


if __name__ == "__main__":
    unittest.main()
