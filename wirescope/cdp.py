from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import socket
import ssl
import struct
import subprocess
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

from .artifacts import private_text_stream
from .models import utc_now
from .redact import (
    DEFAULT_REDACTION_RULES,
    REDACTED,
    RedactionRules,
    is_sensitive_key,
    is_sensitive_path,
    redact_text,
    redact_url,
    safe_error,
)


class CDPError(RuntimeError):
    pass


DEFAULT_MAX_WS_FRAME_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_WS_MESSAGE_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_CDP_EVENT_BYTES = 16 * 1024 * 1024
MAX_WEBSOCKET_HEADERS_BYTES = 64 * 1024
MAX_TARGET_DISCOVERY_BYTES = 1024 * 1024
_INVALID_CLOSE_CODES = {1004, 1005, 1006, 1015}
_HTTP_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number {value}")


def discover_target(host: str, port: int, target_index: int = 0) -> Dict[str, Any]:
    url = f"http://{host}:{port}/json"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            payload = response.read(MAX_TARGET_DISCOVERY_BYTES + 1)
            if len(payload) > MAX_TARGET_DISCOVERY_BYTES:
                raise CDPError(
                    f"Chrome target discovery exceeded {MAX_TARGET_DISCOVERY_BYTES} bytes"
                )
            targets = json.loads(payload.decode("utf-8", errors="strict"))
    except Exception as exc:
        if isinstance(exc, CDPError):
            raise
        raise CDPError(
            f"cannot reach Chrome DevTools at {url}: {exc}. Launch Chrome with --remote-debugging-port={port}"
        ) from exc
    if not isinstance(targets, list):
        raise CDPError("Chrome target discovery returned a non-list JSON value")
    pages = [
        item
        for item in targets
        if isinstance(item, dict)
        and item.get("type") == "page"
        and isinstance(item.get("webSocketDebuggerUrl"), str)
        and item.get("webSocketDebuggerUrl")
    ]
    if not pages:
        raise CDPError("Chrome exposes no debuggable page target")
    if target_index < 0 or target_index >= len(pages):
        raise CDPError(f"target index {target_index} is out of range; available pages: {len(pages)}")
    return pages[target_index]


class WebSocket:
    """Small RFC 6455 client with explicit resource and protocol bounds."""

    def __init__(
        self,
        url: str,
        *,
        max_frame_bytes: int = DEFAULT_MAX_WS_FRAME_BYTES,
        max_message_bytes: int = DEFAULT_MAX_WS_MESSAGE_BYTES,
        max_event_bytes: int = DEFAULT_MAX_CDP_EVENT_BYTES,
    ) -> None:
        for name, value in (
            ("max_frame_bytes", max_frame_bytes),
            ("max_message_bytes", max_message_bytes),
            ("max_event_bytes", max_event_bytes),
        ):
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if max_event_bytes > max_message_bytes:
            raise ValueError("max_event_bytes cannot exceed max_message_bytes")
        self.max_frame_bytes = max_frame_bytes
        self.max_message_bytes = max_message_bytes
        self.max_event_bytes = max_event_bytes
        self._receive_buffer = bytearray()
        self._closed = False
        parts = urlsplit(url)
        if parts.scheme not in ("ws", "wss"):
            raise CDPError(f"unsupported WebSocket scheme: {parts.scheme}")
        if not parts.hostname or parts.username is not None or parts.password is not None:
            raise CDPError("WebSocket URL must contain a host and must not contain userinfo")
        try:
            port = parts.port or (443 if parts.scheme == "wss" else 80)
        except ValueError as exc:
            raise CDPError(f"invalid WebSocket port: {safe_error(str(exc))}") from exc
        raw = socket.create_connection((parts.hostname, port), timeout=5)
        if parts.scheme == "wss":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parts.hostname)
        self.socket = raw
        self.socket.settimeout(0.5)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if any(character in path for character in ("\r", "\n", "\x00")):
            self.socket.close()
            raise CDPError("invalid control character in WebSocket request target")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parts.hostname}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        try:
            self.socket.sendall(request.encode("ascii"))
            response = self._read_headers()
            status, headers = self._parse_handshake(response)
            if status != 101:
                raise CDPError(f"WebSocket upgrade failed with HTTP status {status}")
            if headers.get("upgrade", "").casefold() != "websocket":
                raise CDPError("invalid WebSocket handshake: missing Upgrade: websocket")
            connections = {value.strip().casefold() for value in headers.get("connection", "").split(",")}
            if "upgrade" not in connections:
                raise CDPError("invalid WebSocket handshake: missing Connection: Upgrade")
            if "sec-websocket-extensions" in headers:
                raise CDPError("invalid WebSocket handshake: server selected an extension that was not requested")
            if "sec-websocket-protocol" in headers:
                raise CDPError("invalid WebSocket handshake: server selected a subprotocol that was not requested")
            expected = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode("ascii")
            if not secrets.compare_digest(headers.get("sec-websocket-accept", "").strip(), expected):
                raise CDPError("invalid WebSocket handshake: Sec-WebSocket-Accept mismatch")
        except Exception:
            self.socket.close()
            self._closed = True
            raise

    def _read_headers(self) -> bytes:
        data = bytearray()
        delimiter = b"\r\n\r\n"
        while True:
            boundary = data.find(delimiter)
            if boundary >= 0:
                if boundary > MAX_WEBSOCKET_HEADERS_BYTES:
                    raise CDPError("WebSocket handshake headers are too large")
                break
            chunk = self.socket.recv(4096)
            if not chunk:
                raise CDPError("WebSocket closed during HTTP upgrade")
            data.extend(chunk)
            if len(data) > MAX_WEBSOCKET_HEADERS_BYTES + len(delimiter) - 1:
                raise CDPError("WebSocket handshake headers are too large")
        headers, remainder = bytes(data).split(delimiter, 1)
        self._receive_buffer.extend(remainder)
        return headers

    @staticmethod
    def _parse_handshake(raw: bytes) -> Tuple[int, Dict[str, str]]:
        try:
            lines = raw.decode("iso-8859-1").split("\r\n")
            status_parts = lines[0].split(None, 2)
            if len(status_parts) < 2 or status_parts[0] != "HTTP/1.1":
                raise ValueError
            status = int(status_parts[1])
        except (UnicodeDecodeError, ValueError, IndexError) as exc:
            raise CDPError("invalid HTTP response during WebSocket upgrade") from exc
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if line[0] in " \t" or ":" not in line:
                raise CDPError("invalid folded or malformed WebSocket handshake header")
            key, value = line.split(":", 1)
            normalized = key.strip().casefold()
            if not normalized or not _HTTP_HEADER_NAME.fullmatch(key.strip()):
                raise CDPError("invalid WebSocket handshake header name")
            headers[normalized] = f"{headers[normalized]}, {value.strip()}" if normalized in headers else value.strip()
        return status, headers

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._send_frame(struct.pack("!H", 1000), 0x8)
        except (OSError, CDPError):
            pass
        finally:
            self._closed = True
            self.socket.close()

    def send_json(self, value: Dict[str, Any]) -> None:
        try:
            payload = json.dumps(value, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise CDPError(f"cannot encode CDP command as JSON: {safe_error(str(exc))}") from exc
        if len(payload) > self.max_event_bytes:
            raise CDPError(
                f"outgoing CDP command is {len(payload)} bytes, exceeding max_event_bytes={self.max_event_bytes}"
            )
        self._send_frame(payload, 0x1)

    def _send_frame(self, payload: bytes, opcode: int) -> None:
        if opcode not in (0x1, 0x8, 0x9, 0xA):
            raise CDPError(f"unsupported outgoing WebSocket opcode 0x{opcode:x}")
        if len(payload) > self.max_frame_bytes:
            raise CDPError(
                f"outgoing WebSocket frame is {len(payload)} bytes, exceeding max_frame_bytes={self.max_frame_bytes}"
            )
        if opcode >= 0x8 and len(payload) > 125:
            raise CDPError("outgoing WebSocket control frame exceeds 125 bytes")
        mask = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(bytes(header) + mask + masked)

    def _recv_exact(self, size: int) -> bytes:
        if size < 0:
            raise CDPError("invalid negative WebSocket read size")
        chunks = bytearray()
        if self._receive_buffer:
            take = min(size, len(self._receive_buffer))
            chunks.extend(self._receive_buffer[:take])
            del self._receive_buffer[:take]
        while len(chunks) < size:
            chunk = self.socket.recv(size - len(chunks))
            if not chunk:
                raise CDPError("WebSocket closed unexpectedly while reading a frame")
            chunks.extend(chunk)
        return bytes(chunks)

    def recv_json(self) -> Dict[str, Any]:
        fragments = bytearray()
        fragmented = False
        while True:
            first, second = self._recv_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            if first & 0x70:
                raise CDPError("invalid WebSocket frame: RSV bits are set without an extension")
            if opcode not in (0x0, 0x1, 0x2, 0x8, 0x9, 0xA):
                raise CDPError(f"invalid WebSocket frame opcode 0x{opcode:x}")
            masked = bool(second & 0x80)
            if masked:
                raise CDPError("invalid WebSocket frame: server frames must not be masked")
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
                if length < 126:
                    raise CDPError("invalid WebSocket frame: non-minimal 16-bit length encoding")
            elif length == 127:
                encoded = self._recv_exact(8)
                if encoded[0] & 0x80:
                    raise CDPError("invalid WebSocket frame: 64-bit length has its high bit set")
                length = struct.unpack("!Q", encoded)[0]
                if length < 65536:
                    raise CDPError("invalid WebSocket frame: non-minimal 64-bit length encoding")
            control = opcode >= 0x8
            if control and (not final or length > 125):
                raise CDPError("invalid WebSocket control frame: it must be final and at most 125 bytes")
            if length > self.max_frame_bytes:
                raise CDPError(
                    f"WebSocket frame is {length} bytes, exceeding max_frame_bytes={self.max_frame_bytes}"
                )
            payload = self._recv_exact(length)
            if opcode == 0x8:
                code, reason = self._validate_close_payload(payload)
                if not self._closed:
                    try:
                        self._send_frame(payload, 0x8)
                    except (OSError, CDPError):
                        pass
                    self._closed = True
                    self.socket.close()
                suffix = f": {reason}" if reason else ""
                raise CDPError(f"Chrome closed the DevTools connection (code {code}){suffix}")
            if opcode == 0x9:
                self._send_frame(payload, 0xA)
                continue
            if opcode == 0xA:
                continue
            if opcode == 0x2:
                raise CDPError("unexpected binary WebSocket message from Chrome DevTools")
            if opcode == 0x0:
                if not fragmented:
                    raise CDPError("invalid WebSocket continuation frame without an initial text frame")
            elif fragmented:
                raise CDPError("invalid WebSocket data frame before the fragmented message completed")
            else:
                fragmented = not final
            if len(fragments) + len(payload) > self.max_message_bytes:
                raise CDPError(
                    f"WebSocket message exceeds max_message_bytes={self.max_message_bytes}"
                )
            if len(fragments) + len(payload) > self.max_event_bytes:
                raise CDPError(
                    f"CDP event exceeds max_event_bytes={self.max_event_bytes}"
                )
            fragments.extend(payload)
            if not final:
                continue
            try:
                decoded = fragments.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise CDPError(f"CDP WebSocket text message is not valid UTF-8 at byte {exc.start}") from exc
            try:
                value = json.loads(decoded, parse_constant=_reject_json_constant)
            except json.JSONDecodeError as exc:
                raise CDPError(
                    f"invalid JSON in CDP WebSocket message at line {exc.lineno}, column {exc.colno}: {safe_error(exc.msg)}"
                ) from exc
            except (RecursionError, ValueError) as exc:
                raise CDPError(f"invalid or excessively nested JSON in CDP WebSocket message: {safe_error(str(exc))}") from exc
            if not isinstance(value, dict):
                raise CDPError(f"invalid CDP event type: expected object, got {type(value).__name__}")
            return value

    @staticmethod
    def _validate_close_payload(payload: bytes) -> Tuple[int, str]:
        if not payload:
            return 1005, ""
        if len(payload) == 1:
            raise CDPError("invalid WebSocket close frame: one-byte payload")
        code = struct.unpack("!H", payload[:2])[0]
        if not 1000 <= code <= 4999 or code in _INVALID_CLOSE_CODES:
            raise CDPError(f"invalid WebSocket close code {code}")
        try:
            reason = payload[2:].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CDPError("invalid UTF-8 in WebSocket close reason") from exc
        return code, reason


def sanitize(
    value: Any,
    show_sensitive: bool,
    parent_key: str = "",
    *,
    rules: Optional[RedactionRules] = None,
    _path: Tuple[str, ...] = (),
) -> Any:
    """Sanitize CDP data while preserving the historical two-argument API."""

    if show_sensitive:
        return value
    policy = rules or DEFAULT_REDACTION_RULES
    current_path = _path + ((parent_key,) if parent_key else ())
    if is_sensitive_path(current_path, policy):
        return REDACTED
    if parent_key in ("postData", "body", "postDataEntries", "payloadData", "data"):
        if isinstance(value, str):
            return f"[REDACTED {len(value.encode('utf-8'))} bytes]"
        return REDACTED
    if parent_key.casefold().endswith("headerstext") and isinstance(value, str):
        safe_lines = []
        for line in value.splitlines():
            key = line.split(":", 1)[0]
            if ":" in line and (
                policy.redact_all_headers or is_sensitive_key(key, policy, header=True)
            ):
                safe_lines.append(f"{key}: {REDACTED}")
            else:
                safe_lines.append(redact_text(line, policy))
        return "\n".join(safe_lines)
    if isinstance(value, dict):
        result = {}
        header_container = "header" in parent_key.casefold()
        for key, item in value.items():
            key_text = str(key)
            child_path = current_path + (key_text,)
            if is_sensitive_path(child_path, policy) or is_sensitive_key(key_text, policy, header=header_container):
                result[key] = REDACTED
            elif str(key).lower().endswith("url") and isinstance(item, str):
                result[key] = redact_url(item, rules=policy)
            else:
                result[key] = sanitize(item, False, key_text, rules=policy, _path=current_path)
        return result
    if isinstance(value, list):
        return [
            sanitize(item, False, "", rules=policy, _path=current_path + (str(index),))
            for index, item in enumerate(value)
        ]
    if isinstance(value, str):
        return redact_text(value, policy)
    return value


def _bounded_body(body: Any, base64_encoded: bool, max_body_bytes: int) -> Tuple[str, int, bool]:
    """Return a safely bounded CDP response body without decoding it in memory."""

    if not isinstance(max_body_bytes, int) or max_body_bytes < 0:
        raise ValueError("max_body_bytes must be a non-negative integer")
    text = body if isinstance(body, str) else str(body or "")
    if base64_encoded:
        compact = "".join(text.split())
        if compact and (
            len(compact) % 4
            or not re.fullmatch(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", compact)
        ):
            raise CDPError("Chrome returned an invalid base64-encoded response body")
        padding = len(compact) - len(compact.rstrip("="))
        original_size = max(0, (len(compact) * 3) // 4 - min(padding, 2))
        if original_size <= max_body_bytes:
            return text, original_size, False
        encoded_limit = (max_body_bytes // 3) * 4
        return compact[:encoded_limit] + "[TRUNCATED]", original_size, True
    encoded = text.encode("utf-8")
    original_size = len(encoded)
    if original_size <= max_body_bytes:
        return text, original_size, False
    bounded = encoded[:max_body_bytes].decode("utf-8", errors="ignore")
    return bounded + "[TRUNCATED]", original_size, True


class CDPRecorder:
    def __init__(
        self,
        websocket_url: str,
        output: str,
        show_sensitive: bool = False,
        capture_bodies: bool = False,
        max_body_bytes: int = 1_000_000,
        follow: bool = True,
        idle_timeout: Optional[float] = None,
        max_ws_frame_bytes: int = DEFAULT_MAX_WS_FRAME_BYTES,
        max_ws_message_bytes: int = DEFAULT_MAX_WS_MESSAGE_BYTES,
        max_cdp_event_bytes: int = DEFAULT_MAX_CDP_EVENT_BYTES,
        redaction_rules: Optional[RedactionRules] = None,
    ) -> None:
        if not isinstance(max_body_bytes, int) or max_body_bytes < 0:
            raise ValueError("max_body_bytes must be a non-negative integer")
        for name, value in (
            ("max_ws_frame_bytes", max_ws_frame_bytes),
            ("max_ws_message_bytes", max_ws_message_bytes),
            ("max_cdp_event_bytes", max_cdp_event_bytes),
        ):
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if max_cdp_event_bytes > max_ws_message_bytes:
            raise ValueError("max_cdp_event_bytes cannot exceed max_ws_message_bytes")
        self.websocket_url = websocket_url
        self.output = Path(output)
        self.show_sensitive = show_sensitive
        self.capture_bodies = capture_bodies
        self.max_body_bytes = max_body_bytes
        self.follow = follow
        self.idle_timeout = idle_timeout
        self.max_ws_frame_bytes = max_ws_frame_bytes
        self.max_ws_message_bytes = max_ws_message_bytes
        self.max_cdp_event_bytes = max_cdp_event_bytes
        self.redaction_rules = redaction_rules or DEFAULT_REDACTION_RULES
        self.next_id = 1
        self.pending_bodies: Dict[int, str] = {}
        self.pending_commands: Dict[int, str] = {}
        self.requests: Dict[str, Dict[str, Any]] = {}
        self.domains: Counter[str] = Counter()
        self.types: Counter[str] = Counter()
        self.statuses: Counter[str] = Counter()
        self.methods: Counter[str] = Counter()
        self.network_failures = 0
        self.http_errors = 0
        self.encoded_bytes = 0
        self.inflight: set = set()
        self.page_loaded = False
        self.last_network_activity = time.monotonic()

    def command(self, websocket: WebSocket, method: str, params: Optional[Dict[str, Any]] = None) -> int:
        command_id = self.next_id
        self.next_id += 1
        self.pending_commands[command_id] = method
        websocket.send_json({"id": command_id, "method": method, "params": params or {}})
        return command_id

    def _write(self, stream: Any, event: Dict[str, Any]) -> None:
        stream.write(
            json.dumps(event, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            + "\n"
        )
        stream.flush()

    def record(self, duration: float, navigate: Optional[str] = None, disable_cache: bool = False) -> Dict[str, Any]:
        if (
            self.max_ws_frame_bytes == DEFAULT_MAX_WS_FRAME_BYTES
            and self.max_ws_message_bytes == DEFAULT_MAX_WS_MESSAGE_BYTES
            and self.max_cdp_event_bytes == DEFAULT_MAX_CDP_EVENT_BYTES
        ):
            # Keeping the one-argument construction path preserves compatibility
            # with embedders that replace the transport in tests.
            websocket = WebSocket(self.websocket_url)
        else:
            websocket = WebSocket(
                self.websocket_url,
                max_frame_bytes=self.max_ws_frame_bytes,
                max_message_bytes=self.max_ws_message_bytes,
                max_event_bytes=self.max_cdp_event_bytes,
            )
        started = time.monotonic()
        stopped_reason = "duration"
        try:
            with private_text_stream(self.output) as stream:
                self._write(stream, {"type": "session_start", "timestamp": utc_now(), "source": "chrome_cdp"})
                self.command(
                    websocket,
                    "Network.enable",
                    {
                        "maxTotalBufferSize": 100_000_000,
                        "maxResourceBufferSize": 10_000_000,
                    },
                )
                self.command(websocket, "Page.enable")
                self.command(websocket, "Page.setLifecycleEventsEnabled", {"enabled": True})
                self.command(websocket, "Performance.enable")
                self.command(websocket, "Security.enable")
                if disable_cache:
                    self.command(websocket, "Network.setCacheDisabled", {"cacheDisabled": True})
                if navigate:
                    self.command(websocket, "Page.navigate", {"url": navigate})
                stopped_reason = "duration"
                while time.monotonic() - started < duration:
                    try:
                        message = websocket.recv_json()
                    except socket.timeout:
                        if (
                            self.idle_timeout is not None
                            and self.page_loaded
                            and not self.inflight
                            and time.monotonic() - self.last_network_activity >= self.idle_timeout
                        ):
                            stopped_reason = "network_idle"
                            break
                        continue
                    self._handle_message(websocket, stream, message)
                    if (
                        self.idle_timeout is not None
                        and self.page_loaded
                        and not self.inflight
                        and time.monotonic() - self.last_network_activity >= self.idle_timeout
                    ):
                        stopped_reason = "network_idle"
                        break
                metrics_id = self.command(websocket, "Performance.getMetrics")
                metrics_deadline = time.monotonic() + 1.0
                while metrics_id in self.pending_commands and time.monotonic() < metrics_deadline:
                    try:
                        self._handle_message(websocket, stream, websocket.recv_json())
                    except socket.timeout:
                        continue
                summary = {
                    "requests": len(self.requests),
                    "failed": self.network_failures + self.http_errors,
                    "network_failures": self.network_failures,
                    "http_errors": self.http_errors,
                    "encoded_bytes": self.encoded_bytes,
                    "domains": dict(self.domains.most_common()),
                    "methods": dict(self.methods),
                    "resource_types": dict(self.types),
                    "statuses": dict(self.statuses),
                    "observed_seconds": round(time.monotonic() - started, 2),
                    "stopped_reason": stopped_reason,
                }
                self._write(stream, {"type": "session_end", "timestamp": utc_now(), "summary": summary})
            return summary
        finally:
            websocket.close()

    def _handle_message(self, websocket: WebSocket, stream: Any, message: Dict[str, Any]) -> None:
        message_id = message.get("id")
        if "id" in message and (not isinstance(message_id, int) or isinstance(message_id, bool)):
            raise CDPError(f"invalid CDP response id type: {type(message_id).__name__}")
        if "id" in message and message_id in self.pending_bodies:
            self.pending_commands.pop(message_id, None)
            request_id = self.pending_bodies.pop(message_id)
            result = message.get("result", {})
            if not isinstance(result, dict):
                raise CDPError("invalid CDP response body result: expected object")
            base64_encoded = bool(result.get("base64Encoded"))
            body, raw_length, truncated = _bounded_body(
                result.get("body", ""), base64_encoded, self.max_body_bytes
            )
            event = {
                "type": "response_body",
                "timestamp": utc_now(),
                "request_id": request_id,
                "base64_encoded": base64_encoded,
                "original_size": raw_length,
                "captured_size_limit": self.max_body_bytes,
                "truncated": truncated,
                "body": body if self.show_sensitive else f"[REDACTED {raw_length} bytes]",
            }
            self._write(stream, event)
            return
        if "id" in message:
            command = self.pending_commands.pop(message_id, "unknown")
            self._write(
                stream,
                {
                    "type": "cdp_command_result",
                    "timestamp": utc_now(),
                    "command": command,
                    "result": sanitize(message.get("result"), self.show_sensitive, rules=self.redaction_rules),
                    "error": sanitize(message.get("error"), self.show_sensitive, rules=self.redaction_rules),
                },
            )
            return
        method = message.get("method")
        if not method:
            return
        if not isinstance(method, str):
            raise CDPError(f"invalid CDP event method type: {type(method).__name__}")
        params = message.get("params", {})
        if not isinstance(params, dict):
            raise CDPError(f"invalid CDP params for {method}: expected object")
        request_id = params.get("requestId")
        if method == "Network.requestWillBeSent":
            self.inflight.add(str(request_id))
            self.last_network_activity = time.monotonic()
            request = params.get("request", {})
            url = str(request.get("url", ""))
            domain = urlsplit(url).hostname or "unknown"
            resource_type = str(params.get("type", "Other"))
            http_method = str(request.get("method", "?"))
            self.domains[domain] += 1
            self.types[resource_type] += 1
            self.methods[http_method] += 1
            self.requests[str(request_id)] = {"url": url, "type": resource_type, "method": http_method}
            if self.follow:
                print(
                    f"→ {resource_type[:10]:10} {http_method[:7]:7} "
                    f"{redact_url(url, self.show_sensitive, self.redaction_rules)}",
                    flush=True,
                )
        elif method == "Network.responseReceived":
            self.last_network_activity = time.monotonic()
            response = params.get("response", {})
            status = int(response.get("status", 0) or 0)
            self.statuses[str(status)] += 1
            if status >= 400:
                self.http_errors += 1
            if self.follow:
                known = self.requests.get(str(request_id), {})
                url = redact_url(
                    str(response.get("url") or known.get("url") or ""),
                    self.show_sensitive,
                    self.redaction_rules,
                )
                print(f"← {int(response.get('status', 0)):3} {str(params.get('type', 'Other'))[:10]:10} {url}", flush=True)
        elif method == "Network.loadingFailed":
            self.inflight.discard(str(request_id))
            self.last_network_activity = time.monotonic()
            self.network_failures += 1
            if self.follow:
                known = self.requests.get(str(request_id), {})
                error_text = str(params.get("errorText", "failed"))
                print(
                    f"× {redact_text(error_text, self.redaction_rules)} "
                    f"{redact_url(str(known.get('url', '')), self.show_sensitive, self.redaction_rules)}",
                    flush=True,
                )
        elif method == "Network.loadingFinished":
            self.inflight.discard(str(request_id))
            self.last_network_activity = time.monotonic()
            self.encoded_bytes += int(params.get("encodedDataLength", 0) or 0)
            if self.capture_bodies and request_id:
                command_id = self.command(websocket, "Network.getResponseBody", {"requestId": request_id})
                self.pending_bodies[command_id] = str(request_id)
        elif method == "Page.loadEventFired":
            self.page_loaded = True
        event = {
            "type": "cdp_event",
            "timestamp": utc_now(),
            "method": method,
            "params": sanitize(params, self.show_sensitive, rules=self.redaction_rules),
        }
        self._write(stream, event)


def record_browser(
    host: str,
    port: int,
    target_index: int,
    output: str,
    duration: float,
    navigate: Optional[str],
    disable_cache: bool,
    capture_bodies: bool,
    max_body_bytes: int,
    show_sensitive: bool,
    follow: bool = True,
    idle_timeout: Optional[float] = None,
    max_ws_frame_bytes: int = DEFAULT_MAX_WS_FRAME_BYTES,
    max_ws_message_bytes: int = DEFAULT_MAX_WS_MESSAGE_BYTES,
    max_cdp_event_bytes: int = DEFAULT_MAX_CDP_EVENT_BYTES,
    redaction_rules: Optional[RedactionRules] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    target = discover_target(host, port, target_index=target_index)
    recorder = CDPRecorder(
        target["webSocketDebuggerUrl"],
        output,
        show_sensitive=show_sensitive,
        capture_bodies=capture_bodies,
        max_body_bytes=max_body_bytes,
        follow=follow,
        idle_timeout=idle_timeout,
        max_ws_frame_bytes=max_ws_frame_bytes,
        max_ws_message_bytes=max_ws_message_bytes,
        max_cdp_event_bytes=max_cdp_event_bytes,
        redaction_rules=redaction_rules,
    )
    try:
        summary = recorder.record(duration=duration, navigate=navigate, disable_cache=disable_cache)
    except (OSError, CDPError, json.JSONDecodeError, UnicodeError) as exc:
        raise CDPError(safe_error(str(exc))) from exc
    return target, summary


def launch_chrome(port: int, profile: str, initial_url: str = "about:blank", headless: bool = False) -> subprocess.Popen:
    candidates = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    ]
    executable = next((item for item in candidates if os.path.exists(item)), None)
    if executable is None:
        raise CDPError("Google Chrome or Chromium was not found in /Applications")
    Path(profile).mkdir(parents=True, exist_ok=True)
    arguments = [
        executable,
        f"--remote-debugging-port={port}",
        "--remote-debugging-address=127.0.0.1",
        f"--user-data-dir={profile}",
    ]
    if headless:
        arguments.extend(["--headless=new", "--disable-gpu"])
    arguments.append(initial_url)
    process = subprocess.Popen(
        arguments,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        try:
            discover_target("127.0.0.1", port)
            return process
        except CDPError:
            time.sleep(0.25)
    raise CDPError(f"Chrome started as PID {process.pid}, but DevTools port {port} did not become ready")
