from __future__ import annotations

import base64
import hashlib
import json
import os
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

from .models import utc_now
from .redact import SENSITIVE_KEYS, redact_url, safe_error


class CDPError(RuntimeError):
    pass


def discover_target(host: str, port: int, target_index: int = 0) -> Dict[str, Any]:
    url = f"http://{host}:{port}/json"
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            targets = json.load(response)
    except Exception as exc:
        raise CDPError(
            f"cannot reach Chrome DevTools at {url}: {exc}. Launch Chrome with --remote-debugging-port={port}"
        ) from exc
    pages = [item for item in targets if item.get("type") == "page" and item.get("webSocketDebuggerUrl")]
    if not pages:
        raise CDPError("Chrome exposes no debuggable page target")
    if target_index < 0 or target_index >= len(pages):
        raise CDPError(f"target index {target_index} is out of range; available pages: {len(pages)}")
    return pages[target_index]


class WebSocket:
    def __init__(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("ws", "wss"):
            raise CDPError(f"unsupported WebSocket scheme: {parts.scheme}")
        port = parts.port or (443 if parts.scheme == "wss" else 80)
        raw = socket.create_connection((parts.hostname or "127.0.0.1", port), timeout=5)
        if parts.scheme == "wss":
            raw = ssl.create_default_context().wrap_socket(raw, server_hostname=parts.hostname)
        self.socket = raw
        self.socket.settimeout(0.5)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parts.hostname}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.socket.sendall(request.encode("ascii"))
        response = self._read_headers()
        if not response.startswith(b"HTTP/1.1 101"):
            raise CDPError(response.decode("iso-8859-1", errors="replace").split("\r\n", 1)[0])
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
        if expected.lower() not in response.lower():
            raise CDPError("invalid WebSocket handshake response")

    def _read_headers(self) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.socket.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 65536:
                raise CDPError("WebSocket handshake headers are too large")
        return bytes(data)

    def close(self) -> None:
        try:
            self._send_frame(b"", 0x8)
        except OSError:
            pass
        self.socket.close()

    def send_json(self, value: Dict[str, Any]) -> None:
        self._send_frame(json.dumps(value, separators=(",", ":")).encode("utf-8"), 0x1)

    def _send_frame(self, payload: bytes, opcode: int) -> None:
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
        chunks = bytearray()
        while len(chunks) < size:
            chunk = self.socket.recv(size - len(chunks))
            if not chunk:
                raise CDPError("WebSocket closed")
            chunks.extend(chunk)
        return bytes(chunks)

    def recv_json(self) -> Dict[str, Any]:
        fragments = bytearray()
        while True:
            first, second = self._recv_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]
            mask = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length)
            if masked:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 0x8:
                raise CDPError("Chrome closed the DevTools connection")
            if opcode == 0x9:
                self._send_frame(payload, 0xA)
                continue
            if opcode in (0x1, 0x0):
                fragments.extend(payload)
                if final:
                    return json.loads(fragments.decode("utf-8"))


def sanitize(value: Any, show_sensitive: bool, parent_key: str = "") -> Any:
    if show_sensitive:
        return value
    if parent_key in ("postData", "body", "postDataEntries", "payloadData", "data"):
        if isinstance(value, str):
            return f"[REDACTED {len(value.encode('utf-8'))} bytes]"
        return "[REDACTED]"
    if parent_key == "headersText" and isinstance(value, str):
        safe_lines = []
        for line in value.splitlines():
            key = line.split(":", 1)[0]
            safe_lines.append(f"{key}: [REDACTED]" if SENSITIVE_KEYS.search(key) else line)
        return "\n".join(safe_lines)
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.search(str(key)):
                result[key] = "[REDACTED]"
            elif str(key).lower().endswith("url") and isinstance(item, str):
                result[key] = redact_url(item)
            else:
                result[key] = sanitize(item, False, str(key))
        return result
    if isinstance(value, list):
        return [sanitize(item, False, parent_key) for item in value]
    return value


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
    ) -> None:
        self.websocket_url = websocket_url
        self.output = Path(output)
        self.show_sensitive = show_sensitive
        self.capture_bodies = capture_bodies
        self.max_body_bytes = max_body_bytes
        self.follow = follow
        self.idle_timeout = idle_timeout
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
        stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()

    def record(self, duration: float, navigate: Optional[str] = None, disable_cache: bool = False) -> Dict[str, Any]:
        self.output.parent.mkdir(parents=True, exist_ok=True)
        websocket = WebSocket(self.websocket_url)
        started = time.monotonic()
        with self.output.open("w", encoding="utf-8") as stream:
            self._write(stream, {"type": "session_start", "timestamp": utc_now(), "source": "chrome_cdp"})
            self.command(websocket, "Network.enable", {"maxTotalBufferSize": 100_000_000, "maxResourceBufferSize": 10_000_000})
            self.command(websocket, "Page.enable")
            self.command(websocket, "Page.setLifecycleEventsEnabled", {"enabled": True})
            self.command(websocket, "Performance.enable")
            self.command(websocket, "Security.enable")
            if disable_cache:
                self.command(websocket, "Network.setCacheDisabled", {"cacheDisabled": True})
            if navigate:
                self.command(websocket, "Page.navigate", {"url": navigate})
            try:
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
            finally:
                websocket.close()
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

    def _handle_message(self, websocket: WebSocket, stream: Any, message: Dict[str, Any]) -> None:
        if "id" in message and message["id"] in self.pending_bodies:
            self.pending_commands.pop(message["id"], None)
            request_id = self.pending_bodies.pop(message["id"])
            result = message.get("result", {})
            body = result.get("body", "")
            raw_length = len(body) if result.get("base64Encoded") else len(body.encode("utf-8"))
            if raw_length > self.max_body_bytes:
                body = body[: self.max_body_bytes] + "[TRUNCATED]"
            event = {
                "type": "response_body",
                "timestamp": utc_now(),
                "request_id": request_id,
                "base64_encoded": bool(result.get("base64Encoded")),
                "original_size": raw_length,
                "body": body if self.show_sensitive else f"[REDACTED {raw_length} bytes]",
            }
            self._write(stream, event)
            return
        if "id" in message:
            command = self.pending_commands.pop(message["id"], "unknown")
            self._write(
                stream,
                {
                    "type": "cdp_command_result",
                    "timestamp": utc_now(),
                    "command": command,
                    "result": sanitize(message.get("result"), self.show_sensitive),
                    "error": sanitize(message.get("error"), self.show_sensitive),
                },
            )
            return
        method = message.get("method")
        if not method:
            return
        params = message.get("params", {})
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
                print(f"→ {resource_type[:10]:10} {http_method[:7]:7} {redact_url(url, self.show_sensitive)}", flush=True)
        elif method == "Network.responseReceived":
            self.last_network_activity = time.monotonic()
            response = params.get("response", {})
            status = int(response.get("status", 0) or 0)
            self.statuses[str(status)] += 1
            if status >= 400:
                self.http_errors += 1
            if self.follow:
                known = self.requests.get(str(request_id), {})
                url = redact_url(str(response.get("url") or known.get("url") or ""), self.show_sensitive)
                print(f"← {int(response.get('status', 0)):3} {str(params.get('type', 'Other'))[:10]:10} {url}", flush=True)
        elif method == "Network.loadingFailed":
            self.inflight.discard(str(request_id))
            self.last_network_activity = time.monotonic()
            self.network_failures += 1
            if self.follow:
                known = self.requests.get(str(request_id), {})
                print(f"× {params.get('errorText', 'failed')} {redact_url(str(known.get('url', '')), self.show_sensitive)}", flush=True)
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
            "params": sanitize(params, self.show_sensitive),
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
    )
    try:
        summary = recorder.record(duration=duration, navigate=navigate, disable_cache=disable_cache)
    except (OSError, CDPError, json.JSONDecodeError) as exc:
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
