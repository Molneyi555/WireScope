from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import time
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import urlsplit

from .artifacts import private_text_stream
from .models import utc_now
from .redact import redact_headers, redact_url, safe_error


MAX_HEADER = 1024 * 1024


def parse_host_port(value: str, default_port: int) -> Tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        closing = value.find("]")
        host = value[1:closing]
        port = int(value[closing + 2 :]) if value[closing + 1 :].startswith(":") else default_port
        return host, port
    if value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        return host, int(raw_port)
    return value, default_port


def parse_headers(lines: Iterable[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


class EventWriter:
    def __init__(self, path: Optional[str], show_sensitive: bool = False, capture_http_bodies: bool = False, max_body_bytes: int = 1_000_000) -> None:
        self.path = Path(path) if path else None
        self.show_sensitive = show_sensitive
        self.capture_http_bodies = capture_http_bodies
        self.max_body_bytes = max_body_bytes
        self._stream = None
        self._stream_context = None

    def __enter__(self) -> "EventWriter":
        if self.path:
            self._stream_context = private_text_stream(self.path, append=True)
            self._stream = self._stream_context.__enter__()
        return self

    def __exit__(self, *_args: object) -> None:
        if self._stream:
            self._stream_context.__exit__(None, None, None)

    def emit(self, event: Dict[str, Any]) -> None:
        line = json.dumps(event, ensure_ascii=False, separators=(",", ":"))
        print(line, flush=True)
        if self._stream:
            self._stream.write(line + "\n")
            self._stream.flush()


async def pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    capture: Optional[bytearray] = None,
    capture_limit: int = 0,
) -> int:
    count = 0
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
            count += len(chunk)
            if capture is not None and len(capture) < capture_limit:
                capture.extend(chunk[: capture_limit - len(capture)])
    except (ConnectionError, asyncio.CancelledError):
        pass
    try:
        writer.write_eof()
    except (OSError, AttributeError):
        pass
    return count


class ForwardProxy:
    def __init__(self, writer: EventWriter) -> None:
        self.events = writer

    async def handle(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        peer = client_writer.get_extra_info("peername")
        started = time.monotonic()
        upstream_writer: Optional[asyncio.StreamWriter] = None
        upload: Optional[asyncio.Task] = None
        download: Optional[asyncio.Task] = None
        event: Dict[str, Any] = {"type": "proxy_request", "timestamp": utc_now(), "client": str(peer)}
        try:
            raw_header = await client_reader.readuntil(b"\r\n\r\n")
            if len(raw_header) > MAX_HEADER:
                raise ValueError("request headers exceed 1 MiB")
            text = raw_header.decode("iso-8859-1")
            lines = text.split("\r\n")
            method, target, version = lines[0].split(" ", 2)
            headers = parse_headers(lines[1:])
            event.update(
                {
                    "method": method,
                    "target": redact_url(target, self.events.show_sensitive),
                    "http_version": version,
                    "headers": redact_headers(
                        [(key, value) for key, value in headers.items() if key.lower() in ("host", "user-agent", "content-type", "content-length", "referer", "authorization", "cookie")],
                        self.events.show_sensitive,
                    ),
                }
            )
            for key in list(event["headers"]):
                if key.lower() in ("referer", "referrer"):
                    event["headers"][key] = redact_url(event["headers"][key], self.events.show_sensitive)
            is_connect = method.upper() == "CONNECT"
            if is_connect:
                host, port = parse_host_port(target, 443)
                event.update({"mode": "tls_tunnel", "host": host, "port": port})
                upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
                client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: WireScope/0.2\r\n\r\n")
                await client_writer.drain()
            else:
                parsed = urlsplit(target)
                host_header = headers.get("Host") or headers.get("host", "")
                host, port = parse_host_port(parsed.netloc or host_header, 80)
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                event.update({"mode": "http", "host": host, "port": port, "target": redact_url(target, self.events.show_sensitive)})
                upstream_reader, upstream_writer = await asyncio.open_connection(host, port)
                forwarded = [f"{method} {path} {version}"]
                for key, value in headers.items():
                    if key.lower() in ("proxy-connection", "proxy-authorization", "connection"):
                        continue
                    forwarded.append(f"{key}: {value}")
                forwarded.append("Connection: close")
                upstream_writer.write(("\r\n".join(forwarded) + "\r\n\r\n").encode("iso-8859-1"))
                await upstream_writer.drain()
            request_capture = bytearray() if self.events.capture_http_bodies and not is_connect else None
            response_capture = bytearray() if self.events.capture_http_bodies and not is_connect else None
            upload = asyncio.create_task(
                pipe(client_reader, upstream_writer, request_capture, self.events.max_body_bytes)
            )
            initial_download = 0
            if not is_connect:
                response_header = await asyncio.wait_for(upstream_reader.readuntil(b"\r\n\r\n"), timeout=30)
                if len(response_header) > MAX_HEADER:
                    raise ValueError("response headers exceed 1 MiB")
                response_text = response_header.decode("iso-8859-1", errors="replace")
                response_lines = response_text.split("\r\n")
                status_parts = response_lines[0].split(" ", 2)
                response_headers = parse_headers(response_lines[1:])
                event["response"] = {
                    "http_version": status_parts[0] if status_parts else "",
                    "status": int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 0,
                    "reason": status_parts[2] if len(status_parts) > 2 else "",
                    "headers": redact_headers(response_headers.items(), self.events.show_sensitive),
                }
                event["ttfb_ms"] = round((time.monotonic() - started) * 1000, 2)
                client_writer.write(response_header)
                await client_writer.drain()
                initial_download = len(response_header)
            download = asyncio.create_task(
                pipe(upstream_reader, client_writer, response_capture, self.events.max_body_bytes)
            )
            down_bytes = await download
            if not upload.done():
                upload.cancel()
            up_bytes = await upload
            event.update({"ok": True, "upload_bytes": up_bytes, "download_bytes": down_bytes + initial_download})
            if request_capture is not None:
                event["request_body_base64"] = base64.b64encode(bytes(request_capture)).decode("ascii")
                event["request_body_truncated"] = up_bytes > len(request_capture)
            if response_capture is not None:
                event["response_body_base64"] = base64.b64encode(bytes(response_capture)).decode("ascii")
                event["response_body_truncated"] = down_bytes > len(response_capture)
        except (asyncio.IncompleteReadError, ValueError, OSError) as exc:
            event.update({"ok": False, "error": safe_error(str(exc))})
            try:
                client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                await client_writer.drain()
            except OSError:
                pass
        finally:
            for task in (upload, download):
                if task is not None and not task.done():
                    task.cancel()
            event["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
            self.events.emit(event)
            if upstream_writer:
                upstream_writer.close()
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except OSError:
                pass


def validate_bind(host: str, allow_remote: bool) -> None:
    if allow_remote or host == "localhost":
        return
    try:
        if ipaddress.ip_address(host).is_loopback:
            return
    except ValueError:
        pass
    raise ValueError("refusing a non-loopback proxy bind; pass --allow-remote to acknowledge the exposure")


async def serve_proxy(
    host: str,
    port: int,
    output: Optional[str],
    show_sensitive: bool,
    allow_remote: bool,
    capture_http_bodies: bool = False,
    max_body_bytes: int = 1_000_000,
) -> None:
    validate_bind(host, allow_remote)
    if capture_http_bodies and not show_sensitive:
        raise ValueError("--capture-http-bodies requires --show-sensitive because bodies can contain credentials")
    with EventWriter(
        output,
        show_sensitive=show_sensitive,
        capture_http_bodies=capture_http_bodies,
        max_body_bytes=max_body_bytes,
    ) as writer:
        proxy = ForwardProxy(writer)
        server = await asyncio.start_server(proxy.handle, host, port)
        addresses = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
        print(f"WireScope proxy listening on {addresses}", flush=True)
        print(f"HTTP_PROXY=http://{host}:{port} HTTPS_PROXY=http://{host}:{port}", flush=True)
        print("HTTPS is recorded as CONNECT metadata; payload remains encrypted.", flush=True)
        async with server:
            await server.serve_forever()
