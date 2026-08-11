# Architecture

WireScope uses a layered sensor model.

```text
Native macOS commands ─┐
Chrome DevTools ───────┼─> normalized events ─> analysis ─> terminal/JSON/CSV/HAR/HTML
HTTP/CONNECT proxy ────┤
tcpdump/PCAP ──────────┘
```

## Native sensor

`macos.py` executes fixed native command arrays and converts their output into typed models. `lsof` supplies process/socket ownership, `ifconfig` interfaces, `netstat` routes/counters, `scutil` resolvers/proxy state, and `system_profiler` radio metadata.

Native output changes across OS versions, so pure parser functions are separated from command execution and tested with fixtures.

## Browser sensor

`cdp.py` implements the WebSocket protocol and Chrome DevTools Protocol without third-party dependencies. It writes every enabled event to JSONL before analysis. `analyzer.py` correlates request IDs, redirects, responses, body/transfer lengths, failures, timing, lifecycle, WebSocket totals, and final Performance metrics.

Chrome sees decrypted requests inside the selected browser target. This does not provide visibility into unrelated processes.

## Proxy sensor

`proxy.py` is an asyncio forward proxy. Plain HTTP exposes request/response metadata. HTTPS uses CONNECT and remains encrypted. The proxy does not install a root CA or weaken TLS.

## Packet sensor

`capture.py` constrains invocation of native `tcpdump`, parses plaintext DNS, and summarizes PCAPs. PCAP has packet visibility but generally cannot identify the owning process or decrypt TLS.

## Analysis

Normalized requests feed deterministic aggregations, scores, and explainable findings. Tracker classification is deliberately heuristic and its evidence remains visible.

## Privilege boundary

Most WireScope commands run as the current user. Packet capture, DNS watch, and deep Wi‑Fi diagnostics may require `sudo`. WireScope does not include a persistent privileged daemon.

