# Changelog

All notable changes are documented here.

## 0.2.0 — 2026-08-10

### Added

- Full-screen interactive TUI with seven tabs, filtering, sorting, detail inspection, reverse DNS, effective routes, traffic-rate history, lifecycle events, pause, and export.
- One-command `web` workflow producing HTML, JSON, JSONL, CSV, and HAR.
- CDP request correlator with redirects, timing, cache, security, WebSocket, lifecycle, and Performance metrics.
- Performance, reliability, privacy, security, and overall scores.
- Automated findings for errors, slow/large/duplicate resources, cache usage, third parties, trackers, HTTP, and legacy TLS.
- Self-contained interactive HTML reports and before/after comparison reports.
- `diagnose`, `interfaces`, `neighbors`, `route`, `tls`, `trace`, `dns-test`, `dns-watch`, `leaks`, `speed`, and `pcap` commands.
- DNS wire-format client requiring no external package.
- VPN/DNS/IPv6 route-level leak audit.
- Plain HTTP proxy response status, headers, TTFB, and explicit body capture.
- Layered JSON configuration and shell completion.
- Deep Wi‑Fi mode and richer snapshots.
- GitHub workflow, issue templates, contribution, security, architecture, and data-format documentation.

### Changed

- Running WireScope without a subcommand now opens the dashboard.
- CLOSED sockets are hidden by default in the interactive connection table.
- Local-network traffic is distinguished from loopback and likely VPN-default traffic.
- Browser recording can stop automatically after network idle.
- Secret redaction now covers WebSocket/event-stream payloads and raw header text.

## 0.1.0 — 2026-08-09

- Initial macOS MVP with socket listing, basic dashboard, routes, DNS, VPN, quality, browser recording, HAR analysis, proxy, recording, snapshots, and PCAP capture.
