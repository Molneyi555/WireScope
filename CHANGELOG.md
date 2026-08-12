# Changelog

All notable changes are documented here.

## Unreleased — 0.3.0 release candidate

### Added

- `budget` command for CI-friendly performance, reliability, privacy, cache, transfer, timing, and score limits.
- Reusable JSON budget policies, human-readable byte sizes, machine-readable results, and stable pass/violation exit codes.
- PEP 517/621 packaging metadata in `pyproject.toml`, development tool extras, and fresh-wheel install validation.
- Multi-version macOS CI with correctness linting, focused type checks, CodeQL, dependency review, package metadata validation, checksums, and downloadable build artifacts.
- Project roadmap, community code of conduct, release checklist, release-note categories, and dependency-update configuration.
- A source-release Homebrew Tap formula template and maintainer validation guide; no published formula is claimed yet.
- Strict share-safe JSON/HTML preparation with an embedded safety manifest and additive key, header, and object/URL path rules.
- Value-pattern redaction for JWT, Basic/Bearer credentials, private-key PEM blocks, common GitHub/AWS/Stripe keys, and bounded high-entropy candidates.
- Configurable CDP WebSocket frame/message/event limits with strict handshake, fragmentation, control-frame, UTF-8, close, and JSON validation.
- Versioned schema-v2 `.wsdb` SQLite sessions with WAL recording, typed event envelopes, EventBus delivery, artifact provenance, metadata, session-scoped entities/relations, findings, and migration contracts.
- Hash-addressed HAR/JSONL artifact ingestion with per-event provenance, duplicate detection, UTC timestamp normalization, and atomic rollback when a source changes or fails.
- Non-mutating session integrity verification and copy-forward schema migration that never rewrites its source.
- `session record`, `import`, `ingest`, `migrate`, `verify`, `show`, `timeline`, `entities`, `explain`, `what`, `why`, `who`, `mark`, and `report` workflows.
- Bounded data-only rule packs, built-in deterministic rules, idempotent session analysis, and evidence-chain explanation without executable plugin code.
- Statistical `.wsbaseline` build/compare/check workflows using robust distributions, capability/rule compatibility, stable sets, and explicit unknown/incompatible outcomes.
- Human-reviewed Network Manifest proposals and fail-closed policy checks for domains, protocols, ports, TLS, resolvers, routes, interfaces, tunnels, trackers, rules, findings, budgets, and local baselines.
- Session tagging, deterministic verified merge with clock offsets, evidence-aware dry-run pruning, share-safe/private JSON/JSONL/HTML exports, and fixed-contract support bundles.
- Deterministic release benchmark coverage for session writes, JSONL import, HAR analysis, and peak memory reporting.
- Deterministic process → connection → endpoint and browser request → domain/IP/TLS correlation with evidence and confidence.
- Self-contained offline session reports with Overview, Timeline, Entities, Relations, Findings, and Raw views.
- An eighth TUI Timeline tab for socket lifecycle, route/DNS/VPN/proxy state changes, filtering, details, and user markers.
- Structured native-command diagnostics and capability matrix, plus opt-in parser metadata for macOS output variants.
- Dependency-free offline Mozilla Public Suffix List snapshot with exact, wildcard, exception, private-domain, IDN, and IP semantics.
- Versioned, structured tracker signatures with label-boundary/path matching and auditable classification evidence.
- Additive facts, score factors, confidence, limitations, and structured finding evidence while preserving existing score and tracker fields.
- Secure artifact APIs for owner-only streaming, append, atomic writes, external-writer verification, and failed-output cleanup.
- Real macOS parser fixtures plus focused session, artifact, privacy, PSL, CDP, TUI Timeline, budget, and CLI tests.

### Changed

- Reworked the README as a product landing page around Record → Correlate → Explain, concrete user workflows, real installation URLs, and explicit visibility limits.
- Response-body truncation now uses UTF-8 byte counts or decoded base64 sizes and records the original size plus truncation state.
- `record` selects durable session storage automatically for a `.wsdb` output while retaining JSONL compatibility.
- Legacy lifecycle event names normalize into the canonical dotted taxonomy while their source provenance remains available.
- The dashboard reports sensor capabilities and command/parser health instead of presenting unavailable or malformed data as empty state.
- HTML, JSON, CSV, HAR, PCAP, JSONL, snapshot, and session outputs now use the central private-artifact boundary.
- Share-safe handling is consistent across report, export, compare, web, and session-report derivatives; raw website event streams remain explicitly private.
- Packaging now uses `pyproject.toml` as the canonical PEP 621 configuration while retaining a minimal `setup.py` compatibility shim.
- Row limits now apply consistently to human-readable and JSON connection/route output, with connection totals and truncation metadata preserved.
- Source distributions are normalized to deterministic, host-independent ownership, timestamps, modes, ordering, and gzip/tar metadata before release.

### Security

- New capture artifacts are private from their first byte (`0600`), refuse final-component symlinks and non-regular destinations, and use atomic same-directory replacement for one-shot output.
- SQLite main, WAL, shared-memory, and journal files are permission-verified; sessions open read-only for inspection commands.
- Share-safe redaction recognizes credential/token patterns, identifiers, hardware and network addresses, local paths, custom field/header/path globs, and emits an explicit review manifest.
- CDP rejects invalid WebSocket upgrades, RSV/opcode/control/fragmentation/UTF-8/JSON sequences and bounds frame, message, event, and response-body memory use.
- Session opening validates SQLite application identity and supported schema before mutation, uses no-follow/inode checks, disables trusted schema processing, bounds hostile HAR/JSONL/SQLite/evidence input, and safely handles WAL-aware migration snapshots.
- Share-safe URL handling also removes IP hostnames, user/device identifiers, and Unix, Windows, UNC, and home-relative paths.
- Support bundles enforce fixed payload sets, per-entry hashes, sharing-policy consistency, regular safe ZIP entries, compression/aggregate limits, private permissions, and verification before publication.

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
