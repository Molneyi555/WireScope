# Architecture

WireScope uses a layered sensor model organized around **Record → Correlate → Explain**. Collection remains separate from deterministic analysis and presentation so a sensor's privilege or visibility boundary cannot silently become an analyzer claim.

```text
Native macOS commands ─┐                         ┌─> deterministic analysis/budgets
Chrome DevTools ───────┼─> typed event envelope ┼─> SQLite session + entity graph
HTTP/CONNECT proxy ────┤                         └─> live Timeline/EventBus
tcpdump/PCAP ──────────┘                                      │
                                 terminal/TUI/JSON/CSV/HAR/offline HTML
```

## Design constraints

- Raw events are redacted before durable serialization whenever the sensor permits it.
- Direct observations, parser warnings, heuristics, and unavailable evidence remain distinguishable.
- Collection continues to work without a WireScope account or hosted service.
- Privileged operations are narrow and optional; most commands run as the current user.
- JSONL and normalized exports are public compatibility surfaces, not internal implementation details.
- Every durable capture artifact is created private (`0600`), rejects final-component symlinks and non-regular destinations, and is either streamed safely or replaced atomically.

## Native sensor

`macos.py` executes fixed native command arrays described by `CommandSpec` and converts their output into typed models. `lsof` supplies process/socket ownership, `ifconfig` interfaces, `netstat` routes/counters, `scutil` resolvers/proxy state, and `system_profiler` radio metadata. Exit-code policy is explicit per command; timeouts, unavailable tools, rejected exits, parser warnings, and missing fields are retained as structured diagnostics instead of being silently treated as empty data.

Native output changes across OS versions, so pure parser functions are separated from command execution and tested with real-output fixtures. Existing parser return values remain compatible; callers that need provenance can request `ParseResult` metadata. The adapter capability matrix lets the TUI and `doctor` explain which sensors are usable on the current Mac.

## Session core

`session.py` defines a versioned `EventEnvelope`, a synchronous `EventBus`, a deterministic `CorrelationEngine`, and a portable SQLite `SessionStore`. A `.wsdb` file keeps these layers separate:

- raw typed events, source, severity, confidence, correlation ID, and optional entity link;
- stable entities such as processes, connections, IPs, domains, HTTP requests, and TLS observations;
- directional relations with first/last seen timestamps, confidence, and evidence;
- evidence-backed findings, user markers, recorder metadata, and independent schema versions.

System recording correlates socket ownership and endpoints while placing route, DNS, VPN, and proxy changes on the same timeline. JSONL import also recognizes browser request/response events and links requests to domains, remote IPs, and TLS details when those fields were directly observed. Unknown or unsupported event types are preserved rather than discarded.

SQLite uses WAL while recording and checkpoints on close. The main database and sidecars pass through the same private-artifact verification boundary as other recordings. Readers open existing sessions in SQLite read-only mode. Multi-source ingest is hash-addressed and transactional, integrity verification is non-mutating, and schema migration copies through SQLite backup into a private validated destination rather than rewriting its source.

`lifecycle.py` handles session tags, verified multi-session merge, evidence-aware pruning, share-safe/private exports, and support bundles. Mutating operations use explicit transactions and safe defaults: merge never rewrites a source, prune is a preview unless applied, export is share-safe unless made private, and bundles omit the raw database unless explicitly requested.

## Browser sensor

`cdp.py` implements the WebSocket protocol and Chrome DevTools Protocol without third-party dependencies. The transport validates the upgrade, opcodes, control frames, fragmentation, close payloads, UTF-8, and JSON shape, with configurable frame/message/event limits before accepting data. It writes every enabled event to JSONL before analysis. `analyzer.py` correlates request IDs, redirects, responses, body/transfer lengths, failures, timing, lifecycle, WebSocket totals, and final Performance metrics.

Chrome sees decrypted requests inside the selected browser target. This does not provide visibility into unrelated processes.

## Proxy sensor

`proxy.py` is an asyncio forward proxy. Plain HTTP exposes request/response metadata. HTTPS uses CONNECT and remains encrypted. The proxy does not install a root CA or weaken TLS.

## Packet sensor

`capture.py` constrains invocation of native `tcpdump`, parses plaintext DNS, and summarizes PCAPs. PCAP has packet visibility but generally cannot identify the owning process or decrypt TLS.

## Analysis

Normalized requests feed deterministic aggregations, scores, and explainable findings. Registrable domains use a bundled, integrity-checked Mozilla Public Suffix List snapshot, including exact, wildcard, exception, private, IDN, and IP handling without runtime network access. Tracker matching uses a versioned local dataset and boundary-aware host/path rules. A match is still a diagnostic classification rather than proof of harmful behavior, so its rule, dataset version, party basis, confidence, evidence, and limitations remain visible.

`budget.py` evaluates explicit upper and lower bounds against normalized summaries and scores. It has no collection side effects, so the same policy can gate HAR imports and WireScope recordings in CI.

`rules.py` is a deterministic, data-only explanation engine. Versioned rule packs declare bounded predicates, evidence selectors, severity, confidence, limitations, explanation, and remediation. The validator rejects executable hooks and unknown syntax. Findings retain pack/rule versions and evidence references, so `session why` can reconstruct the chain without executing untrusted code.

`baseline.py` builds robust session baselines from medians, p90 values, median absolute deviation, missingness, capability profiles, rule-pack versions, and stable sets. Unknown or incompatible evidence is a first-class result, never a pass. `manifest.py` adds a human-approved Network Manifest policy layer for domains, protocols, routes, resolvers, TLS, tunnels, findings, budgets, and local baselines; generated proposals cannot approve themselves.

## Artifact and sharing boundary

`artifacts.py` is the only low-level path for capture/report outputs. It opens new files with owner-only permissions from the first byte, refuses final symlinks and non-regular files, uses same-directory temporary files plus `fsync` for atomic one-shot writes, verifies externally written files, and cleans failed temporary output.

Default collection redaction removes known secret fields and payloads before serialization. `--share-safe` is a second, non-mutating export policy that additionally strips identifiers, paths, header/query values, recognized credential formats, and bounded high-entropy candidates. Custom key/header/path rules are additive to the strict policy. The resulting manifest documents what remains visible and requires human review; it is a safety control, not a promise that arbitrary captured data can be published without inspection.

## Presentation

The full-screen TUI consumes current adapter state and maintains a bounded live Timeline of socket lifecycles, network-state changes, and user markers. `session_report.py` turns an existing `.wsdb` into a self-contained offline report with Overview, Timeline, Entities, Relations, Findings, and Raw views. Reports contain no remote assets or telemetry.

## Privilege boundary

Most WireScope commands run as the current user. Packet capture, DNS watch, and deep Wi‑Fi diagnostics may require `sudo`. WireScope does not include a persistent privileged daemon.
