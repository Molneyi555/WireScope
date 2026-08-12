# WireScope

[![CI](https://github.com/Molneyi555/WireScope/actions/workflows/test.yml/badge.svg)](https://github.com/Molneyi555/WireScope/actions/workflows/test.yml)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![macOS](https://img.shields.io/badge/platform-macOS-111111?logo=apple)](https://github.com/Molneyi555/WireScope)
[![License: Apache-2.0](https://img.shields.io/github/license/Molneyi555/WireScope)](https://github.com/Molneyi555/WireScope/blob/main/LICENSE)

**Record → Correlate → Explain network activity on your Mac.**

WireScope is a privacy-first network observability toolkit for macOS. It brings process sockets, routes, DNS, VPN, Wi‑Fi, browser requests, TLS, PCAP, diagnostics, and offline reports into one terminal-native workflow.

It is built for evidence, not magic: data stays on the Mac, secrets are redacted by default, and every sensor states what it can and cannot see.

[Quick start](#quick-start) · [Use cases](#what-can-i-do-with-it) · [Visibility](#visibility-boundaries) · [Website analysis](#website-and-browser-analysis) · [Architecture](https://github.com/Molneyi555/WireScope/blob/main/docs/ARCHITECTURE.md) · [Roadmap](https://github.com/Molneyi555/WireScope/blob/main/ROADMAP.md)

> [!IMPORTANT]
> WireScope is alpha software. Review recordings before sharing them, and capture only systems and networks you own or are authorized to diagnose.

## What can I do with it?

| Question | Workflow | Result |
|---|---|---|
| Which process is connecting where? | `wirescope` or `wirescope connections` | Live process, PID, endpoint, state, route, and lifecycle views |
| Is DNS or VPN routing leaking? | `wirescope diagnose` and `wirescope leaks` | Resolver, default-route, tunnel, and evidence-backed warnings |
| Why is a website slow or noisy? | `wirescope web https://example.com` | Offline waterfall, timing, protocol, third-party, cache, and failure report |
| Did a deployment regress network performance? | `wirescope budget page.har ...` | Reproducible pass/fail policy for CI |
| What changed while an app was running? | `wirescope session record ...` | Durable `.wsdb` timeline with processes, connections, endpoints, routes, DNS, VPN, proxy, and markers |
| Is this build behaving unlike normal? | `wirescope baseline check ...` | Robust session regression gate with explicit unknown/incompatible states |
| Did an app contact an unexpected service? | `wirescope manifest check ...` | Human-reviewed policy for domains, protocols, routes, resolvers, TLS, findings, and budgets |
| Which devices does this Mac already know? | `wirescope neighbors` | Existing ARP/NDP entries without active scanning |
| Do I need raw evidence? | `wirescope record`, `browser`, or `capture` | JSONL, HAR, CSV, HTML, or PCAP artifacts, depending on the sensor |

WireScope is useful for application developers, performance engineers, privacy-conscious Mac users, support teams, and authorized incident responders. It does not require an account or a WireScope cloud service.

## Quick start

Requirements: macOS and Python 3.9 or newer. The core has no third-party runtime dependencies.

```bash
git clone https://github.com/Molneyi555/WireScope.git
cd WireScope
./bin/wirescope doctor
./bin/wirescope
```

Running without a subcommand opens the interactive dashboard. Press `?` for keys and `q` to quit.

Install isolated command-line entry points for development:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
wirescope doctor
```

Analyze a complete website load:

```bash
./bin/wirescope web https://github.com --open-report
```

The command creates a timestamped, local bundle:

```text
wirescope-results/github.com-YYYYMMDD-HHMMSS/
├── report.html      interactive, self-contained report
├── analysis.json    normalized requests and evidence-backed findings
├── network.jsonl    redacted Chrome DevTools event stream
├── requests.csv     spreadsheet-friendly request table
└── requests.har     portable HTTP Archive export
```

## How WireScope works

1. **Record** with the sensor that matches the question: macOS sockets, Chrome DevTools, proxy, DNS watcher, or PCAP.
2. **Correlate** related lifecycle events into requests, connections, timing, routes, and aggregates.
3. **Explain** findings with visible evidence and explicit confidence or visibility limits.

Browser analysis correlates request/response lifecycles. Durable `.wsdb` sessions apply the same model to long-lived system observations, preserving typed events, entities, evidence links, and user markers without turning WireScope into a cloud product.

## Visibility boundaries

| Sensor | Scope | Decrypted HTTPS | Process owner | Rich timing | Payload |
|---|---|---:|---:|---:|---:|
| Live/system sockets | Local processes visible to the user | No | Yes | Socket lifecycle | No |
| Chrome DevTools | Selected Chromium tab | Yes, in that tab | Browser process | Yes | Opt-in |
| HTTP/CONNECT proxy | Explicitly configured applications | Plain HTTP only | Sometimes | Duration/TTFB | HTTP opt-in |
| PCAP | Selected interface/filter | No | No | Packet timestamps | Encrypted/raw |
| HAR import | Exported browser session | Browser already decrypted it | Browser only | Usually | HAR-dependent |

Important limits:

- WireScope does not promise universal HTTPS, QUIC, DoH, or certificate-pinned traffic decryption.
- PCAP cannot reliably identify the owning process; system sockets cannot expose HTTP paths inside TLS.
- `neighbors` reads existing ARP/NDP state and is not an active network scanner.
- Tracker classification, reverse DNS, leak detection, and scores are diagnostic signals rather than proof of malicious behavior.
- Packet capture, DNS watch, and deep Wi‑Fi diagnostics may require narrowly scoped `sudo` access.
- macOS privacy controls can hide SSIDs, Bluetooth data, sockets owned by other users, or other metadata.

For a command-focused tour, continue below. Maintainers can also read the [architecture](https://github.com/Molneyi555/WireScope/blob/main/docs/ARCHITECTURE.md), [data formats](https://github.com/Molneyi555/WireScope/blob/main/docs/DATA_FORMAT.md), [security policy](https://github.com/Molneyi555/WireScope/blob/main/SECURITY.md), and [release process](https://github.com/Molneyi555/WireScope/blob/main/docs/RELEASING.md).

## Interactive dashboard

```bash
./bin/wirescope
# or
./bin/wirescope live --interval 1
```

Dashboard tabs:

- Overview — connections, traffic-rate history, recent typed events, and capability/parser/command health.
- Connections — process/PID, endpoint, state, path, filtering, sorting, details, reverse DNS, and effective routes.
- Processes — socket counts and unique remote targets per process.
- Interfaces — address, MTU, state, byte totals, and current rates when macOS exposes counters.
- DNS — scoped resolvers and system proxy configuration.
- VPN — tunnel interfaces, MTU, addresses, defaults, and warnings.
- Routes — complete IPv4 routing table with tunnel routes highlighted.
- Timeline — socket lifecycle, route/DNS/VPN/proxy changes, user markers, filtering, selection, and evidence details.

Keys:

```text
1–8 / ← → / h l   switch tabs
↑ ↓ / j k          move selection
/                  filter connections or timeline
m                  add a timestamped user marker
s                  sort by process, destination, state, or PID
x                  show/hide CLOSED sockets
d / Enter          connection or event details
n                  reverse-DNS selected destination
g                  inspect effective route
p / Space          pause/resume
r                  refresh immediately
e                  export dashboard snapshot
c                  clear filter, counters, and timeline
?                  help
q / Esc            quit
```

For scripts and non-interactive terminals:

```bash
./bin/wirescope live --plain
./bin/wirescope connections --remote-only --json
```

## Correlated sessions and Network Timeline

Record a durable local investigation database:

```bash
./bin/wirescope session record --duration 60 --interval 1 -o investigation.wsdb
# Equivalent shorthand: output suffix selects the session format.
./bin/wirescope record --duration 60 -o investigation.wsdb
```

The recorder creates typed lifecycle events and a deterministic entity graph connecting processes, sockets, endpoints, domains, requests, routes, DNS, VPN, and proxy state when the corresponding evidence is available. Add a marker while reproducing a problem, then inspect or explain it later:

```bash
./bin/wirescope session mark investigation.wsdb "Application became slow"
./bin/wirescope session show investigation.wsdb
./bin/wirescope session timeline investigation.wsdb --reverse
./bin/wirescope session entities investigation.wsdb --type process
./bin/wirescope session explain investigation.wsdb "Chrome"
./bin/wirescope session who investigation.wsdb github.com
./bin/wirescope session report investigation.wsdb -o investigation.html
./bin/wirescope session verify investigation.wsdb
```

Organize recordings with deterministic, idempotent tags:

```bash
./bin/wirescope session tag investigation.wsdb vpn regression
./bin/wirescope session list-tags investigation.wsdb
```

Existing connection JSONL recordings remain useful and can be imported without recapturing traffic:

```bash
./bin/wirescope session import connections.jsonl -o imported.wsdb
```

HAR and JSONL evidence can also be added to an existing schema-v2 session. WireScope hashes each source, records line/request provenance, rejects accidental duplicate ingestion by default, and commits the source atomically:

```bash
./bin/wirescope session ingest investigation.wsdb browser.har
```

The SQLite schema is versioned. `session verify` performs non-mutating schema, SQLite integrity, foreign-key, evidence-reference, and private-permission checks; it exits with `1` when any check fails. Upgrade an older database by copying it into a new current-schema artifact—the source is never rewritten:

```bash
./bin/wirescope session migrate legacy.wsdb -o upgraded.wsdb
```

Merge recordings into a new verified database. Sources remain unchanged; `--source` and per-source clock offsets are repeatable, and the destination must not already exist:

```bash
./bin/wirescope session merge \
  --source system.wsdb \
  --source browser.wsdb \
  --clock-offset browser.wsdb=125.5 \
  -o incident.wsdb
```

Pruning is a dry-run unless `--apply` is explicitly provided. User markers and events referenced by evidence are preserved:

```bash
./bin/wirescope session prune incident.wsdb --before 2026-08-01T00:00:00Z
./bin/wirescope session prune incident.wsdb --before 2026-08-01T00:00:00Z --apply
```

Create reviewable derivatives and verified support bundles. Session exports and bundles are share-safe by default:

```bash
./bin/wirescope session export incident.wsdb -o incident.json
./bin/wirescope session export incident.wsdb -o incident.html
./bin/wirescope session bundle create incident.wsdb -o support-bundle.zip
./bin/wirescope session bundle verify support-bundle.zip
```

Observations, inferred relationships, confidence, and evidence stay distinct so reports can explain what was directly seen and what was derived.

## Automatic diagnosis

Local-only audit:

```bash
./bin/wirescope diagnose
```

Include external ping, DNS, TLS, and HTTP probes:

```bash
./bin/wirescope diagnose --active -o diagnosis.json
```

WireScope checks active interfaces, DNS configuration, competing default routes, VPN routing, public listeners, socket churn, proxies, likely DNS/IPv6 tunnel bypasses, and active quality signals.

Focused commands:

```bash
./bin/wirescope interfaces
./bin/wirescope neighbors
./bin/wirescope routes --default
./bin/wirescope route 1.1.1.1
./bin/wirescope vpn
./bin/wirescope leaks
./bin/wirescope tls github.com
./bin/wirescope trace github.com
./bin/wirescope quality --domain github.com --url https://github.com --verbose
./bin/wirescope speed
```

`speed` uses Apple's native `networkQuality` tool for capacity and responsiveness measurements.
`neighbors` reads the existing ARP/NDP tables to show devices the Mac already knows about; it does not probe or scan other hosts.

## DNS

Configuration and system resolution:

```bash
./bin/wirescope dns
./bin/wirescope dns --resolve github.com
```

Directly compare resolvers without `dig`:

```bash
./bin/wirescope dns-test github.com
./bin/wirescope dns-test github.com --type AAAA --servers 1.1.1.1,8.8.8.8,9.9.9.9
```

Watch plaintext DNS packets (requires capture privileges):

```bash
sudo ./bin/wirescope dns-watch -i any --duration 60 -o dns-events.jsonl
```

DoH and DoT stay encrypted and are not misreported as ordinary port-53 DNS.

## Website and browser analysis

Recommended one-command workflow:

```bash
./bin/wirescope web https://example.com
```

Options:

```bash
./bin/wirescope web https://example.com \
  --duration 30 \
  --idle 4 \
  --capture-bodies \
  --max-body-bytes 2000000
```

The recorder captures Chrome DevTools `Network.*`, `Page.*`, `Security.*`, and `Performance.*` events, including:

- every request, redirect, response, failure, and cache hit;
- initiator data and resource type;
- connection reuse, protocol, IP, port, priority, and service-worker state;
- DNS/connect/TLS/send/TTFB timing when Chrome exposes it;
- TLS protocol, cipher, certificate/security details;
- WebSocket events and frame counts;
- page lifecycle events and final performance metrics;
- optional request and response bodies with size limits.

Advanced attachment to an existing debug-enabled browser:

```bash
./bin/wirescope browser \
  --launch \
  --headless \
  --navigate https://example.com \
  --idle 3 \
  --report \
  -o session.jsonl
```

## Analyze, report, compare, export

Supported inputs: WireScope CDP JSONL, proxy JSONL, connection JSONL, and HAR.

```bash
./bin/wirescope analyze session.jsonl --sort slowest --limit 50
./bin/wirescope analyze page.har --sort largest
./bin/wirescope report session.jsonl -o report.html
./bin/wirescope compare before.har after.har -o comparison.html
./bin/wirescope export session.jsonl --format json -o normalized.json
./bin/wirescope export session.jsonl --format csv -o requests.csv
./bin/wirescope export session.jsonl --format har -o requests.har
```

Automated analysis includes:

- performance, reliability, privacy, security, and overall scores;
- slow and large resources;
- failed and HTTP-error requests;
- duplicate fetches and low cache usage;
- protocol and MIME distributions;
- third-party requests and likely trackers;
- unencrypted HTTP and legacy TLS;
- domain, status, method, resource, transfer, and timing aggregates.

The HTML report has no CDN, analytics, fonts, or external JavaScript. It works offline and includes filters, sortable requests, details, a waterfall, domain charts, findings, WebSocket totals, lifecycle events, and browser metrics.

### Performance budgets for CI

Turn a HAR or WireScope recording into a pass/fail quality gate:

```bash
./bin/wirescope budget page.har \
  --max-requests 80 \
  --max-transfer 2MB \
  --max-page-span 3000 \
  --max-errors 0 \
  --min-score 80
```

The command exits with `0` when every check passes, `1` for budget violations, and `2` for an invalid recording or policy. Use `--json` or `-o budget-result.json` for machine-readable output.

Reusable policies keep limits in source control:

```json
{
  "budgets": {
    "max_requests": 80,
    "max_transfer_bytes": "2MB",
    "max_page_span_ms": 3000,
    "max_errors": 0,
    "max_third_party_percent": 30,
    "max_trackers": 0,
    "min_cache_percent": 20,
    "min_overall_score": 80
  }
}
```

```bash
./bin/wirescope budget page.har --policy wirescope-budget.json
```

Inline flags override matching values from the policy file, which is useful for temporary CI experiments.

### Deterministic rules and “Why?”

Run the built-in data-only explanation rules against a durable session, then follow the exact evidence chain behind a finding:

```bash
./bin/wirescope session analyze investigation.wsdb
./bin/wirescope rules list
./bin/wirescope rules show slow-load-path
./bin/wirescope session why investigation.wsdb slow-load-path
```

Rules keep severity, confidence, evidence, limitations, explanation, and remediation separate. Custom JSON packs are validated before use and cannot contain executable hooks:

```bash
./bin/wirescope rules validate company-rules.json
./bin/wirescope session analyze investigation.wsdb --pack company-rules.json
```

### Statistical baselines and regression gates

Build a noise-tolerant baseline from at least three comparable sessions, compare a candidate interactively, or enforce it in CI:

```bash
./bin/wirescope baseline build run-1.wsdb run-2.wsdb run-3.wsdb -o app.wsbaseline
./bin/wirescope baseline compare app.wsbaseline candidate.wsdb -o comparison.html
./bin/wirescope baseline check app.wsbaseline candidate.wsdb
```

Baselines record capability and rule-pack context plus medians, p90, median absolute deviation, missingness, stable sets, and source fingerprints. Missing or incompatible evidence is reported as unknown/incompatible and uses exit code `2`; it never becomes a false pass.

### Application Network Manifest

Discover observed behavior as an explicitly unapproved proposal:

```bash
./bin/wirescope manifest discover candidate.wsdb -o network-manifest.json --profile ci
```

Review the JSON, narrow the allowed domains/protocols/routes/resolvers/TLS/budgets, change it from proposal to an approved policy, then validate and enforce it:

```bash
./bin/wirescope manifest validate network-manifest.json
./bin/wirescope manifest check network-manifest.json candidate.wsdb --profile ci
./bin/wirescope manifest check network-manifest.json candidate.wsdb \
  --profile ci --format junit -o manifest-result.xml
```

Discovery cannot self-approve. Required evidence that the selected sensor could not observe is `unevaluable` and fails closed; a reviewer may mark specific checks optional when that limitation is intentional.

## Local proxy

```bash
./bin/wirescope proxy -o proxy-events.jsonl

HTTP_PROXY=http://127.0.0.1:8080 \
HTTPS_PROXY=http://127.0.0.1:8080 \
curl https://example.com
```

The proxy records plain HTTP status, headers, TTFB, duration, and byte counts. HTTPS is an opaque CONNECT tunnel: destination and byte totals are visible, payload remains encrypted.

Plain HTTP body capture requires two deliberate flags:

```bash
./bin/wirescope proxy \
  --show-sensitive \
  --capture-http-bodies \
  --max-body-bytes 1000000
```

The proxy binds only to loopback by default and refuses remote exposure unless `--allow-remote` is supplied.

## Packets and PCAP

```bash
sudo ./bin/wirescope capture -i en0 --duration 30 -o traffic.pcap
sudo ./bin/wirescope capture -i en0 --duration 30 -o dns.pcap port 53
./bin/wirescope pcap traffic.pcap
./bin/wirescope pcap traffic.pcap --json
```

The PCAP analyzer summarizes protocols, endpoints, conversations, ports, observed payload bytes, and sample packet lines using native `tcpdump`.

Only capture networks and devices you own or are authorized to diagnose.

## Wi‑Fi and Bluetooth

```bash
./bin/wirescope wifi
./bin/wirescope bluetooth
sudo ./bin/wirescope wifi --deep
```

Deep Wi‑Fi mode includes privileged `wdutil` radio/channel diagnostics when available. macOS may hide SSIDs or Bluetooth controller data based on Location Services, privacy permissions, radio state, and OS version.

## Recording system connections

```bash
./bin/wirescope record --duration 60 --interval 1 -o connections.jsonl
./bin/wirescope record --duration 60 --interval 1 -o investigation.wsdb
./bin/wirescope snapshot --radios -o snapshot.json
./bin/wirescope snapshot --radios --quality -o deep-snapshot.json
```

JSONL is append/stream friendly and works with `jq`, DuckDB, ClickHouse, and log pipelines. `.wsdb` is a private, portable SQLite session with indexed events, entities, relations, findings, metadata, and schema versions.

## Configuration and shell completion

Show effective settings:

```bash
./bin/wirescope config show
```

Create a local project configuration:

```bash
./bin/wirescope config init --local
```

Or create `~/.config/wirescope/config.json`:

```bash
./bin/wirescope config init
```

WireScope checks `.wirescope.json`, then the user config. `WIRESCOPE_CONFIG` can point to another file.

Zsh completion:

```bash
eval "$(./bin/wirescope completion zsh)"
```

Bash and Fish are also supported.

## Distribution status

The supported installation path during alpha is the source checkout shown in [Quick start](#quick-start). The repository now produces standard Python source distributions and wheels, but no PyPI package, Homebrew formula, signed binary, DMG, or notarized app is claimed as published until its release link appears here.

Maintainers preparing a source-based Homebrew Tap can use [the formula template and checklist](https://github.com/Molneyi555/WireScope/blob/main/docs/HOMEBREW.md). End users should not copy the template before its version and checksum placeholders are replaced by a tagged release.

## Privacy model

Default redaction covers:

- authorization, cookies, tokens, passwords, API keys, sessions, and credentials;
- JWT, Basic/Bearer credentials, PEM private keys, common GitHub/AWS/Stripe key formats, and bounded high-entropy candidates even when their field name looks harmless;
- sensitive URL query parameters and URL user information;
- request/response bodies, WebSocket payloads, and event-stream data;
- raw cookie structures and sensitive header text.

Prepare a stricter derivative before attaching a report to a public issue:

```bash
./bin/wirescope report session.jsonl --share-safe --output public-report.html
./bin/wirescope export session.jsonl --format json --share-safe --redact-key 'customer_*'
./bin/wirescope session report investigation.wsdb --share-safe -o public-session.html
./bin/wirescope session export investigation.wsdb -o public-session.json
./bin/wirescope session bundle create investigation.wsdb -o support-bundle.zip
./bin/wirescope session bundle verify support-bundle.zip
```

Share-safe mode additionally removes URL paths and all query/header values, IP, email and hardware addresses, and local file paths. It records a `sharing_safety` manifest in JSON/HTML and keeps domain names plus diagnostic evidence useful for review. `session export` and `session bundle create` use this mode by default; retaining identifiers requires explicit `--private`, while embedding the raw database in a bundle requires `--include-raw-private`. This is defense in depth, not a guarantee: inspect every artifact before publishing it. Repeat `--redact-key`, `--redact-header`, or `--redact-path` for organization-specific fields.

`--show-sensitive` is always explicit. Treat recordings made with it as secrets: do not commit, upload, or share them casually.

WireScope has no telemetry and sends no analysis data to a WireScope service. Active probes contact only the targets requested by the user. Website recording naturally contacts the requested website and its dependencies.

## Architecture

WireScope separates collection from correlation, assessment, and presentation. Native macOS commands, Chrome DevTools, proxy, and packet sensors produce local events; deterministic analyzers turn those events into terminal output, JSON/JSONL, CSV, HAR, and self-contained HTML.

See [docs/ARCHITECTURE.md](https://github.com/Molneyi555/WireScope/blob/main/docs/ARCHITECTURE.md) for trust boundaries and subsystem responsibilities, and [docs/DATA_FORMAT.md](https://github.com/Molneyi555/WireScope/blob/main/docs/DATA_FORMAT.md) for compatibility expectations.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make ci
```

Fast standard-library-only checks remain available without development extras:

```bash
make test
make check
```

See [CONTRIBUTING.md](https://github.com/Molneyi555/WireScope/blob/main/CONTRIBUTING.md), [CODE_OF_CONDUCT.md](https://github.com/Molneyi555/WireScope/blob/main/CODE_OF_CONDUCT.md), [SECURITY.md](https://github.com/Molneyi555/WireScope/blob/main/SECURITY.md), [CHANGELOG.md](https://github.com/Molneyi555/WireScope/blob/main/CHANGELOG.md), and [docs/RELEASING.md](https://github.com/Molneyi555/WireScope/blob/main/docs/RELEASING.md).

## Roadmap

WireScope stays macOS-first and advances its **Record → Correlate → Explain** model. Durable sessions, a unified timeline, initial cross-sensor correlation, deterministic rules, statistical baselines, Network Manifests, lifecycle controls, regression budgets, and verified support bundles are implemented. Deeper correlation, richer graph explanations, visualization, and eventually a narrowly scoped native helper come next. See [ROADMAP.md](https://github.com/Molneyi555/WireScope/blob/main/ROADMAP.md) for priorities and explicit non-goals.

## License

WireScope code is licensed under the [Apache License 2.0](https://github.com/Molneyi555/WireScope/blob/main/LICENSE). The bundled Mozilla Public Suffix List snapshot remains under the [Mozilla Public License 2.0](https://github.com/Molneyi555/WireScope/blob/main/LICENSES/MPL-2.0.txt); its exact source, transformation, snapshot date, digest, and rule count are documented in [THIRD_PARTY_NOTICES.md](https://github.com/Molneyi555/WireScope/blob/main/THIRD_PARTY_NOTICES.md).

WireScope is intended for diagnostics, performance analysis, and authorized security work.
