# WireScope

**Terminal-native network observability for macOS — processes, sockets, DNS, VPN, Wi‑Fi, browser requests, TLS, packet captures, diagnostics, and reports.**

WireScope keeps data local, has no runtime dependencies, and redacts secrets by default. Version `0.2.0` combines several independent sensors because no single API can truthfully expose every layer of modern encrypted networking.

## Start in ten seconds

```bash
chmod +x bin/wirescope
./bin/wirescope doctor
./bin/wirescope
```

Running `wirescope` without arguments opens the interactive dashboard. Press `?` for keys and `q` to quit.

Analyze a complete website load with one command:

```bash
./bin/wirescope web https://github.com --open-report
```

This creates a timestamped bundle containing:

```text
wirescope-results/github.com-YYYYMMDD-HHMMSS/
├── report.html      interactive, self-contained report
├── analysis.json    normalized requests, scores, and findings
├── network.jsonl    lossless Chrome DevTools event stream
├── requests.csv     spreadsheet-friendly request table
└── requests.har     portable HTTP Archive export
```

## What WireScope can see

| Sensor | Scope | Decrypted HTTPS | Process owner | Rich timing | Payload |
|---|---|---:|---:|---:|---:|
| Live/system sockets | All local processes | No | Yes | Socket lifecycle | No |
| Chrome DevTools | Selected Chrome tab | Yes | Chrome | Yes | Opt-in |
| HTTP/CONNECT proxy | Configured applications | Plain HTTP only | Sometimes | Duration/TTFB | HTTP opt-in |
| PCAP | Selected interface | No | No | Packet timestamps | Encrypted/raw |
| HAR import | Exported browser session | Yes | Browser only | Usually | HAR-dependent |

TLS, QUIC, encrypted DNS, certificate pinning, VPN routing, and OS privacy controls create real visibility boundaries. WireScope labels those boundaries instead of promising impossible universal decryption.

## Interactive dashboard

```bash
./bin/wirescope
# or
./bin/wirescope live --interval 1
```

Dashboard tabs:

- Overview — connections, protocol totals, traffic-rate history, VPN state, and recent lifecycle events.
- Connections — process/PID, endpoint, state, path, filtering, sorting, details, reverse DNS, and effective routes.
- Processes — socket counts and unique remote targets per process.
- Interfaces — address, MTU, state, byte totals, and current rates when macOS exposes counters.
- DNS — scoped resolvers and system proxy configuration.
- VPN — tunnel interfaces, MTU, addresses, defaults, and warnings.
- Routes — complete IPv4 routing table with tunnel routes highlighted.

Keys:

```text
1–7 / ← → / h l   switch tabs
↑ ↓ / j k          move selection
/                  filter connections
s                  sort by process, destination, state, or PID
x                  show/hide CLOSED sockets
d / Enter          connection details
n                  reverse-DNS selected destination
g                  inspect effective route
p / Space          pause/resume
r                  refresh immediately
e                  export dashboard snapshot
c                  clear filter/event counters
?                  help
q / Esc            quit
```

For scripts and non-interactive terminals:

```bash
./bin/wirescope live --plain
./bin/wirescope connections --remote-only --json
```

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
./bin/wirescope snapshot --radios -o snapshot.json
./bin/wirescope snapshot --radios --quality -o deep-snapshot.json
```

JSONL is append/stream friendly and works with `jq`, DuckDB, ClickHouse, and log pipelines.

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

## Installation

WireScope requires macOS and Python 3.9+. It uses only the Python standard library and native macOS commands.

Run directly:

```bash
git clone <repository-url> wirescope
cd wirescope
./bin/wirescope doctor
```

Editable install:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
wirescope doctor
```

## Privacy model

Default redaction covers:

- authorization, cookies, tokens, passwords, API keys, sessions, and credentials;
- sensitive URL query parameters and URL user information;
- request/response bodies, WebSocket payloads, and event-stream data;
- raw cookie structures and sensitive header text.

`--show-sensitive` is always explicit. Treat recordings made with it as secrets: do not commit, upload, or share them casually.

WireScope has no telemetry and sends no analysis data to a WireScope service. Active probes contact only the targets requested by the user. Website recording naturally contacts the requested website and its dependencies.

## Architecture

```text
wirescope/
├── cli.py          commands and human-readable output
├── tui.py          interactive curses dashboard
├── macos.py        native macOS sensors and parsers
├── diagnostics.py  DNS wire client, TLS, trace, VPN leaks, diagnosis
├── cdp.py          WebSocket and Chrome DevTools recorder
├── analyzer.py     request correlation, scores, findings, exports
├── report.py       self-contained interactive HTML reports
├── proxy.py        asyncio HTTP/CONNECT proxy
├── capture.py      PCAP, DNS watch, and tcpdump parsing
├── quality.py      ping, DNS, TLS, and HTTP probes
├── record.py       connection lifecycle recorder
├── config.py       layered configuration
└── redact.py       secret-safe serialization
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/DATA_FORMAT.md](docs/DATA_FORMAT.md).

## Development

```bash
make test
make check
```

Equivalent commands:

```bash
PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache python3 -m unittest discover -s tests -v
PYTHONPYCACHEPREFIX=/private/tmp/wirescope-pycache python3 -m py_compile wirescope/*.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).

## Roadmap

- Linux eBPF adapter for exact per-process byte/retransmission/DNS events.
- Windows ETW and Windows Filtering Platform adapter.
- Native signed macOS helper with narrowly scoped capture privileges.
- HTTP/3 and QUIC transport diagnostics beyond browser-level visibility.
- SQLite/Parquet sessions and long-running historical dashboards.
- Public-suffix and optional offline ASN/geolocation databases.

## License

Apache License 2.0. WireScope is intended for diagnostics, performance analysis, and authorized security work.
