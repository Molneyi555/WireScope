# Security and privacy

## Reporting a vulnerability

Do not open a public issue containing credentials, private recordings, exploit details, or personal network data. Contact the maintainers privately through the repository security advisory channel.

Include the affected version, operating system, reproduction steps, impact, and a minimal synthetic fixture when possible.

## Threat model

WireScope processes highly sensitive local metadata. URLs, DNS names, process names, headers, bodies, cookies, and PCAPs may reveal credentials or personal activity.

Defenses in the default configuration:

- no WireScope telemetry or cloud upload;
- authorization, cookies, tokens, credentials, bodies, WebSocket payloads, and sensitive query parameters are redacted;
- proxy binds to loopback and refuses remote binds without explicit acknowledgement;
- HTTPS proxy traffic remains opaque CONNECT tunnels;
- body collection is opt-in and size-limited;
- browser recording uses an isolated profile when WireScope launches Chrome;
- system commands receive validated argument arrays rather than shell strings.

## User responsibilities

- Capture only devices and networks you own or are authorized to diagnose.
- Protect recordings as sensitive data.
- Avoid `--show-sensitive` unless necessary.
- Do not run the entire tool as root when only one capture command needs privileges.
- Review HTML/JSON/PCAP files before sharing them.

## Known boundaries

- Redaction is defense-in-depth, not a guarantee that arbitrary application payloads contain no secrets.
- Reverse DNS and tracker classification are heuristic.
- Route-level VPN checks cannot prove external egress without contacting an external endpoint.
- A compromised local administrator can observe or modify the same traffic WireScope sees.

