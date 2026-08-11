# Contributing to WireScope

Thanks for helping improve local-first network diagnostics.

## Principles

1. Be honest about visibility boundaries. Never imply that encrypted traffic was decrypted when it was not.
2. Keep collection local by default and make transmission explicit.
3. Redact secrets by default. New event sources need privacy tests.
4. Prefer native APIs and the Python standard library for the core CLI.
5. Every platform-specific parser should have fixture-based unit tests.
6. Privileged helpers must be narrow, auditable, and optional.

## Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
make test
```

## Pull requests

- Keep changes focused and explain the user-visible outcome.
- Add or update tests.
- Update `README.md` and `CHANGELOG.md` for user-facing features.
- Do not commit recordings, PCAPs, HAR files, tokens, cookies, or private network snapshots.
- Test on a real terminal when changing curses code.
- Preserve JSONL backward compatibility or increment `schema_version`.

## Adding a platform adapter

Platform adapters should produce the same normalized concepts:

- processes and socket ownership;
- interfaces, counters, routes, resolvers, proxies, and VPN state;
- effective route lookup;
- optional Wi‑Fi/Bluetooth/native quality capabilities.

Keep command execution argument-based; never build privileged shell command strings from user input.

