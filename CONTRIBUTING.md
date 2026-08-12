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
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make ci
```

For a quick change that needs no development dependencies, `make test` and `make check` use only the standard library.

## Good first contributions

- Add synthetic fixtures for a macOS output variant.
- Improve an error, permission, capability, or visibility-boundary message.
- Add a privacy regression test for a sensitive value pattern.
- Clarify a reproducible troubleshooting workflow in the documentation.
- Turn an unexplained conclusion into evidence plus confidence.

Open an issue before a large architectural change. The [roadmap](ROADMAP.md) describes direction, not permission to build every item at once.

## Pull requests

- Keep changes focused and explain the user-visible outcome.
- Add or update tests.
- Update `README.md` and `CHANGELOG.md` for user-facing features.
- Do not commit recordings, PCAPs, HAR files, tokens, cookies, or private network snapshots.
- Test on a real terminal when changing curses code.
- Preserve JSONL backward compatibility or increment `schema_version`.
- Run `make lint` and `make typecheck` when development extras are installed.
- Follow the [code of conduct](CODE_OF_CONDUCT.md).

## Commit and release hygiene

- Keep generated reports and build directories out of commits.
- Do not bump the version in feature branches unless the change is preparing a release.
- Maintainers follow [docs/RELEASING.md](docs/RELEASING.md) for tagged artifacts.
- Never claim signing, notarization, package-manager availability, or reproducibility that was not verified.

## Adding a platform adapter

Platform adapters should produce the same normalized concepts:

- processes and socket ownership;
- interfaces, counters, routes, resolvers, proxies, and VPN state;
- effective route lookup;
- optional Wi‑Fi/Bluetooth/native quality capabilities.

Keep command execution argument-based; never build privileged shell command strings from user input.
