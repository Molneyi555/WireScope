# Release process

This checklist covers source distributions and pure-Python wheels. It does not imply that PyPI, Homebrew, signed binaries, or a notarized macOS application are currently published.

## 1. Prepare the release

- Work from a clean branch based on `main` with all required CI checks passing.
- Choose a semantic version and update `wirescope.__version__` once.
- Move relevant `Unreleased` entries in `CHANGELOG.md` under the version and release date.
- Confirm user-facing commands and data-format compatibility are documented.
- Run `session verify` against representative schema-v2 sessions and migrate a synthetic schema-v1 fixture by copy.
- Verify share-safe and explicitly private session exports, support bundles, rule packs, baselines, and Network Manifest failure modes.
- Review dependency changes, security-sensitive code, redaction behavior, and generated-artifact permissions.
- Confirm no HAR, PCAP, JSONL, private report, credential, or local network snapshot is tracked.

## 2. Run the release checks

Use a fresh virtual environment:

```bash
python3 -m venv /private/tmp/wirescope-release-venv
. /private/tmp/wirescope-release-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make ci
make benchmark
```

Record the benchmark parameters, elapsed timings, peak RSS, Python/macOS versions, and machine model in the release notes. Benchmark numbers from different machines are not directly comparable; the release gate is that all core paths complete within their documented bounds, not an unqualified performance claim.

Validate that the source version and installed distribution metadata match:

```bash
python -c 'import importlib.metadata, wirescope; assert importlib.metadata.version("wirescope") == wirescope.__version__'
```

The package job must produce exactly one `.tar.gz`, one `.whl`, and passing `twine check` output. Install the wheel in a second empty environment and run:

```bash
wirescope --version
wscope --help
wirescope doctor --json
wirescope session --help
wirescope rules list --json
```

## 3. Create the GitHub release

- Create an annotated tag named `vX.Y.Z` from the reviewed commit.
- Use the immutable `release-candidate-<commit SHA>` artifact produced by the
  required CI package job for that exact commit. The release workflow refuses
  to rebuild distributions because Python sdists are not assumed reproducible.
- Generate SHA-256 checksums for every uploaded artifact.
- Draft release notes from the changelog; clearly separate features, fixes, security/privacy changes, and known limitations.
- Upload the sdist, wheel, and checksum file to the GitHub release.
- Verify downloads and checksums from a clean machine before marking the release final.

Do not describe an artifact as signed, notarized, reproducible, or supported by a package manager unless that property was actually verified for the release.

## 4. Optional distribution channels

- **PyPI:** not automated by the GitHub release workflow. If added later, first configure Trusted Publishing and a protected release environment, then test the exact workflow on TestPyPI before production.
- **Homebrew:** follow [HOMEBREW.md](HOMEBREW.md), replace template placeholders with the tagged sdist URL and checksum, then run install/test/audit from a clean Tap.
- **macOS application:** use a separate checklist for Developer ID signing, hardened runtime, entitlements, notarization, stapling, update integrity, and privileged-helper review.

## 5. Post-release verification

- Confirm the README installation instructions point only to channels that now exist.
- Open a tracking issue for every deferred known problem.
- Announce the release with one reproducible use case and an honest visibility boundary.
- Start the next `Unreleased` section in `CHANGELOG.md`.

Reference: [Python Packaging User Guide — packaging flow](https://packaging.python.org/en/latest/flow/) and [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/).
