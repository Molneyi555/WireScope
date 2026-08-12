# Homebrew preparation

WireScope does not currently claim a published Homebrew formula. This directory contains a maintainer template for a future source-based Tap release.

## Release prerequisites

1. Publish a tagged GitHub release following [RELEASING.md](RELEASING.md).
2. Attach the built sdist named `wirescope-X.Y.Z.tar.gz`.
3. Calculate its SHA-256 checksum:

   ```bash
   shasum -a 256 wirescope-X.Y.Z.tar.gz
   ```

4. Copy `packaging/homebrew/wirescope.rb.template` into `Formula/wirescope.rb` in the Tap repository.
5. Replace `__VERSION__` and `__SHA256__`; do not commit unresolved placeholders.

The current zero-runtime-dependency template installs the package under Homebrew's isolated `libexec` and creates launchers backed by Homebrew Python. It does not fetch Python packages during installation, install a daemon, modify packet-capture permissions, or grant `sudo` access.

## Validate in a Tap

With the formula in a local Tap, run:

```bash
brew install --build-from-source --verbose wirescope
brew test wirescope
brew audit --strict --formula wirescope
wirescope doctor
```

Test on Apple Silicon and Intel before advertising the Tap. Recalculate the checksum from the exact uploaded release artifact; a checksum from a local build or a different archive is not interchangeable.

## Publication order

- Start with a project Tap such as `Molneyi555/homebrew-tap`.
- Publish installation instructions only after the Tap CI passes on a real tag.
- Consider `homebrew/core` only after stable tagged releases, demonstrated usage, and compliance with Homebrew's acceptance rules.
- Add bottles or a cask only when their build/signing provenance is real and documented.

Reference: [Homebrew Formula Cookbook](https://docs.brew.sh/Formula-Cookbook).
