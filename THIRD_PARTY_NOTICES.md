# Third-party notices

WireScope source code is licensed under the Apache License 2.0, except for
third-party material identified below. The project-level SPDX license
expression remains `Apache-2.0`; that expression does not relicense the
separately identified dataset.

## Mozilla Public Suffix List

WireScope distributes a normalized snapshot of the Mozilla Public Suffix List
for dependency-free, offline registrable-domain classification.

- Component: Public Suffix List
- Upstream source: <https://publicsuffix.org/list/public_suffix_list.dat>
- Snapshot capture date: 2026-08-11
- Bundled source form: `wirescope/data/public_suffix_list.dat`
- Source-form transformation: comments and blank lines were removed, retaining
  one effective UTF-8 rule per line
- Rule count: 8,832
- SHA-256 of the bundled UTF-8 source form:
  `d839a154060dfaf2f42a7b685bfa35e5119e5cf53f8ed34c6a7bcf6d418452a0`
- Runtime behavior: the bundled file is read locally and its digest and rule
  count are verified before use; WireScope never downloads PSL data at runtime
- Component license: Mozilla Public License 2.0 (`MPL-2.0`)
- Full license text: `LICENSES/MPL-2.0.txt`

This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can
obtain one at <https://mozilla.org/MPL/2.0/>.
