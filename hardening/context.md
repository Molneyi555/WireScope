# Hardening analysis context

- Analysis ID: `hardening_20260811_private_artifacts`
- Source root: `/Users/mihail/Documents/ChatGPT/WireScope`
- Source revision: `03af0533fc3b8c20241618460ef566c3b6f2088c`
- Working tree at inspection: clean
- Evidence collection SHA-256: `8dfe9481e64aaa64256036dea008fd07a9ce4f202fdafc15ebad52e866a0c38b`
- Test baseline: `python3 -m unittest discover -s tests -v` — 21 passed

## Evidence inventory

| ID | Title | Source | What it establishes |
| --- | --- | --- | --- |
| `E001` | Sensitive local artifact threat model | `SECURITY.md` | Recordings may contain credentials, browsing activity, process data, and packet captures. |
| `E002` | Dispersed artifact creation | `wirescope/record.py`, `wirescope/cdp.py`, `wirescope/capture.py`, `wirescope/proxy.py`, `wirescope/report.py`, `wirescope/tui.py` | Multiple components independently create output files using ordinary `Path.open` or `Path.write_text`. |
| `E003` | Explicit raw-data modes | `wirescope/proxy.py`, `wirescope/cdp.py` | Opt-in modes can persist HTTP bodies and unredacted request metadata, increasing the consequence of permissive file modes. |

The repository itself is the evidence collection. The digest above is the SHA-256 of the concatenated `shasum -a 256` inventory for `SECURITY.md` and the inspected writer modules.
