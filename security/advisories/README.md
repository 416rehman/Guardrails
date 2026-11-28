# Guardrails ADR Security Advisories (`security/advisories/`)

Machine-readable PSIRT advisory archive and generators implementing `docs/design/35-product-security-programme.md` (`SP-26`..`SP-32`) and CRA Article 14 reporting timelines:

- `psirt-policy.toml`: SLA targets (7-day bundled dep patch SLA), CRA Article 14 clocks (`24h` early warning, `72h` initial notification, `14d` / `30d` final report), and PGP key custody policy.
- `advisory-record.schema.json`: Input source record contract (`grdr.advisory.v1`).
- `external-audits.toml`: External audit status tracker under non-blocking precondition `pre-external-audit`.
- `generate_advisories.py`: Emits and validates CSAF 2.0 (`csaf_vex`), OpenVEX 0.2.0, OSV 1.6, CRA reporting deadlines, and TUF yank records.
- `records/`: Published advisories and `index.json`.

Verify locally:

```sh
python -I -B -m unittest security/advisories/test_advisories.py -v
python -I -B security/advisories/generate_advisories.py --check-dir security/advisories/records
```
