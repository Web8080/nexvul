# Vendored schemas (test-only)

| File | Source | Pinned commit | SHA-256 |
|------|--------|---------------|---------|
| `sarif-schema-2.1.0.json` | https://raw.githubusercontent.com/oasis-tcs/sarif-spec/a560296ca8c921f3bdb8d4a8db57ab83dae968a7/sarif-2.1/schema/sarif-schema-2.1.0.json (OASIS TC repository `oasis-tcs/sarif-spec`, path `sarif-2.1/schema/sarif-schema-2.1.0.json`; schema `id` is the OASIS errata01 URI) | `a560296ca8c921f3bdb8d4a8db57ab83dae968a7` (latest commit touching the file, 2024-05-02) | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |

Fetched once on 2026-10-16 (the `main` copy and the pinned-commit copy had the same SHA-256).
Tests read the local copy only; no test needs network access. `tests/unit/test_reporting_sarif.py`
checks the SHA-256 above so a silent edit fails the suite. Licence: OASIS IPR policy (the schema
is a normative OASIS work product, redistributed unmodified).
