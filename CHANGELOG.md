# Changelog

## 0.1.3 - 2026-07-18

- Upgrade to the durable persistence contracts in
  `@absolutejs/vulnerabilities@0.5.0`.

## 0.1.2 - 2026-07-18

- Preserve OSV `upstream` identifiers used by Ubuntu records as advisory
  aliases for cross-source correlation.

## 0.1.1 - 2026-07-18

- Preserve provider severity labels such as Ubuntu's severity as normalized
  vendor severity.

## 0.1.0 - 2026-07-18

- Add official OSV `querybatch` ingestion with per-query pagination.
- Normalize OSV advisories into the AbsoluteJS vulnerability contract.
- Preserve affected ranges, aliases, CVSS vectors, and source provenance.
