# Quality report

Last run: 2026-11-11 · Version 0.2.0 · Windows 11, Node.js 26.13, npm 11.20

Only checks that were actually executed are reported as passed. All runs below were local.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Lint | `npm run lint` | Passed, 0 findings |
| Type check | `npm run typecheck` | Passed (strict, `noUncheckedIndexedAccess`) |
| Unit, integration and pipeline tests | `npm test` | Passed, 272 tests in 10 files |
| Data pipeline against live sources | `npm run data:build` | 5/5 datasets fresh (KEV 1,779; NVD recent 4,688; NVD KEV 1,779; ATT&CK v20.1, 706 techniques; CERT-FR 80) |
| Production build | `npm run build` | Passed (main bundle 510 kB, 158 kB gzip) |
| Repository identity check | `npm run check:identity` | Passed, 77 files plus build output |
| Dependency audit | `npm run audit:deps` | 0 known vulnerabilities |
| End-to-end tests | `npm run test:e2e` | Passed, 32 tests (16 scenarios × desktop and mobile Chromium), fixture data |

Manual review in a browser with the live datasets: overview, Vulnerability Center, CVE detail and
ATT&CK matrix in French; no console errors.

## Cross-check against real data

- CVSS 3.x base scores recomputed locally for 5,850 NVD records: 0 mismatch with the published
  score; 0 severity mismatch.
- CVSS 4.0 vectors: all decoded after accepting multi-letter supplemental values (e.g. `U:Amber`).
- IOC extraction on 2 MB of real CVE text: ran in 66 ms. The first run showed false positives
  (code identifiers as domains, `::` as IPv6); fixed with the IANA TLD list and stricter IPv6
  boundaries, then covered by tests.

## What the tests cover

- **Pipeline normalisation (44 tests):** dates, KEV, NVD, ATT&CK and CERT-FR normalisers on valid,
  duplicated, revoked, malformed and hostile input (non-http URLs, markup in RSS, foreign hosts,
  null entries); outputs validated against the published schemas.
- **Dataset loader (30 tests):** manifest and dataset validation, missing files, network
  failures, malformed JSON, HTML error pages, path traversal in file names, `javascript:` URLs,
  oversized fields, invalid dates, request deduplication, no caching of failures, same-origin
  requests only, freshness levels.
- **CVSS (31 tests):** base scores against reference values, invalid and oversized vectors, 4.0
  decoding, severity scale.
- **IOC (67 tests):** refang/defang, IPv4/IPv6 parsing and classification, single-value
  validation, extraction from mixed text, false-positive guards, markup, credentials in URLs,
  truncation, pathological input performance.
- **Prioritisation, export, formatting, ATT&CK index (27 tests):** priority factors, unscored
  CVEs, search and sort, CSV quoting and formula neutralisation, UTC dates, relationships.
- **Pages (22 tests, fixture data):** figures from datasets, stale and failed datasets, severity
  filter, KEV entries without NVD record, CSV export, CVE detail and priority explanation, unscored
  CVE, watchlist persistence, malformed CVE id, missing and corrupted datasets, ATT&CK matrix and
  relationships, IOC extraction without network access, oversized and hostile file names, notes
  with delete confirmation. Hostile text in datasets is checked to render as text.
- **Foundation (41 tests):** i18n parity, preferences, storage, shell, settings.
- **End-to-end:** no console errors and no third-party requests, navigation, persistence, data
  export, dataset figures with provenance, no-dataset state, no horizontal overflow on eight
  routes at desktop and mobile width, markup in the URL rendered as text.

## Explicit security test status

| Case | Status |
| --- | --- |
| XSS attempts (routes, dataset text, file names, pasted text) | Tested |
| Malformed JSON, corrupted cached data, unexpected structures | Tested |
| Oversized files and fields | Tested |
| Invalid timestamps | Tested |
| Malicious file names | Tested |
| Storage failures | Tested |
| Network failures, missing datasets | Tested |

## Not measured

- Lighthouse performance and accessibility scores.
- Automated accessibility rules (axe or equivalent).
- Firefox and WebKit.
- GitHub Actions workflows: written, never executed on GitHub.

## Observations

- With four parallel browsers, the first page load occasionally exceeded the default 5 s
  assertion timeout. The assertion timeout is now 10 s and the wait for stored preferences is
  capped at 2.5 s. Of the next five full runs, four passed 32/32; one, which ran unusually slowly
  (51 s instead of about 11 s, machine under load), had 4 assertion timeouts. This intermittent
  failure is not resolved; CI retries a failed test once.
