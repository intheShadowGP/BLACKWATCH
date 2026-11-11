# Quality report

Last run: 2026-11-11 · Version 0.4.0 · Windows 11, Node.js 26.13, npm 11.20

Only checks that were actually executed are reported as passed. All runs below were local.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Lint | `npm run lint` | Passed, 0 findings |
| Type check | `npm run typecheck` | Passed (strict, `noUncheckedIndexedAccess`) |
| Unit, integration and pipeline tests | `npm test` | Passed, 525 tests in 20 files |
| Data pipeline against live sources | `npm run data:build` | 5/5 datasets fresh (KEV 1,779; NVD recent 4,694; NVD KEV 1,779; ATT&CK v20.1, 706 techniques; CERT-FR 80) |
| Production build | `npm run build` | Passed (main bundle 551 kB, 174 kB gzip; the increase is the toolbox translations, which load with the shell) |
| Repository identity check | `npm run check:identity` | Passed, 133 files plus build output |
| Dependency audit | `npm run audit:deps` | 0 known vulnerabilities |
| End-to-end tests | `npm run test:e2e` | 54 tests (27 scenarios × desktop and mobile Chromium), fixture data: three consecutive full runs passed 54/54 |

Manual review in a browser with the live datasets: overview, Vulnerability Center, CVE detail and
ATT&CK matrix in French; no console errors. Regex tester in the browser: the pattern `^(a+)+# Quality report

Last run: 2026-11-11 · Version 0.3.0 · Windows 11, Node.js 26.13, npm 11.20

Only checks that were actually executed are reported as passed. All runs below were local.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Lint | `npm run lint` | Passed, 0 findings |
| Type check | `npm run typecheck` | Passed (strict, `noUncheckedIndexedAccess`) |
| Unit, integration and pipeline tests | `npm test` | Passed, 429 tests in 15 files |
| Data pipeline against live sources | `npm run data:build` | 5/5 datasets fresh (KEV 1,779; NVD recent 4,694; NVD KEV 1,779; ATT&CK v20.1, 706 techniques; CERT-FR 80) |
| Production build | `npm run build` | Passed (main bundle 551 kB, 174 kB gzip; the increase is the toolbox translations, which load with the shell) |
| Repository identity check | `npm run check:identity` | Passed, 111 files plus build output |
| Dependency audit | `npm run audit:deps` | 0 known vulnerabilities |
| End-to-end tests | `npm run test:e2e` | 44 tests (22 scenarios × desktop and mobile Chromium), fixture data: 4 of 5 consecutive full runs passed 44/44, one had 1 failure (see Observations) |

Manual review in a browser with the live datasets: overview, Vulnerability Center, CVE detail and

on 40 "a" followed by "!" was stopped after 2 seconds and reported, with the page still usable.

## Cross-check against real data

- SOC Workbench limits measured on the production build (DECISIONS.md D-031): 97 MB / 560,000 lines
  analysed in 3.1 s (capped at 500,000 events), search over 500,000 events in under 0.1 s; saving
  100,000 events 0.4 s, Settings export of 105 MB 0.5 s, deletion 0.1 s.

- File hashing on the production build: a 496 MB random file was hashed with all five algorithms
  in a worker in 9.3 s (Chromium, development machine), matching the SHA-256 computed by Node.
  This is the basis for the 512 MB limit.

- CVSS 3.x base scores recomputed locally for 5,686 NVD records (latest datasets): 0 mismatch
  with the published score.
- CVSS 4.0 vectors: 1,470 of 1,470 decoded. A first run failed on 28 vectors with multi-letter
  supplemental values (e.g. `U:Amber`); the parser was fixed and the check re-run.
- 407 NVD records have more than 12 references. The pipeline now keeps remediation-tagged
  references first and records the total, so the CVE page says "12 of N" instead of wrongly
  stating that no remediation reference exists.
- IOC extraction on 2 MB of real CVE text: ran in 66 ms. The first run showed false positives
  (code identifiers as domains, `::` as IPv6); fixed with the IANA TLD list and stricter IPv6
  boundaries, then covered by tests.

## What the tests cover

- **SOC Workbench (96 unit tests):** format detection, binary recognition, UTF-16 and BOM
  decoding; ISO timestamps with any fraction and offset, impossible dates, year inference across
  December/January, configured offsets (also run with TZ=America/New_York); SSH attempt counting
  with PAM duplicates and "message repeated"; sudo, su and account changes; IPv6 sources; web
  access lines including malformed scanner requests; Apache and Nginx error logs; NDJSON with
  journald fields, malformed lines, prototype keys; CSV with quoted multi-line fields and ragged
  rows; Windows XML with and without a root, entity declarations refused; each detection rule
  with a positive case, one below the threshold and one just outside the window; web patterns with
  ordinary requests that must not match; Sigma subset features, unsupported constructs, not
  applicable cases, adversarial wildcards; report fencing and escaping; CSV formula
  neutralisation; investigation save, load, size limit and corrupted records.
- **SOC end-to-end (production build):** import of four files with no request other than the
  application's own scripts; findings, binary file guidance; drill-down from a finding to its
  events; import kept across navigation; changing the time zone re-dates inferred timestamps;
  Sigma evaluation and rejection; Markdown report escaping and fencing; save, reload and reopen.

- **Security Toolbox (140 tests):** hashes against `node:crypto` on empty and random inputs around
  block boundaries, MD5 against the RFC 1321 vectors and in uneven chunks; Base64 and hex
  round-trips against Node, invalid input, non-UTF-8 output shown as hex; entropy bounds; strict
  JSON parser error positions, duplicate keys, unsafe integers, prototype keys, 100,000-level
  nesting; JWT decoding with alg none, expiry and JWE; IPv4 and CIDR including /0, /31, /32 and
  255.255.255.255; IPv6 compression with the RFC 5952 examples; URL findings; header analysis;
  password patterns (eight well-known weak passwords never rated above weak); YARA tokenisation
  with braces and comment markers inside strings; Sigma parsing, duplicate keys and alias
  expansion; file signature detection; registry coverage of the 23 specified utilities; every tool
  page renders with its limits; inputs stay out of the URL and browser storage.
- **Toolbox end-to-end (production build):** catastrophic regex stopped and the page still usable;
  file hashing in a worker under the CSP, checked against Node digests; magic-byte detection and
  extension mismatch; IANA port search; Sigma with the lazily loaded YAML parser; all 20 tools open
  without console errors or horizontal overflow on desktop and mobile.

- **Pipeline fallback (6 tests):** last valid copy accepted; checksum mismatch, schema-invalid
  copy, "missing" entry, invalid manifest and absent copy rejected; fall-through between sources.
- **Pipeline normalisation (45 tests):** dates, KEV, NVD, ATT&CK and CERT-FR normalisers on valid,
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
- **Foundation (42 tests):** i18n parity, preferences, storage, shell, settings, and slow storage:
  stored preferences are never overwritten by defaults when IndexedDB answers after the timeout.
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

- **End-to-end workers.** With one worker the toolbox suite ran three times without the stall;
  with four workers the first batch of desktop tests stalled in one run. The suite now runs with
  two workers locally and in CI (DECISIONS.md D-026).

- **Intermittent end-to-end failure, local only.** In roughly one full run out of five to ten,
  2–4 of the first tests time out: the shell is rendered but the main region stays on the
  lazy-route fallback ("Loading…"). Findings so far:
  - The Playwright trace shows the requests for the route chunks pending without a response,
    while the HTML, CSS and main bundle loaded in under 35 ms.
  - The failure reproduces with `vite preview` and with a minimal Node static server.
  - With a request-logging server, every request the server received was answered within 10 ms
    (241 received, 241 answered) during a failing run.
  - Warming the built files before the tests did not help.

  - Resource timing captured at failure lists only the main bundle and stylesheet: the route
    chunk requests never completed in the browser.

  The stall therefore lies between the browser and the loopback server on this machine; neither
  the server nor a defect in the route code has been shown to cause it. Not resolved; CI retries
  a failed test once and reports it as flaky.
