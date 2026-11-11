# Project state

Last updated: 2026-11-11 · Version 0.4.0

## Summary

Milestone 0 (foundation) is complete. Milestone 1 (intelligence) is largely implemented and
tested locally on real data: the data pipeline, the overview dashboard, the Vulnerability Center,
the MITRE ATT&CK Explorer and the Threat Intelligence module. Nothing has been pushed or deployed;
the repository has no remote yet.

## Milestones

| Milestone | State |
| --- | --- |
| 0 — Foundation | Complete, tested locally; first deployment pending |
| 1 — Intelligence | Mostly complete (see "Partially implemented"); deployment pending |
| 2 — Security Toolbox | Complete, tested locally |
| 3 — SOC Workbench | Complete, tested locally |
| 4 — Cyber Lab | Not started |
| 5 — Production hardening | Not started |

## Implemented and tested

- **Foundation:** shell, routing, FR/EN, themes, density, reduced motion, IndexedDB storage,
  settings, local data export and deletion, error boundary.
- **Data pipeline** (`scripts/data`): CISA KEV, NVD (CVEs of the last 7 days and records of KEV
  entries), MITRE ATT&CK Enterprise, CERT-FR advisories and alerts. Validation against shared Zod
  schemas, normalisation, deduplication, provenance manifest with licence, notice, retrieval time
  and SHA-256, last-valid-copy fallback marked "stale". Last local run: 5/5 datasets fresh.
- **Overview:** KEV and CVE figures, severity distribution, monthly KEV additions, latest KEV
  entries, recent critical CVEs, latest CERT-FR publications, dataset freshness table.
- **Vulnerability Center:** recent CVEs, KEV catalog and watchlist tabs; search, severity filter,
  sorting, pagination; CVE page with CVSS 3.x (recomputed and compared) and 4.0 (decoded), CWE,
  products, references, KEV details, remediation references, explained P1–P5 priority; CSV export;
  print stylesheet.
- **MITRE ATT&CK Explorer:** matrix with platform filter, groups, software, campaigns,
  mitigations; detail pages with relationships in both directions; dataset version shown.
- **Threat Intelligence:** merged CERT-FR / KEV feed, IOC explorer (paste or file up to 5 MB;
  IPv4, IPv6, domains, URLs, e-mail, MD5/SHA-1/SHA-256/SHA-512; refang/defang; address classes;
  CSV/JSON export), threat actors, campaign timeline, investigation notes.
- **Settings:** favorites (watchlist) management added.

- **Security Toolbox:** 20 tools covering the 23 required utilities (registry test enforces the
  mapping); regex tester in a worker with a 2 s kill switch; file hashing and inspection in a
  worker (MD5, SHA-1, SHA-256, SHA-384, SHA-512, entropy profile, magic-byte detection, hex view);
  IPv4/IPv6/CIDR calculators; IANA port registry search; HTTP header analyzer; password pattern
  checks; TLS reference from RFC 9325; Sigma and YARA structural viewers; shared IOC explorer.

- **SOC Workbench:** multi-file local import in a worker; parsers for JSON/JSON Lines (incl.
  journald), CSV, syslog (RFC 3164, RFC 5424, ISO; auth.log, secure), Apache/Nginx access and error
  logs, Windows Event XML (UTF-8/UTF-16, with or without <Events> root); binary inputs (EVTX, gzip,
  zip, pcap…) recognised with instructions; per-file statistics with unparsed samples; year and
  time-zone settings; 12 detection rules with parameters, ATT&CK mapping and contributing events;
  documented Sigma subset with "not applicable" and "unsupported" outcomes; events table with
  filters and flags, timeline, entities; explicit save of investigations; Markdown report, CSV and
  JSON exports.

## Partially implemented

- Vulnerability Center: no OSV or GitHub Advisory Database data; CVEs older than 7 days are only
  available when they are in KEV; CVSS 4.0 scores are not recomputed; PDF export relies on the
  browser's print dialog for the current page of results.
- Threat Intelligence: no indicator reputation feed (abuse.ch excluded, see DECISIONS.md D-015),
  no indicator relationship graph, no geolocation (by design: no credible source integrated).
- Settings: dataset cache controls wait for offline support.

## Not implemented

Cyber Lab, PWA and offline support.

## Deployment

- `deploy.yml` builds the datasets, verifies and publishes on push and daily. `ci.yml` runs lint,
  types, unit and end-to-end tests on fixtures. Neither has run on GitHub yet.
- Owner actions needed: create the public repository, push, set Pages source to GitHub Actions.

## Known limitations

- Overview downloads about 6.5 MB of JSON before compression on first visit.
- Main JavaScript bundle is about 510 kB (158 kB gzip).
- Brief dark background at start-up for light-theme users.
- End-to-end coverage is Chromium only; Lighthouse not measured.

## Security considerations

- Meta-delivered CSP: no framing protection, no HTTP security headers (README).
- Dataset text is third-party and validated, length-limited and rendered as text.
- CSV exports neutralise spreadsheet formulas.
- URLs embedding credentials are rejected by the IOC extractor so secrets are never exported.
- IndexedDB content is unencrypted at rest.
