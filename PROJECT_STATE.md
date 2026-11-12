# Project state

Last updated: 2026-11-12 · Version 1.0.0

## Summary

Milestones 0 to 5 are complete. Every module works on real, traceable public data or on the
user's own files, the application is installable and usable offline, and the quality checks listed
in [QUALITY_REPORT.md](QUALITY_REPORT.md) pass, in CI on Chromium, Firefox and WebKit. Version
1.0.0 is deployed at https://intheshadowgp.github.io/BLACKWATCH/.

## Milestones

| Milestone | State |
| --- | --- |
| 0 — Foundation | Complete, deployed |
| 1 — Intelligence | Complete with the partial areas listed below, deployed |
| 2 — Security Toolbox | Complete, deployed |
| 3 — SOC Workbench | Complete, deployed |
| 4 — Cyber Lab | Complete, deployed |
| 5 — Production hardening | Complete, deployed |

## Implemented and tested

- **Foundation:** shell, routing, FR/EN, themes, density, reduced motion, IndexedDB storage,
  settings, local data export and deletion, error boundary.
- **Data pipeline** (`scripts/data`): CISA KEV, NVD (CVEs of the last 7 days and records of KEV
  entries), MITRE ATT&CK Enterprise, CERT-FR advisories and alerts. Validation against shared Zod
  schemas, normalisation, deduplication, provenance manifest with licence, notice, retrieval time
  and SHA-256, last-valid-copy fallback marked "stale". Derived Overview summary with the checksums
  of its sources.
- **Overview:** KEV and CVE figures, severity distribution, monthly KEV additions, latest KEV
  entries, recent critical CVEs, latest CERT-FR publications, dataset freshness table.
- **Vulnerability Center:** recent CVEs, KEV catalog and watchlist tabs; search, filters, sorting,
  pagination; CVE page with CVSS 3.x (recomputed and compared) and 4.0 (decoded), CWE, products,
  references, KEV details, explained P1–P5 priority; CSV export; print stylesheet.
- **MITRE ATT&CK Explorer:** matrix with platform filter, groups, software, campaigns,
  mitigations; detail pages with relationships in both directions; dataset version shown.
- **Threat Intelligence:** merged CERT-FR / KEV feed, IOC explorer, threat actors, campaign
  timeline, investigation notes.
- **Security Toolbox:** 20 tools covering the 23 required utilities.
- **SOC Workbench:** local multi-format log import in a worker, 12 detection rules, Sigma subset,
  events, timeline, entities, saved investigations, Markdown/CSV/JSON exports.
- **Cyber Lab:** ten synthetic scenarios with evidence, graded steps, cited guidance, versioned
  local progress and Markdown reports.
- **Production hardening:** axe WCAG A/AA audit in both themes and keyboard focus fixes;
  installable web application with an offline shell, verified offline dataset copies and a
  user-triggered update; Overview summary (6.4 MB of JSON to 48 kB on first visit); reserved chart
  heights (desktop CLS 0.046); workflow actions pinned to commit SHAs; Firefox and WebKit projects
  in CI; README screenshots.

## Partially implemented

- Vulnerability Center: no OSV or GitHub Advisory Database data; CVEs older than 7 days are only
  available when they are in KEV; CVSS 4.0 scores are not recomputed; PDF export relies on the
  browser's print dialog.
- Threat Intelligence: no indicator reputation feed (abuse.ch excluded, see DECISIONS.md D-015),
  no indicator relationship graph, no geolocation.

## Not verified

- Firefox and WebKit locally (they cannot be started on the development machine); they pass in CI.
- The service worker outside Chromium, and the axe audit on Firefox (see QUALITY_REPORT.md).

## Deployment

- `deploy.yml` builds the datasets, verifies and publishes on push and daily; `ci.yml` runs lint,
  types, unit and end-to-end tests on fixtures. Both succeeded on GitHub for 1.0.0 (commit 8f86b3f).
- Remaining release step, the owner's decision: tag `v1.0.0` and publish a GitHub release.

## Known limitations

- Main JavaScript bundle 593 kB (184 kB gzip), needed for the first render.
- Brief dark background at start-up for light-theme users.
- Offline, only datasets opened while online are available.

## Security considerations

- Meta-delivered CSP: no framing protection, no HTTP security headers (README).
- All sites of the GitHub account share the web origin and can read this application's browser
  storage (README).
- Dataset text is third-party and validated, length-limited and rendered as text.
- CSV exports neutralise spreadsheet formulas; reports are Markdown with fenced excerpts.
- IndexedDB content is unencrypted at rest.
