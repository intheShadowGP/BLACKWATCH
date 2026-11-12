# Tasks

## Milestone 0 — Foundation

- [x] Project initialisation (Vite, React, strict TypeScript, Tailwind CSS)
- [x] Design system tokens, dark and light themes, density, reduced motion
- [x] Hash routing, lazy views, not-found view, error boundary
- [x] French / English internationalisation
- [x] Responsive shell with accessible mobile navigation
- [x] IndexedDB schema and storage operations
- [x] Settings: appearance, local data export and deletion, version, privacy
- [x] Unit, integration and end-to-end test infrastructure
- [x] CI and deployment workflows
- [x] Repository identity check
- [x] Configure the Git identity for this repository and create the first commit
- [ ] Create the public GitHub repository and push (owner authorisation required)
- [ ] Enable GitHub Pages (source: GitHub Actions) and verify the first deployment
- [ ] Confirm CI passes on GitHub-hosted runners

## Milestone 1 — Intelligence

- [x] Verify licence, redistribution terms, attribution and rate limits (CISA KEV, NVD, MITRE ATT&CK, CERT-FR, abuse.ch)
- [x] Data pipeline: fetch, validate, normalise, deduplicate, provenance, last-valid-copy fallback
- [x] Daily dataset refresh in the deploy workflow
- [x] Dataset manifest and freshness indicators in the interface
- [x] Overview dashboard figures and charts from published datasets
- [x] Vulnerability Center: search, detail, CVSS 3.x / 4.0, KEV status, prioritisation, watchlist, CSV export, print
- [x] IOC Explorer: validation, extraction, normalisation, classification, export
- [x] Threat feed, threat actor reference, campaign timeline, notes
- [x] MITRE ATT&CK Explorer from the versioned STIX dataset
- [x] Favorites management in settings
- [ ] OSV and GitHub Advisory Database (licence check, pipeline, UI)
- [ ] Wider CVE coverage than the 7-day window (incremental NVD sync or on-demand shards)
- [ ] Small summary dataset so the overview does not download full datasets
- [ ] Dedicated PDF report generation (currently the browser print dialog)
- [ ] Indicator relationship view
- [ ] First deployment and check of the daily refresh on GitHub

## Milestone 2 — Security Toolbox

- [x] The 23 utilities listed in the product specification, each with stated limitations
- [x] Web Workers for file analysis and the regular expression tester
- [ ] Optional: maintained password estimator (zxcvbn) loaded on demand
- [ ] Optional: CVSS 4.0 score computation

## Milestone 3 — SOC Workbench

- [x] Import with size and event limits (measured); format detection with manual override
- [x] Parsers: JSON, CSV, syslog, Linux authentication, SSH, Apache, Nginx, Windows Event XML
- [x] Normalised event model, filtering, search, timeline, entities
- [x] Detection rules (12) and a documented Sigma subset
- [x] Investigations (explicit save), notes, flags, Markdown/CSV/JSON exports
- [ ] Binary EVTX parser (currently: export to XML first)
- [ ] Configurable rule parameters
- [ ] Saving investigations above 100,000 events (chunked storage)

## Milestone 4 — Cyber Lab

- [x] Scenario engine: evidence, tasks, decisions, scoring, final report
- [x] Ten synthetic scenarios with cited guidance
- [x] Local progress storage, versioned
- [ ] Optional: more scenarios and difficulty levels

## Milestone 5 — Production hardening

- [x] PWA: manifest, icons, service worker, offline shell, update notification, cache management
- [x] Bundle analysis (vendor chunk splitting evaluated and not applied, see QUALITY_REPORT.md)
- [x] Overview summary dataset
- [x] Lighthouse performance and accessibility measurements (local build)
- [x] Automated accessibility checks in end-to-end tests
- [x] Firefox and WebKit end-to-end projects (CI; not executed locally)
- [x] Pin GitHub Actions to commit SHAs
- [x] Screenshots in the README

## Release 1.0

- [x] Documentation and quality report updated, version 1.0.0
- [ ] Push a release branch and open a pull request; confirm CI (Firefox and WebKit included)
- [ ] Merge into `main` and confirm the deployment
- [ ] Tag v1.0.0 and publish the GitHub release

## After 1.0

- [ ] Remove the start-up theme flash for light-theme users
- [ ] Remove the `minimatch` override when upstream ranges allow it
- [ ] Characterise or rule out the local end-to-end chunk stall
- [ ] Optional: OSV and GitHub Advisory data, more Lab scenarios
