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
- [ ] Configure the Git identity for this repository and create the first commit (owner action)
- [ ] Create the public GitHub repository and push (owner authorisation required)
- [ ] Enable GitHub Pages (source: GitHub Actions) and verify the first deployment
- [ ] Confirm CI passes on GitHub-hosted runners

## Milestone 1 — Intelligence

- [ ] Verify licence, redistribution terms, attribution and rate limits for each candidate source
      (NVD, CISA KEV, MITRE ATT&CK STIX, OSV, GitHub Advisory Database, CERT-FR, abuse.ch)
- [ ] Data pipeline workflow: fetch, validate (Zod), normalise, deduplicate, record provenance and
      timestamps, keep the last valid dataset on failure
- [ ] Dataset manifest and freshness indicators in the interface
- [ ] Overview dashboard figures and charts (ECharts) from published datasets
- [ ] Vulnerability Center: search, detail, CVSS 3.1 / 4.0, KEV status, prioritisation, watchlists,
      CSV and PDF export
- [ ] IOC Explorer: validation, extraction, normalisation, classification, export
- [ ] Threat intelligence feed, threat actor reference, notes
- [ ] MITRE ATT&CK Explorer from the versioned STIX dataset
- [ ] Favorites management in settings

## Milestone 2 — Security Toolbox

- [ ] The 23 utilities listed in the product specification, each with stated limitations
- [ ] Web Worker for file hashing and other heavy processing

## Milestone 3 — SOC Workbench

- [ ] Import with size and parsing limits; format detection
- [ ] Parsers: JSON, CSV, syslog, Linux authentication, SSH, Apache, Nginx, Windows Event XML
- [ ] Normalised event model, filtering, search, timeline, correlation
- [ ] Detection rules and a documented Sigma subset
- [ ] Investigations, notes, exportable reports

## Milestone 4 — Cyber Lab

- [ ] Scenario engine: evidence, tasks, decisions, scoring, final report
- [ ] Ten synthetic scenarios
- [ ] Local progress storage

## Milestone 5 — Production hardening

- [ ] PWA: manifest, service worker, offline shell, update notification, cache management
- [ ] Bundle analysis and vendor chunk splitting
- [ ] Lighthouse performance and accessibility measurements
- [ ] Automated accessibility checks in end-to-end tests
- [ ] Firefox and WebKit end-to-end projects
- [ ] Pin GitHub Actions to commit SHAs
- [ ] Remove the `minimatch` override when upstream ranges allow it
- [ ] Remove the start-up theme flash for light-theme users
- [ ] Screenshots in the README
