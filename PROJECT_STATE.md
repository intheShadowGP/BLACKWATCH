# Project state

Last updated: 2026-11-10 · Version 0.1.0

## Summary

Milestone 0 (foundation) is implemented and verified locally. No functional security module
exists yet. Nothing has been committed, pushed or deployed.

## Milestones

| Milestone | Scope | State |
| --- | --- | --- |
| 0 — Foundation | Shell, routing, i18n, design system, local storage, settings, tests, CI | Implemented and tested locally; first deployment pending |
| 1 — Intelligence | Data pipeline, dashboard figures, threat intelligence, IOC explorer, vulnerabilities, ATT&CK | Not started |
| 2 — Security Toolbox | 23 local utilities | Not started |
| 3 — SOC Workbench | Log import, parsers, detections, timeline, reports | Not started |
| 4 — Cyber Lab | Ten incident response scenarios | Not started |
| 5 — Production hardening | Security and accessibility review, performance, PWA, offline | Not started |

## Implemented and tested

- Application shell: sidebar on large screens, modal drawer on small screens, skip link, focus
  moved to the main region on navigation, document title per view, error boundary per view.
- Routing: hash routes for the overview, seven module routes, settings and a not-found view;
  views are lazily loaded.
- Internationalisation: English and French, browser-language detection, runtime switch from the
  header and from settings, `lang` attribute kept in sync.
- Design system: dark (default) and light themes through CSS custom properties, two densities,
  reduced-motion handling (system, forced, off), visible focus styles.
- Local storage: Dexie database with six stores, Zod-validated preferences, degraded in-memory
  mode with a visible warning when IndexedDB is unavailable.
- Settings and privacy: appearance preferences, per-store record counts, JSON export, full
  deletion behind a confirmation dialog, version information, privacy statement.
- Overview: module status list driven by the module registry, local storage status, explicit
  "no dataset published" state.
- Tooling: ESLint (including bans on `eval` and raw HTML injection), strict TypeScript, Vitest,
  Playwright, repository identity check, CI and deployment workflows.

## Partially implemented

- **Overview dashboard (Module 1).** Structure only. CVE, KEV, advisory and freshness panels
  depend on the Milestone 1 data pipeline.
- **Settings (Module 8).** Favorites management and cache management are not implemented; the
  corresponding stores exist but nothing writes to them yet.

## Not implemented

Threat Intelligence, Vulnerability Center, SOC Workbench, MITRE ATT&CK Explorer, Security Toolbox,
Cyber Lab, static data pipeline, PWA and offline support, CSV/PDF exports, Web Workers.

## Deployment

- Workflows `ci.yml` and `deploy.yml` are written but have never run: the repository has no
  remote and no commit yet.
- GitHub Pages must be switched to the "GitHub Actions" source after the repository is created.

## Known limitations

- Brief dark background at start-up for light-theme users (see DECISIONS.md, D-006).
- Main JavaScript bundle is about 451 kB (142 kB gzip); vendor splitting has not been tuned.
- End-to-end coverage is Chromium only.
- Lighthouse performance and accessibility scores have not been measured.
- GitHub Actions are referenced by version tag, not by commit SHA.

## Security considerations

- The meta-delivered Content Security Policy cannot prevent framing and cannot replace HTTP
  security headers (README, "Security limitations").
- IndexedDB content is unencrypted at rest.
- Stored and URL-derived values are treated as untrusted: validated on read, rendered as text.
