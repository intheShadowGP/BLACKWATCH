# BLACKWATCH

**Privacy first. Intelligence driven. Built for professionals.**

BLACKWATCH is a cybersecurity workbench that runs entirely in the browser: threat intelligence,
vulnerability management, SOC investigation tooling, MITRE ATT&CK exploration, security utilities
and incident response training. It is a static application — no account, no backend, no tracking.
Files and data you provide are processed locally and never leave your device.

> **Status: 0.1.0 — foundation (Milestone 0).** The application shell, bilingual interface, local
> storage layer, settings and quality tooling are implemented and tested. The seven functional
> modules are **not implemented yet**; the application says so on each of their pages and shows no
> placeholder data. See [PROJECT_STATE.md](PROJECT_STATE.md) for the exact status.

## Features

| Area | Status |
| --- | --- |
| Application shell, responsive navigation, keyboard and screen-reader support | Implemented, tested |
| French / English interface, switchable at runtime | Implemented, tested |
| Settings: language, theme (dark, light, system), density, reduced motion | Implemented, tested |
| Local data control: per-store record counts, JSON export, full deletion with confirmation | Implemented, tested |
| Overview dashboard (module status, storage status) | Implemented; intelligence figures planned (Milestone 1) |
| Threat Intelligence, IOC Explorer | Planned (Milestone 1) |
| Vulnerability Center | Planned (Milestone 1) |
| MITRE ATT&CK Explorer | Planned (Milestone 1) |
| Security Toolbox | Planned (Milestone 2) |
| SOC Workbench | Planned (Milestone 3) |
| Cyber Lab | Planned (Milestone 4) |
| PWA / offline mode | Planned (Milestone 5) |

Screenshots will be added once the first functional modules are in place.

## Architecture

- **Static frontend.** A single-page application served as static files. Routing uses the URL
  hash and all asset URLs are relative, so the same build works under any GitHub Pages sub-path.
- **Local processing.** Parsing, hashing, analysis and investigation state live in the browser.
  Persistent data is stored in IndexedDB (`blackwatch` database).
- **Static data pipeline (planned, Milestone 1).** GitHub Actions will retrieve, validate and
  normalise public datasets and publish them as static JSON files next to the application. The
  browser never contacts intelligence providers directly.

```
src/
  app/         shell, routing, module registry, preferences provider
  components/  shared interface components
  i18n/        English and French dictionaries, translation helpers
  lib/         preferences schema, IndexedDB schema, storage operations
  pages/       one lazily loaded view per route
e2e/           Playwright end-to-end tests (run against the production build)
scripts/       repository checks
```

Design decisions and their rationale are recorded in [DECISIONS.md](DECISIONS.md).

## Technology stack

React 19 · TypeScript (strict) · Vite · Tailwind CSS 4 · React Router · Dexie (IndexedDB) · Zod ·
Vitest + Testing Library · Playwright · ESLint · GitHub Actions · GitHub Pages.

No web fonts, analytics or third-party scripts are loaded.

## Getting started

Requirements: Node.js 22 or later and npm.

```bash
npm ci
npm run dev
```

The development server prints its local URL. Dependency install scripts are disabled in `.npmrc`.

### Scripts

| Command | Purpose |
| --- | --- |
| `npm run dev` | Development server with hot reload |
| `npm run build` | Production build in `dist/` |
| `npm run preview` | Serve the production build locally |
| `npm run lint` | ESLint |
| `npm run typecheck` | TypeScript, strict mode |
| `npm test` | Unit and integration tests (Vitest) |
| `npm run test:e2e` | End-to-end tests (Playwright; run `npx playwright install chromium` once) |
| `npm run check:identity` | Repository identity policy check |
| `npm run audit:deps` | Dependency vulnerability audit |
| `npm run verify` | Lint, typecheck, tests, build and identity check |

## Deployment

`.github/workflows/deploy.yml` verifies, builds and publishes `dist/` to GitHub Pages on every
push to `main`. To enable it, set **Settings → Pages → Source** to **GitHub Actions** in the
repository. No secrets are required.

## Privacy model

- No registration, accounts, analytics, advertising, telemetry or fingerprinting.
- The browser only requests files hosted with the application.
- Preferences and work are stored in IndexedDB in your browser profile. **Settings & Privacy**
  lets you export everything as JSON or erase it.
- GitHub Pages, as the host, can observe standard connection metadata (such as IP address and
  user agent) when the application is downloaded. BLACKWATCH cannot prevent that.

## Security limitations

- **Content Security Policy is delivered through a `<meta>` element**, because GitHub Pages does
  not allow custom HTTP response headers. This is weaker than a header-based policy:
  `frame-ancestors`, `report-uri` and `sandbox` are unavailable, so the application cannot forbid
  being framed by another site, and the policy only applies from the point where the element is
  parsed. Headers such as `Strict-Transport-Security`, `X-Content-Type-Options`,
  `Referrer-Policy` or `Permissions-Policy` cannot be set by this project on that host.
- The policy forbids inline scripts and inline style elements, restricts connections to the
  application's own origin and disables form submission.
- Data stored in IndexedDB is not encrypted and is readable by anyone with access to the browser
  profile.
- BLACKWATCH is an analysis and training aid. Verify critical results independently.

## Data sources

No external dataset ships with this version. Each source considered for Milestone 1 (for example
NVD, CISA KEV, MITRE ATT&CK, OSV, CERT-FR, abuse.ch) will be integrated only after its licence,
redistribution terms, attribution requirements and rate limits have been verified; the outcome
will be documented here together with the required notices.

## Licensing

BLACKWATCH source code is released under the [MIT License](LICENSE). The licence covers this
project's code only: external datasets and third-party assets remain under their own terms.

## Contributing

Issues and pull requests are welcome. Before opening a pull request:

1. Run `npm run verify` and `npm run test:e2e`.
2. Add or update tests for any behaviour you change.
3. Add both English and French strings for any interface text.
4. Do not add features that send user data to a server, load third-party resources at runtime or
   display fabricated data.

## Known limitations

- Functional modules are not implemented yet (see the table above).
- Not yet a PWA: the application needs a network connection to load.
- Light-theme users may see the dark background for an instant at start-up, because preferences
  are read asynchronously from IndexedDB.
- End-to-end tests currently cover Chromium only (desktop and mobile viewports).
- Lighthouse scores have not been measured yet.

## Development assistance disclosure

Development of this project was assisted by Claude. Although efforts have been made to review,
test and validate the implementation, errors, omissions or security vulnerabilities may still
exist. Users should independently verify critical results before relying on them.
