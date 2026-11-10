# Architecture decisions

Decisions are numbered and append-only. A decision that is reversed gets a new entry.

## D-001 — Dedicated repository

BLACKWATCH lives in its own repository, separate from any other project of the owner. It has its
own licence (MIT), history and deployment.

## D-002 — Hash routing and relative base path

GitHub Pages serves static files without rewrite rules, and the final URL sub-path depends on the
repository name. The application therefore uses hash-based routes (`#/settings`) and a relative
Vite `base` (`./`). The same build works at any path, deep links survive a reload, and no
`404.html` redirect trick is needed. Trade-off: URLs contain a `#`.

## D-003 — Content Security Policy through a meta element, injected at build time

GitHub Pages cannot send custom response headers, so the policy is a `<meta http-equiv>` element
added by a small Vite plugin during production builds only (the development server relies on
inline scripts for hot reload). The policy has no `'unsafe-inline'` and no `'unsafe-eval'`.
Limitations are documented in the README. End-to-end tests run against the production build so
that a policy violation fails the suite.

## D-004 — Native `<dialog>` instead of a dialog library

Radix UI Dialog was evaluated first. Its scroll-lock dependency injects a `<style>` element at
runtime, which the strict policy of D-003 blocks. The native `<dialog>` element provides the focus
trap, Escape handling and inert background without any injected style, so modals and the mobile
navigation drawer are built on it. Radix primitives remain an option for components that do not
conflict with the policy.

## D-005 — In-house internationalisation

Two languages and flat message keys do not justify a dependency. `src/i18n` provides typed keys
(a missing French key is a compile error), `{placeholder}` substitution and language detection.
Tests enforce key and placeholder parity. Messages are always rendered as text.

## D-006 — IndexedDB through Dexie as the only persistence layer

All persistent state, preferences included, is stored in one IndexedDB database with six stores
(`kv`, `favorites`, `notes`, `investigations`, `labProgress`, `cache`). Nothing is written to
`localStorage` or cookies. Consequences:

- Preferences load asynchronously; rendering waits for them, which avoids a language flash but
  allows a brief dark background for light-theme users.
- Stored data is treated as untrusted and validated with Zod, field by field, on every read.
- If IndexedDB is unavailable the application keeps working in memory and tells the user.

## D-007 — No source maps and no web fonts in production

Source maps are disabled to keep build output free of local file paths. Typography uses the
system font stack: no font files, no third-party requests.

## D-008 — Honest placeholders

A module is listed as "available" in `src/app/modules.ts` only when it is implemented and tested.
Planned modules render a page that states they are not functional and describes their intended
scope. No mock data, sample statistics or inert controls are displayed.

## D-009 — TypeScript 6.x

TypeScript is pinned to the 6.x line because the lint tooling does not yet support 7.x.

## D-010 — Patched `minimatch` through an npm override

The lint toolchain depends on a `minimatch` range affected by a moderate denial-of-service
advisory (GHSA-g3hv-75wg-m249). `package.json` overrides it to `^11.0.6`. It is a development-only
dependency and is not shipped. Remove the override once the tools update their range.

## D-011 — Repository identity policy enforced by a script

`scripts/check-identity.mjs` scans repository files, build output and Git metadata (authors,
committers, messages, refs) for restricted terms; only the root `README.md` is exempt. It runs in
`npm run verify`, in CI and before deployment.

## D-012 — GitHub Actions referenced by major version tag

Workflows use `actions/*@vN` tags with read-only default permissions; only the deploy job gets
`pages: write` and `id-token: write`. Pinning actions to full commit SHAs is tracked in TASKS.md.
