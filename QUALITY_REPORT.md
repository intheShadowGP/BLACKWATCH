# Quality report

Last run: 2026-11-10 · Version 0.1.0 · Windows 11, Node.js 26.13, npm 11.20

Only checks that were actually executed are reported as passed. All runs below were local and
followed a clean `npm ci`.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Lint | `npm run lint` | Passed, 0 findings |
| Type check | `npm run typecheck` | Passed (strict, `noUncheckedIndexedAccess`) |
| Unit and integration tests | `npm test` | Passed, 51 tests in 4 files |
| Production build | `npm run build` | Passed |
| Repository identity check | `npm run check:identity` | Passed, 48 files plus build output |
| Dependency audit | `npm run audit:deps` | 0 known vulnerabilities |
| End-to-end tests | `npm run test:e2e` | Passed, 14 tests (7 scenarios × desktop and mobile Chromium) |

Manual review in a browser: overview and settings in dark and light themes, 375 px mobile layout,
French and English; no console errors.

## What the tests cover

**Internationalisation (12 tests).** Key parity and placeholder parity between languages, no
empty message, placeholder substitution, prototype-safe parameters, verbatim insertion of hostile
values, fallback for unknown keys, language detection.

**Preferences (13 tests).** Defaults, valid records, complete fallback for malformed input
(`undefined`, `null`, strings, numbers, arrays), per-field recovery, unknown properties dropped,
prototype pollution ignored.

**Storage (10 tests, fake IndexedDB).** Round trip, corrupted record recovery, refusal to store
invalid data, per-store counts, export structure and metadata, full deletion, behaviour when
every database operation fails, export file name safety.

**Application (16 tests, jsdom).** Module registry integrity, navigation to every route, focus
management, mobile drawer, start-up language, language switch and persistence across remount,
appearance preferences applied to the document, deletion confirmation (cancel and confirm), JSON
export, degraded mode when storage is unavailable, hostile and oversized route paths rendered as
truncated text.

**End-to-end (production build, Content Security Policy active).** No console errors and no
request to another origin on load, navigation on desktop and mobile, language and theme
persistence across reloads, local data deletion, export download, no horizontal overflow, markup
in the URL rendered as text.

## Explicit security test status

| Case | Status |
| --- | --- |
| XSS attempts (route path, message parameters, stored preferences) | Tested |
| Malformed stored data / corrupted cache record | Tested for preferences |
| Unexpected input structures | Tested for preferences |
| Storage failures | Tested |
| Malformed JSON, oversized files, invalid timestamps, malicious file names | Not applicable yet: no file import exists (Milestones 2 and 3) |
| Network failures, missing datasets | Not applicable yet: no dataset is fetched (Milestone 1) |

## Not measured

- Lighthouse performance and accessibility scores: no measurement has been run.
- Automated accessibility rules (axe or equivalent): not integrated yet.
- Firefox and WebKit: not tested.
- CI and deployment workflows: written, never executed on GitHub.

## Observations

- With an unrestricted worker count, the first end-to-end runs failed by timeout on the
  development machine (twelve browsers started at once). The worker pool is now capped at 4
  locally and 2 in CI; the suite has passed consistently since.
- Main bundle: 451 kB (142 kB gzip). Acceptable for the foundation; to be optimised in
  Milestone 5.
