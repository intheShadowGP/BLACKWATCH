# Quality report

Last run: 2026-11-12 · Version 1.0.0 · Windows 11, Node.js 26.13, npm 11.20

Only checks that were actually executed are reported as passed. Unless stated otherwise, the runs
below were local. The GitHub Actions workflows ran successfully on GitHub for version 0.4 (CI and
deployment); the 1.0 changes to them (Firefox and WebKit in CI, pinned actions, non-blocking ATT&CK
check) have **not** run on GitHub yet.

## Results

| Check | Command | Result |
| --- | --- | --- |
| Lint | `npm run lint` | Passed, 0 findings |
| Type check | `npm run typecheck` | Passed (strict, `noUncheckedIndexedAccess`) |
| Unit, integration and pipeline tests | `npm test` | Passed, 556 tests in 21 files (see "Observations" for one unexplained failure) |
| Data pipeline against live sources | `npm run data:build` | 5/5 datasets fresh (KEV 1,779, catalog 2026.11.10; NVD recent 4,922; NVD KEV 1,779; ATT&CK v20.1, 706 techniques; CERT-FR 80); Overview summary 4.6 kB |
| Production build | `npm run build` | Passed; main bundle 593 kB (184 kB gzip); service worker precaches 60 files |
| Repository identity check | `npm run check:identity` | Passed, 172 files plus build output |
| Dependency audit | `npm run audit:deps` | 0 known vulnerabilities |
| End-to-end tests, Chromium | `npm run test:e2e` | 76 tests (38 × desktop and mobile Chromium) passed in a full run; the Lab and service worker specs also passed repeated 4 and 2 times |
| End-to-end tests, Firefox and WebKit | `E2E_ALL_BROWSERS=1 npm run test:e2e` | **Not executed** (see "Not measured") |
| Accessibility rules (axe-core 4.14, WCAG 2.0/2.1/2.2 A and AA) | `e2e/a11y.spec.ts` | 0 violations on 15 routes plus the loaded SOC Workbench, dark and light themes, desktop and mobile |
| Web app manifest and installability | Chromium DevTools protocol | No manifest errors, no installability errors |

## Measurements

**Lighthouse 12.8.2**, final 1.0.0 production build with the live datasets,
`http://localhost:5181/` (Overview), Playwright's Chromium headless shell, default throttling. The
service worker registers after the load event; Lighthouse does not list the worker's own requests,
so the precaching cost is not visible in these figures. Fresh-profile visits to the same build with
the worker active showed the page heading in 857–889 ms (10 sequential) and 871–886 ms (4 parallel,
twice), as before the worker existed.

| Form factor | Performance | Accessibility | Best practices | SEO | FCP | LCP | TBT | CLS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Mobile | 96 | 100 | 96 | 91 | 2.0 s | 2.4 s | 0 ms | 0 |
| Desktop | 100 | 100 | 96 | 91 | 0.5 s | 0.5 s | 0 ms | 0.046 |

- Desktop CLS was 0.195 before the loading placeholders reserved the chart heights.
- SEO: the only failed audit is `robots.txt`, which the local server answers with the application
  page. On GitHub Pages, a project site has no `robots.txt` of its own (it lives at the root of the
  account's domain).
- Best practices: Chromium logged one Content Security Policy issue without a URL. The end-to-end
  tests record every console message and observed no CSP violation from the application; the issue
  was not traced further.

**Overview data on first visit** (same build, 3 fresh profiles each, local server):

| | Data files | JSON decoded | Figures shown after |
| --- | --- | --- | --- |
| Before (full datasets) | manifest, certfr, kev, nvd-recent | 6,447 kB | 506–519 ms |
| After (derived summary) | manifest, overview, certfr | 48 kB | 415–419 ms |

Over the network the saving is larger: kev and nvd-recent are about 970 kB gzip-compressed.

**Main bundle composition** (source-map-explorer): react-dom 207 kB, interface strings in both
languages 116 kB, Dexie 98 kB, Zod 92 kB, React Router 39 kB, application code about 25 kB. All of
it is needed for the first render; vendor chunk splitting was not applied because it would add
requests without reducing bytes.

**First visits to the live site** (`https://intheshadowgp.github.io/BLACKWATCH/`, version 0.4
deployment, fresh Chromium profiles from the development machine): 10 sequential visits showed the
page heading in 468–8,673 ms (median 961 ms); 2 rounds of 4 parallel visits in 963–982 ms. No visit
stalled beyond 20 s. The same script against the local build: 868–893 ms sequential.

## Cross-check against real data

- SOC Workbench limits measured on the production build (DECISIONS.md D-031): 97 MB / 560,000 lines
  analysed in 3.1 s (capped at 500,000 events), search over 500,000 events in under 0.1 s; saving
  100,000 events 0.4 s, Settings export of 105 MB 0.5 s, deletion 0.1 s.
- Attack-shaped loads: 303,000 SSH lines from one address (8,002 findings) analysed in 1.7 s,
  timeline in 0.8 s; 300,000 malicious web requests from one address in 2.2 s.
- File hashing: a 496 MB random file hashed with all five algorithms in a worker in 9.3 s, matching
  the SHA-256 computed by Node. This is the basis for the 512 MB limit.
- CVSS 3.x base scores recomputed for 5,686 NVD records: 0 mismatches with the published score.
  CVSS 4.0: 1,470 of 1,470 vectors decoded.
- IOC extraction on 2 MB of real CVE text: 66 ms, false positives fixed and covered by tests.
- Lab scenarios cite ATT&CK techniques and mitigations that exist in the published ATT&CK v20.1
  dataset (checked by a test against the live data).

## What the tests cover

- **Foundation (52 tests):** i18n parity, preferences, storage, shell, settings; stored preferences
  never overwritten by defaults when IndexedDB answers after the timeout.
- **Data pipeline (51 tests):** normalisers on valid, duplicated, revoked, malformed and hostile
  input; last-valid-copy fallback with checksum checks.
- **Dataset loader and Overview summary (39 tests):** manifest and dataset validation, missing
  files, network failures, malformed JSON, HTML error pages, path traversal, `javascript:` URLs,
  request deduplication, freshness. The Overview summary is used only when its source checksums
  match the manifest; older summaries, invalid ones, absent ones and manifests without checksums
  fall back to the full datasets, which give the same figures.
- **CVSS, IOC, prioritisation, export, ATT&CK index (126 tests).**
- **Pages (37 tests, fixture data):** intelligence pages and toolbox pages, hostile text rendered
  as text.
- **Security Toolbox (134 tests):** hashes against `node:crypto` and RFC vectors, encodings, JSON,
  JWT, network calculators, headers, passwords, YARA and Sigma parsing, file signatures, registry
  coverage of the 23 specified utilities.
- **SOC Workbench (104 tests):** parsers, time handling, detections with boundary cases, Sigma
  subset, reports, investigations, robustness.
- **Cyber Lab (13 tests, looping over all scenarios):** the ten specified topics, structure,
  synthetic addresses and domains only, evidence parsed by the SOC parsers with zero unparsed lines,
  detections triggered, ATT&CK identifiers, deterministic scoring, progress storage.
- **End-to-end (production build, fixture data):** no console errors and no third-party requests;
  navigation, persistence, export; no horizontal overflow; toolbox workers under the CSP; SOC
  import, drill-down, report, saved investigation; Lab play-through, resume after reload, identical
  reports, restart; axe audit and keyboard focus after actions that remove the focused control.
- **Offline support (`e2e/pwa.spec.ts`, Chromium):** the spec serves the build under
  `/BLACKWATCH/` and stops its server to simulate a lost connection. Covered: no reload on first
  visit; offline reload; a route never visited online; a dataset opened online served offline; a
  dataset never opened reported as a network error; a cached dataset that no longer matches the
  cached manifest refused; the update notice with the previous version still in control until the
  user reloads, then exactly one reload; another open tab told to reload and not reloaded; Delete local data removes the dataset
  copies, keeps the
  application shell and leaves another cache of the same origin alone. Disabling the checksum
  comparison in the worker makes the mismatch test fail (checked once).
  Checked by hand: two builds of the same source produce an identical `sw.js`.

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
| Offline copies that do not match the published checksums | Tested (Chromium) |

## Not measured

- **Firefox and WebKit.** Playwright's builds could not be started on the development machine:
  launching Firefox failed with `spawn UNKNOWN` (started directly, Windows reported that its
  side-by-side configuration is incorrect); the WebKit download failed and its folder had no
  executable. Playwright's full Chromium (`chrome.exe`) was also refused ("Permission denied"),
  while its headless shell runs. The cause was not established. CI is configured to run every spec
  except the service worker spec on Firefox and WebKit; until that run is green, those browsers are
  untested.
- The service worker on Firefox and WebKit, and installation on a real phone.
- Manual screen-reader testing (the axe rules and keyboard tests are automated checks only).
- Lighthouse on the deployed site (measured locally only).

## Observations

- **One unexplained unit test failure.** One `npm test` run on 2026-11-12 reported one failed test.
  Its output was not captured, and every run since (more than ten, three of them in parallel)
  passed. A load-sensitive timing test is the likeliest candidate. Not resolved.
- **End-to-end stall, local only.** Earlier runs occasionally stalled 2–4 of the first tests: the
  route chunk requests never completed in the browser, while the server answered every request it
  received (with `vite preview` and with a minimal Node server). Two workers reduce it (DECISIONS.md
  D-026). It did not occur in today's full runs. Fresh-profile visits to the live site showed no
  stall (see "Measurements"). Not explained; CI retries a failed test once.
- **Lab end-to-end race, fixed in the test.** The test reloaded a scenario immediately after
  answering; progress is saved asynchronously, so the last answer was occasionally not yet stored
  (2 failures in 9 mobile runs). The test now waits until both answers are stored.
