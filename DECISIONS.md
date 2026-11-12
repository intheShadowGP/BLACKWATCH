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

## D-013 — Datasets built by the deployment workflow, not committed

The data pipeline runs in the deploy workflow (on push and once a day) and writes into
`public/data/`, which is ignored by Git. Committing 11 MB of data each day would bloat the history
and mix generated content with code. When a source fails, the previous valid copy is fetched from
the deployed site (`DATA_FALLBACK_URL`) and flagged "stale". `ci.yml` never contacts the sources:
tests use synthetic fixtures.

## D-014 — One schema file shared by the pipeline and the application

`src/data/schemas.ts` (Zod) is imported by the pipeline (Node 24 type stripping) and by the
browser. The pipeline refuses to publish a dataset that fails it; the application validates every
file again on load and discards invalid ones. Text fields have length limits and URLs must be
http(s), so a compromised or malformed source cannot inject markup or oversized payloads.

## D-015 — Source selection

Integrated: CISA KEV (CC0), NVD CVE API 2.0 (terms of use; required notice shown), MITRE ATT&CK
Enterprise STIX (licence reproduced in `public/licenses/`), CERT-FR RSS (Licence Ouverte 2.0).
Not integrated: abuse.ch, whose terms restrict commercial use, require authentication and forbid
derivative works without consent. NVD scope is limited to CVEs of the last 7 days plus the records
of KEV entries, to respect the public rate limit and keep the published data small. Rejected CVE
ids are excluded because they describe no vulnerability.

## D-016 — Third-party payloads exempt from the identity check

Dataset text is written by the publishers and may name any vendor or product, including AI
vendors (ATT&CK documents campaigns that used AI tools). Removing or rewriting such records would
falsify the intelligence. `scripts/check-identity.mjs` therefore skips `dist/data/*.json` except
`manifest.json`, which this project writes. The rule still applies to all project code,
documentation, metadata and Git history. Status: confirmed by the project owner on 2026-11-11.

## D-017 — Transparent prioritisation

Priority levels P1–P5 use only published facts: KEV listing first, then the highest published
CVSS base score. Each CVE page lists the factors that produced its level. Exposure in the user's
environment is unknown to the application and is stated as not considered. A missing score is
shown as "not scored", never as low severity.

## D-018 — No charting library yet

The current charts are horizontal bar distributions. They are rendered as SVG inside tables, so
every value is also available as text to assistive technology, with no dependency. ECharts remains
an option if interactive time series are needed.

## D-019 — Bounded wait for stored preferences

Rendering waits for stored preferences to avoid a language flash, but never longer than 2.5 s: a
stalled IndexedDB (blocked upgrade, slow disk) must not leave the page blank.

## D-020 — Security Toolbox as a registry of thin views over pure functions

Each tool is an entry in `src/toolbox/registry.ts` (id, category, translated title, summary and
limits text, lazily loaded component). Logic lives in `src/toolbox/lib` as pure, tested functions;
views only render. `SPECIFICATION_COVERAGE` maps the 23 required utilities to the 20 tools that
provide them (the three SHA-2 sizes share one tool, as do JSON formatting and validation) and a
test fails if a requirement loses its tool. Tool inputs stay in component state: never in the URL,
IndexedDB or browser storage.

## D-021 — Workers for regular expressions and file analysis

Regular expressions run in a module worker created per test and terminated after 2 s: only a
separate thread can be stopped while a pattern backtracks catastrophically. File hashing, entropy
and signature detection also run in a worker. Both load under the production CSP
(`worker-src 'self'`), which the end-to-end tests check on the built site. When workers are
unavailable, the regex tester refuses to run rather than risk freezing the page.

## D-022 — MD5 implemented locally

Web Crypto has no MD5, yet MD5 is the most common hash in indicator feeds. A small RFC 1321
implementation is tested against the RFC vectors and against `node:crypto` on random inputs. It is
offered for matching indicators only.

## D-023 — Password estimator reports findings, not a score

Character-class scoring rates `Password1!` as strong. The tool instead reports named guessable
patterns (common passwords with affixes or substitutions, sequences, repetition, dates, length)
and an explicitly labelled upper bound on entropy. The verdict is either "weak" or "no known
weakness", never "strong". A maintained estimator such as zxcvbn remains an option.

## D-024 — Authored reference data is cited and checked

The TLS reference follows RFC 9325 (BCP 195) and the RFCs it cites; the file signature table
cites the defining specification of each format. When written (2026-11-11), every cited RFC was
downloaded and each cited section number checked against its heading, the RFC 9325 requirement
sentences were read in the RFC text, and the other cited URLs returned HTTP 200 (except
pdfa.org, which refuses automated clients). Section anchors of non-RFC documents were not checked. The port reference is generated from the IANA registry (CC0 1.0) by
`npm run reference:ports` and committed with its retrieval date.

## D-025 — YAML parser dependency for the Sigma viewer

`yaml` (ISC, no dependencies, already present through Vite) parses Sigma rules. It is loaded only
in the Sigma viewer's chunk, with unique keys enforced and alias expansion capped at 100.

## D-026 — Two end-to-end workers

On the development machine, several freshly started browsers loading the site at once
occasionally never receive responses for route chunks (see QUALITY_REPORT.md). In a small
number of runs it did not occur with one worker and occurred in one run out of five with two.
Both local runs and CI use two workers; this reduces the problem, it does not explain it.

## D-027 — SOC Workbench: parsing in a worker, state above the routes

Imported files are read, identified, parsed and analysed in a module worker; the parsed result is
held in a React context above the routes, so following a link to a CVE or a tool keeps the
import. Nothing is persisted unless the analyst saves an investigation; reloading clears it. The
engine is loaded on first use, so the shell does not carry it. Windows Event XML is read by a small
XML reader written for this purpose (DOMParser is unavailable in workers); document type and
entity declarations are refused.

## D-028 — Explicit time assumptions

Classic syslog has no year and many logs have no time zone. The year of the last line and the
offset of zone-less timestamps are settings shown on screen and written into the report; such
timestamps are marked "inferred". The year is inferred backwards across December-to-January
rollovers. Events without a readable timestamp are kept, counted, shown, and excluded from
time-window rules with a per-rule count.

## D-029 — Counting authentication attempts

One SSH attempt is one sshd "Failed <method> for … from …" line. PAM lines describing the same
attempt and "PAM n more authentication failures" summaries are informational, so an attempt is
never counted twice; "message repeated N times" counts N. sudo "n incorrect password attempts"
counts n.

## D-030 — Sigma subset evaluated as string matching

The workbench evaluates a documented Sigma subset (field selections, keyword lists, contains,
startswith, endswith, all, wildcards, null values, and/or/not, "1 of", "all of", "them"). Matching
compares strings only; nothing in a rule is compiled to code or to a regular expression, and
wildcards use an iterative matcher. This is consistent with the toolbox statement that rules are
never executed: a rule is data compared against events. Unsupported constructs (regular
expressions, other modifiers, aggregations, timeframes, correlations) reject the whole rule with
the reason, and a rule whose log source or fields are absent from the imported events is reported
as not applicable rather than as having no match.

## D-031 — Measured limits

On the development machine (Chromium): a 97 MB access log of 560,000 lines was analysed in 3.1 s,
stopping at the 500,000-event cap, with about 330 MB of JavaScript heap. Saving 100,000 events in
IndexedDB took 0.4 s and the Settings export of the resulting 105 MB took 0.5 s; a 500,000-event
save did not complete within 5 minutes. Limits are therefore 100 MB per file, 50 files, 500,000
events per analysis and 100,000 events per saved investigation.

That first benchmark produced no finding, so attack-shaped files were measured as well, after
making every rule linear in the number of events: 303,000 SSH lines from one address with 5,000
rotating accounts and 3,000 successful logins (8,002 findings) were analysed in 1.7 s and the
timeline drawn in 0.8 s; 300,000 traversal requests from one address (3 findings, one with
300,000 events) were analysed in 2.2 s. Files are read one at a time and files after the event cap
are not read. Success-after-failure findings list at most 200 prior failures per source; their
count is complete.

## D-032 — Reports in Markdown, never HTML

Log content is attacker-controlled and a downloaded HTML file would open without the site's CSP.
Reports are Markdown: inline text is escaped and excerpts are placed in code fences longer than
any backtick run they contain. CSV exports use the formula-neutralising cell encoder.

## D-033 — Verified identifiers in detections

Windows event identifiers were checked against Microsoft's audit event documentation (4624, 4625,
4688, 4720, 4732, 4740, 1102 on their own pages; 4728 and 4756 on the security group management
page). ATT&CK technique identifiers are checked by a test against the published dataset when it is
present; this caught that Clear Windows Event Logs is T1685.005 in ATT&CK v20.

## D-034 — Cyber Lab: deterministic scenarios with cited answer keys

Ten synthetic scenarios cover the topics named in the specification; a test maps each topic to a
scenario and checks the required parts (context, incident, evidence, investigation, decision,
containment and remediation steps, scoring, report). Scoring is deterministic: single-choice
options carry points (partial credit where practitioners accept an option but prefer another, for
example powering off instead of isolating during ransomware), multiple-selection steps subtract
wrong selections and never reward selecting everything. Answers lock once feedback is shown.
Each step cites public guidance: NIST CSF 2.0 subcategories as used by NIST SP 800-61r3 (April 2025,
which superseded r2), MITRE ATT&CK mitigations, and the CISA and ANSSI ransomware guides.
Subcategory statements were checked against the CSF 2.0 text.

## D-035 — Synthetic and inert scenario content

Tests enforce that every address in scenario text is a documentation, private or loopback address
and every domain a reserved example name; the only other host is the Windows event XML namespace.
Encoded commands decode to an inert training string, and attack tool command lines are not
reproduced. Log-shaped evidence is parsed by the SOC Workbench parsers with zero unparsed lines,
and representative evidence triggers the matching SOC detection. Scenario bodies are separate
chunks; the list page uses a small catalogue checked against them.

## D-036 — Versioned Lab progress

Progress is stored per scenario in IndexedDB with the scenario version. An attempt made on an
older version keeps its frozen score and is never re-scored against new questions; the learner is
offered a restart, which asks for confirmation.

## D-037 — Accessibility checked by rules and by focus tests

Every route, in both themes and at desktop and mobile width, is audited with axe-core against the
WCAG 2.0, 2.1 and 2.2 A and AA rules in the end-to-end suite; the build fails on any violation.
Scrollable regions (evidence, outputs, wide tables) are focusable and named. When an action removes
the focused control (submitting a Lab answer, showing the events of a finding), focus moves to its
result instead of falling back to the page. Visible language codes start the buttons' accessible
names. These are automated checks; no manual screen-reader session has been recorded.

## D-038 — Derived Overview summary instead of chunk splitting

The Overview parsed about 6.4 MB of JSON to show a few figures. The pipeline now publishes
overview.json, computed by the same module the application uses (src/data/overview.ts, imported by
Node directly), with the SHA-256 of the files it was derived from. The application uses it only when
those checksums match the manifest and otherwise computes the figures from the datasets, so a
partial or out-of-order publication can never show figures that disagree with the data. Vendor
chunk splitting was measured and not applied: everything in the main bundle is needed for the first
render, so splitting adds requests without saving bytes.

## D-039 — Offline support with verified dataset copies

The service worker is generated at build time from a readable template, without a framework. It
precaches every built file except the datasets, atomically and bypassing the HTTP cache, under a
version derived from their content. Datasets are network first; the copy kept for offline use is
served only if its SHA-256 matches the cached manifest, otherwise the request fails as a network
error and the page says so (never "not published"). A new version waits until the user reloads from
the notice, in that tab only: an automatic reload would discard SOC imports held in memory. Cache
names carry a "blackwatch-" prefix because other sites of the account share the origin; deleting
local data removes the dataset copies and keeps the application shell, which holds no user data.
End-to-end specs block service workers; a dedicated spec serves the build under /BLACKWATCH/ and
stops its server to simulate a lost connection.

## D-040 — Cross-browser testing in CI

Firefox and WebKit projects run in CI and, locally, with E2E_ALL_BROWSERS=1. Neither engine could be
started on the development machine, so their results come only from CI. The download helper keeps
the object URL alive for 30 seconds, because revoking it at once can cancel the download in Safari
and Firefox. Supported versions follow from the code (README): Chrome and Edge 111, Firefox 128,
Safari 16.4.

## D-041 — Pinned actions and a non-blocking ATT&CK drift check

Workflow actions are pinned to the commit of their current release, resolved with git ls-remote,
with the version in a comment; pins are updated by hand. Lab scenarios cite ATT&CK identifiers that a
test checks against the published dataset. In the daily deployment that check runs in its own
non-blocking step: a new ATT&CK release that retires an identifier is reported without stopping the
refresh of the other datasets. Everywhere else the check blocks.

## D-042 — README screenshots checked for restricted names

Screenshots are taken from the production build with the live datasets by
scripts/docs-screenshots.mjs, which refuses to write a capture whose visible text contains a term
of the repository identity policy (third-party dataset text may name any product, D-016). The SOC
view uses a synthetic log with documentation addresses.
