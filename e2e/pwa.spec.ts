import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { extname, join, normalize } from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { buildOverviewSummary } from '../src/data/overview';
import { DATA_FILES, kev, manifest, nvdRecent } from '../src/test/fixtures';

// Offline support. This spec serves the production build itself, under the /BLACKWATCH/ sub-path
// used by GitHub Pages, because requests answered by a service worker are invisible to page.route
// and the shared preview server cannot be stopped to simulate a lost connection. The datasets are
// the test fixtures, with manifest checksums computed over the exact bytes served.
//
// Chromium only: Firefox and WebKit cannot be launched on the development machine, so this spec has
// not been run against them; CI runs the other specs on all three engines.

test.skip(({ browserName }) => browserName !== 'chromium', 'Service worker spec verified on Chromium only');
test.describe.configure({ mode: 'serial' });
test.use({ serviceWorkers: 'allow', locale: 'en-US', baseURL: undefined });

const DIST = join(process.cwd(), 'dist');
const BASE_PATH = '/BLACKWATCH/';
const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

const sha256 = (text: string | undefined) => {
  if (text === undefined) throw new Error('no such published file');
  return createHash('sha256').update(text).digest('hex');
};

/** Dataset files as published by the pipeline, with real checksums. */
function publish(kevVersion: string): Record<string, string> {
  const files: Record<string, string> = {};
  for (const [name, value] of Object.entries(DATA_FILES)) {
    if (name !== 'manifest.json' && name !== 'overview.json') files[name] = JSON.stringify(value);
  }
  files['kev.json'] = JSON.stringify({ ...kev, catalogVersion: kevVersion });
  const overview = JSON.stringify(
    buildOverviewSummary(
      {
        kev: { data: JSON.parse(files['kev.json'] ?? ''), retrievedAt: manifest.generatedAt, sha256: sha256(files['kev.json']) },
        recent: { data: nvdRecent, sha256: sha256(files['nvd-recent.json']) },
      },
      manifest.generatedAt,
      1,
    ),
  );
  files['overview.json'] = overview;
  files['manifest.json'] = JSON.stringify({
    ...manifest,
    datasets: manifest.datasets.map((entry) => ({ ...entry, sha256: sha256(files[entry.file]) })),
    overview: { file: 'overview.json', sha256: sha256(overview) },
  });
  return files;
}

let server: Server | undefined;
let port = 0;
let data = publish('2026.01.10');
let workerScript: string | null = null;

function start(): Promise<void> {
  const created = createServer((request, response) => {
    const path = decodeURIComponent(new URL(request.url ?? '/', 'http://localhost').pathname);
    if (!path.startsWith(BASE_PATH)) return void response.writeHead(404).end();
    const file = path.slice(BASE_PATH.length) || 'index.html';
    if (file.startsWith('data/')) {
      const body = data[file.slice('data/'.length)];
      if (body === undefined) return void response.writeHead(404).end();
      return void response.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-cache' }).end(body);
    }
    if (file === 'sw.js' && workerScript !== null) {
      return void response.writeHead(200, { 'content-type': TYPES['.js'], 'cache-control': 'no-cache' }).end(workerScript);
    }
    const target = normalize(join(DIST, file));
    if (!target.startsWith(DIST) || !statSync(target, { throwIfNoEntry: false })?.isFile()) return void response.writeHead(404).end();
    response.writeHead(200, { 'content-type': TYPES[extname(target)] ?? 'application/octet-stream', 'cache-control': 'no-cache' });
    response.end(readFileSync(target));
  });
  server = created;
  return new Promise((resolve) => created.listen(port, '127.0.0.1', () => {
    port = (created.address() as AddressInfo).port;
    resolve();
  }));
}

function stop(): Promise<void> {
  // afterAll also runs when every test was skipped, and beforeAll then never started the server.
  const current = server;
  if (!current?.listening) return Promise.resolve();
  return new Promise((resolve) => {
    current.close(() => resolve());
    current.closeAllConnections();
  });
}

const url = (hash = '') => `http://127.0.0.1:${port}${BASE_PATH}${hash ? `#${hash}` : ''}`;

/** Status of a same-origin request made by the page, as the service worker answers it. */
const fetchStatus = (page: Page, file: string) =>
  page.evaluate((path) => fetch(path).then((response) => response.status, () => 'network error'), file);

const cacheNames = (page: Page) => page.evaluate(() => caches.keys());

/** Waits until the worker has stored its offline copy of a data file (written in the background). */
const stored = (page: Page, file: string) =>
  expect.poll(() => page.evaluate((path) => caches.open('blackwatch-data').then((cache) => cache.match(path)).then(Boolean), file)).toBe(true);

async function openControlled(page: Page) {
  await page.goto(url());
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.waitForFunction(() => navigator.serviceWorker.controller !== null);
}

test.beforeAll(async () => {
  await start();
});

test.afterAll(async () => {
  await stop();
});

test.afterEach(async () => {
  data = publish('2026.01.10');
  workerScript = null;
  if (!server?.listening) await start();
});

test('opens offline, including routes never visited online, with verified dataset copies only', async ({ page }) => {
  let loads = 0;
  page.on('load', () => (loads += 1));
  await openControlled(page);
  // The first visit is never reloaded: the worker takes control of the open page.
  expect(loads).toBe(1);

  await page.goto(url('/vulnerabilities'));
  await expect(page.getByText('CVE-2026-10001').first()).toBeVisible();
  await stored(page, 'data/kev.json');

  await stop();
  await page.reload();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.goto(url('/toolbox/cidr'));
  await expect(page.getByRole('heading', { level: 1, name: /CIDR/ })).toBeVisible();
  await page.goto(url('/vulnerabilities'));
  await expect(page.getByText('CVE-2026-10001').first()).toBeVisible();
  // Opened online: served from the verified copy. Never opened: a network error, not "not published".
  expect(await fetchStatus(page, 'data/kev.json')).toBe(200);
  expect(await fetchStatus(page, 'data/attack.json')).toBe('network error');
  await page.goto(url('/attack'));
  await expect(page.getByText(/could not be downloaded/).first()).toBeVisible();
});

test('refuses an offline copy that no longer matches the cached manifest', async ({ page }) => {
  await openControlled(page);
  await page.goto(url('/vulnerabilities'));
  await expect(page.getByText('CVE-2026-10001').first()).toBeVisible();

  // A new publication changes kev.json; the Overview fetches the new manifest but not kev.json.
  data = publish('2026.02.01');
  await page.goto(url('/'));
  await page.reload();
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
  await page.waitForLoadState('networkidle');
  await stored(page, 'data/kev.json');
  await stored(page, 'data/overview.json');

  await stop();
  expect(await fetchStatus(page, 'data/kev.json')).toBe('network error');
  expect(await fetchStatus(page, 'data/nvd-recent.json')).toBe(200);
  expect(await fetchStatus(page, 'data/overview.json')).toBe(200);
});

test('offers a new version and activates it only when the user reloads', async ({ page }) => {
  await openControlled(page);
  const [initial] = (await cacheNames(page)).filter((name) => name.startsWith('blackwatch-shell-'));
  expect(initial).toBeTruthy();

  workerScript = readFileSync(join(DIST, 'sw.js'), 'utf8').replace(/const VERSION = '[^']+';/, "const VERSION = 'e2e-update';");
  let loads = 0;
  page.on('load', () => (loads += 1));
  await page.reload();
  await expect(page.getByText('A new version of BLACKWATCH is available.')).toBeVisible();
  // Installed but waiting: the previous version still serves this page.
  expect(await page.evaluate(async () => Boolean((await navigator.serviceWorker.getRegistration())?.waiting))).toBe(true);
  expect(await cacheNames(page)).toEqual(expect.arrayContaining([initial, 'blackwatch-shell-e2e-update']));
  expect(loads).toBe(1);

  await page.getByRole('button', { name: 'Reload to update' }).click();
  await page.waitForEvent('load');
  await expect(page.getByText('A new version of BLACKWATCH is available.')).toHaveCount(0);
  await expect.poll(async () => (await cacheNames(page)).filter((name) => name.startsWith('blackwatch-shell-'))).toEqual(['blackwatch-shell-e2e-update']);
  expect(loads).toBe(2);
});

test('deleting local data removes the dataset copies and leaves other caches alone', async ({ page }) => {
  await openControlled(page);
  await page.goto(url('/vulnerabilities'));
  await expect(page.getByText('CVE-2026-10001').first()).toBeVisible();
  await page.evaluate(() => caches.open('another-site-on-this-origin'));
  expect(await cacheNames(page)).toContain('blackwatch-data');

  await page.goto(url('/settings'));
  await expect(page.getByText('Offline support is active in this browser.')).toBeVisible();
  await page.getByRole('button', { name: 'Delete local data' }).click();
  await page.getByRole('button', { name: 'Delete everything' }).click();
  await expect(page.getByText(/Local data deleted/)).toBeVisible();

  const names = await cacheNames(page);
  expect(names).not.toContain('blackwatch-data');
  expect(names).toContain('another-site-on-this-origin');
  expect(names.some((name) => name.startsWith('blackwatch-shell-'))).toBe(true);
});

test('tells other open tabs to reload, without reloading them, after an update applied in one tab', async ({ context }) => {
  const first = await context.newPage();
  await openControlled(first);
  const second = await context.newPage();
  let secondLoads = 0;
  second.on('load', () => (secondLoads += 1));
  await second.goto(url('/settings'));
  await expect(second.getByRole('heading', { level: 1 })).toBeVisible();
  await second.waitForFunction(() => navigator.serviceWorker.controller !== null);

  workerScript = readFileSync(join(DIST, 'sw.js'), 'utf8').replace(/const VERSION = '[^']+';/, "const VERSION = 'e2e-other-tab';");
  await first.reload();
  await expect(first.getByText('A new version of BLACKWATCH is available.')).toBeVisible();
  await first.getByRole('button', { name: 'Reload to update' }).click();
  await first.waitForEvent('load');

  await expect(second.getByText(/updated in another tab/)).toBeVisible();
  expect(secondLoads).toBe(1);
});
