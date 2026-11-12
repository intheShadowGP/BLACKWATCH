// BLACKWATCH service worker.
//
// Generated at build time from scripts/pwa/sw.template.js: the build replaces
// the VERSION and PRECACHE placeholders (see vite.config.ts). VERSION is a hash
// of every precached file, so any change to the application yields a new
// worker and an update notice.
//
// - Application shell: every built file except the datasets is precached at
//   install, atomically and bypassing the HTTP cache. Navigations to the scope
//   root or index.html are answered from it, so the application opens offline.
// - Datasets (data/*.json): network first. A successful response is kept as
//   the offline copy. Offline, a copy is served only when its SHA-256 matches
//   the checksum in the cached manifest; otherwise the request fails as a
//   network error, which the application reports as such.
// - A new version waits until the user chooses to reload (no automatic
//   activation under an open page: SOC imports live in memory).
// - Only requests inside the scope, from this origin, are handled. Cache names
//   carry the "blackwatch-" prefix because the origin may host other sites.

const VERSION = '__BLACKWATCH_VERSION__';
const PRECACHE = /* __BLACKWATCH_PRECACHE__ */ [];

const PREFIX = 'blackwatch-';
const SHELL_CACHE = `${PREFIX}shell-${VERSION}`;
const DATA_CACHE = `${PREFIX}data`;
const SCOPE = new URL(self.registration.scope);
const DATA_FILE = /^data\/[a-z0-9-]+\.json$/;

const absolute = (path) => new URL(path, SCOPE).href;

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(SHELL_CACHE);
      // addAll stores every file or none.
      await cache.addAll(PRECACHE.map((path) => new Request(absolute(path), { cache: 'reload' })));
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names.filter((name) => name.startsWith(`${PREFIX}shell-`) && name !== SHELL_CACHE).map((name) => caches.delete(name)),
      );
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const target = new URL(request.url);
  if (target.origin !== SCOPE.origin || !target.pathname.startsWith(SCOPE.pathname)) return;
  const path = target.pathname.slice(SCOPE.pathname.length);

  if (request.mode === 'navigate') {
    if (path === '' || path === 'index.html') event.respondWith(fromShell('index.html', request));
    return;
  }
  if (DATA_FILE.test(path)) {
    event.respondWith(dataFile(request, path));
    return;
  }
  if (PRECACHE.includes(path)) event.respondWith(fromShell(path, request));
});

async function fromShell(path, request) {
  const cached = await caches.match(absolute(path), { cacheName: SHELL_CACHE });
  return cached ?? fetch(request);
}

async function dataFile(request, path) {
  let response;
  try {
    response = await fetch(request);
  } catch {
    return (await verifiedCopy(path)) ?? Response.error();
  }
  const cache = await caches.open(DATA_CACHE);
  if (response.ok) await cache.put(absolute(path), response.clone());
  else if (response.status === 404) await cache.delete(absolute(path));
  return response;
}

/** The offline copy of a data file, only if it is the one the cached manifest describes. */
async function verifiedCopy(path) {
  const cache = await caches.open(DATA_CACHE);
  const copy = await cache.match(absolute(path));
  if (!copy) return null;
  if (path === 'data/manifest.json') return copy;
  const manifestCopy = await cache.match(absolute('data/manifest.json'));
  if (!manifestCopy) return null;
  let manifest;
  try {
    manifest = await manifestCopy.json();
  } catch {
    return null;
  }
  const file = path.slice('data/'.length);
  const expected =
    manifest?.overview?.file === file ? manifest.overview.sha256 : manifest?.datasets?.find?.((entry) => entry?.file === file)?.sha256;
  if (typeof expected !== 'string') return null;
  const digest = await crypto.subtle.digest('SHA-256', await copy.clone().arrayBuffer());
  const actual = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
  return actual === expected ? copy : null;
}
