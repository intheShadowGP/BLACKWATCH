// Static data pipeline.
//
// Retrieves public cybersecurity datasets, validates and normalises them and
// writes static JSON files plus a manifest (provenance, licence, retrieval
// time, checksum) into public/data. The application only ever reads these
// files: the browser never contacts the publishers.
//
// Failure policy, per dataset: if retrieval or validation fails, the last
// valid copy is kept (from the output directory, or from the currently
// deployed site when DATA_FALLBACK_URL is set) and marked "stale". If no valid
// copy exists the dataset is marked "missing". The pipeline itself never
// publishes an unvalidated file.
//
// Environment:
//   DATA_FALLBACK_URL  Base URL of the deployed site, e.g. https://owner.github.io/repo/
//   NVD_API_KEY        Optional NVD API key (raises the NVD rate limit). Never shipped.
//   DATA_ONLY          Optional comma-separated dataset ids to refresh.
//
// Requires Node.js 24 or later (imports the TypeScript schema file directly).

import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DATA_SCHEMA_VERSION,
  DATASET_SCHEMAS,
  manifestSchema,
  overviewSummarySchema,
} from '../../src/data/schemas.ts';
import { buildOverviewSummary } from '../../src/data/overview.ts';
import { selectPreviousCopy, sha256 } from './fallback.mjs';
import { normalizeAttack, normalizeCertfr, normalizeCveList, normalizeKev } from './normalize.mjs';

const OUTPUT = fileURLToPath(new URL('../../public/data/', import.meta.url));
const USER_AGENT = 'blackwatch-data-pipeline';
const MAX_BYTES = 120 * 1024 * 1024;
const NVD_RECENT_DAYS = 7;
// NVD public rate limit: 5 requests per rolling 30 seconds (50 with a key).
const NVD_DELAY_MS = process.env.NVD_API_KEY ? 1000 : 6500;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function fetchText(url, { headers = {}, timeoutMs = 120_000, attempts = 3 } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(url, {
        headers: { 'user-agent': USER_AGENT, ...headers },
        signal: AbortSignal.timeout(timeoutMs),
        redirect: 'follow',
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const declared = Number(response.headers.get('content-length') ?? 0);
      if (declared > MAX_BYTES) throw new Error(`response too large (${declared} bytes)`);
      const body = await response.text();
      if (body.length > MAX_BYTES) throw new Error('response too large');
      return body;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) await sleep(attempt * 8000);
    }
  }
  throw new Error(`${new URL(url).host}: ${lastError?.message ?? 'request failed'}`);
}

const fetchJson = async (url, options) => JSON.parse(await fetchText(url, options));

async function fetchNvd(parameters) {
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const pageSize = 2000;
  const all = [];
  for (let startIndex = 0; ; startIndex += pageSize) {
    const query = new URLSearchParams({ ...parameters, resultsPerPage: String(pageSize), startIndex: String(startIndex) });
    // "hasKev" is a flag parameter: the NVD API expects it without a value.
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${query.toString().replace('hasKev=', 'hasKev')}`;
    const page = await fetchJson(url, { headers });
    if (!Array.isArray(page?.vulnerabilities)) throw new Error('unexpected NVD response');
    all.push(...page.vulnerabilities);
    await sleep(NVD_DELAY_MS);
    if (startIndex + pageSize >= Number(page.totalResults ?? 0) || page.vulnerabilities.length === 0) break;
    if (all.length > 40000) throw new Error('NVD result set unexpectedly large');
  }
  return all;
}

// Wording required by the NVD API Terms of Use. BLACKWATCH shows a selection of
// fields from NVD records without altering their values.
const NVD_NOTICE =
  'This product uses the NVD API but is not endorsed or certified by the NVD. BLACKWATCH displays a subset of the fields of each NVD record, unaltered; the NVD record is the complete reference.';

/** Dataset definitions: provenance metadata and the function that produces the dataset. */
const DATASETS = [
  {
    id: 'kev',
    publisher: 'Cybersecurity and Infrastructure Security Agency (CISA)',
    sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    licence: 'Creative Commons Zero 1.0 (CC0 1.0)',
    licenceUrl: 'https://www.cisa.gov/sites/default/files/licenses/kev/license.txt',
    notice:
      'Source: CISA Known Exploited Vulnerabilities Catalog. Use of this data does not imply endorsement by CISA or DHS. Third-party links in the catalog are bound by the policies of those sites.',
    async build() {
      const raw = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
      const data = normalizeKev(raw);
      return { data, version: data.catalogVersion, count: data.items.length };
    },
  },
  {
    id: 'nvd-recent',
    publisher: 'National Vulnerability Database (NIST)',
    sourceUrl: 'https://nvd.nist.gov/developers/vulnerabilities',
    licence: 'NVD API Terms of Use',
    licenceUrl: 'https://nvd.nist.gov/developers/terms-of-use',
    notice: NVD_NOTICE,
    async build() {
      const end = new Date();
      const start = new Date(end.getTime() - NVD_RECENT_DAYS * 86_400_000);
      const raw = await fetchNvd({ pubStartDate: start.toISOString(), pubEndDate: end.toISOString() });
      const data = normalizeCveList(raw, {
        scope: `CVE records published during the ${NVD_RECENT_DAYS} days before retrieval, rejected records excluded`,
        publishedFrom: start.toISOString(),
        publishedTo: end.toISOString(),
      });
      return { data, version: null, count: data.items.length };
    },
  },
  {
    id: 'nvd-kev',
    publisher: 'National Vulnerability Database (NIST)',
    sourceUrl: 'https://nvd.nist.gov/developers/vulnerabilities',
    licence: 'NVD API Terms of Use',
    licenceUrl: 'https://nvd.nist.gov/developers/terms-of-use',
    notice: NVD_NOTICE,
    async build() {
      const raw = await fetchNvd({ hasKev: '' });
      const data = normalizeCveList(raw, {
        scope: 'NVD records of the CVEs listed in the CISA Known Exploited Vulnerabilities Catalog, rejected records excluded',
        publishedFrom: null,
        publishedTo: null,
      });
      return { data, version: null, count: data.items.length };
    },
  },
  {
    id: 'attack',
    publisher: 'The MITRE Corporation',
    sourceUrl: 'https://github.com/mitre-attack/attack-stix-data',
    licence: 'MITRE ATT&CK Terms of Use',
    licenceUrl: 'https://attack.mitre.org/resources/legal-and-branding/terms-of-use/',
    notice:
      '© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. The full ATT&CK licence is shipped with this application in licenses/mitre-attack.txt.',
    async build() {
      const base = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/';
      const index = await fetchJson(`${base}index.json`);
      const collection = index?.collections?.find((entry) => entry?.name === 'Enterprise ATT&CK');
      const latest = collection?.versions?.[0];
      if (!latest?.url?.startsWith(base)) throw new Error('ATT&CK index: enterprise collection not found');
      const data = normalizeAttack(await fetchJson(latest.url, { timeoutMs: 300_000 }));
      if (data.version !== String(latest.version)) throw new Error('ATT&CK bundle version mismatch');
      return { data, version: data.version, count: data.techniques.length };
    },
  },
  {
    id: 'certfr',
    publisher: 'CERT-FR (ANSSI)',
    sourceUrl: 'https://www.cert.cyber.gouv.fr/',
    licence: 'Licence Ouverte / Open Licence 2.0 (Etalab)',
    licenceUrl: 'https://www.etalab.gouv.fr/licence-ouverte-open-licence/',
    notice: 'Source : CERT-FR (ANSSI). Titres et résumés reproduits depuis les flux RSS publics du CERT-FR.',
    async build() {
      const feeds = await Promise.all(
        ['avis', 'alerte'].map((kind) => fetchText(`https://www.cert.cyber.gouv.fr/${kind}/feed/`)),
      );
      const data = normalizeCertfr(feeds);
      if (data.items.length === 0) throw new Error('CERT-FR feeds contained no usable item');
      return { data, version: null, count: data.items.length };
    },
  },
];

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

/** Loads the previous manifest and a previous dataset copy, locally first, then from the deployed site. */
async function previousCopy(definition, file) {
  const sources = [
    async () => ({
      manifest: await readJson(join(OUTPUT, 'manifest.json')),
      content: await readFile(join(OUTPUT, file), 'utf8'),
    }),
  ];
  const fallback = process.env.DATA_FALLBACK_URL;
  if (fallback && /^https:\/\//.test(fallback)) {
    const base = fallback.endsWith('/') ? fallback : `${fallback}/`;
    sources.push(async () => ({
      manifest: await fetchJson(`${base}data/manifest.json`, { attempts: 1 }),
      content: await fetchText(`${base}data/${file}`, { attempts: 1 }),
    }));
  }
  return selectPreviousCopy(definition.id, sources);
}

async function writeAtomic(path, content) {
  const temporary = `${path}.tmp`;
  await writeFile(temporary, content);
  await rename(temporary, path);
}

/**
 * Derives overview.json from the kev and nvd-recent files as published by this run (fresh or kept
 * stale copies), recording their checksums so the application can detect a mismatch.
 */
async function writeOverview(entries, generatedAt) {
  const published = async (id) => {
    const entry = entries.find((item) => item.id === id);
    if (!entry || entry.status === 'missing' || !entry.sha256) return null;
    const content = await readFile(join(OUTPUT, entry.file), 'utf8');
    if (sha256(content) !== entry.sha256) throw new Error(`${id}: published file does not match its manifest checksum`);
    return { data: DATASET_SCHEMAS[id].parse(JSON.parse(content)), retrievedAt: entry.retrievedAt, sha256: entry.sha256 };
  };
  const kev = await published('kev');
  const recent = await published('nvd-recent');
  if (!kev && !recent) return null;
  const summary = overviewSummarySchema.parse(buildOverviewSummary({ kev, recent }, generatedAt, DATA_SCHEMA_VERSION));
  const content = JSON.stringify(summary);
  await writeAtomic(join(OUTPUT, 'overview.json'), content);
  console.log(`overview  ${(content.length / 1024).toFixed(1)} kB`);
  return { file: 'overview.json', sha256: sha256(content) };
}

async function run() {
  await mkdir(OUTPUT, { recursive: true });
  const only = (process.env.DATA_ONLY ?? '').split(',').map((value) => value.trim()).filter(Boolean);
  const entries = [];

  for (const definition of DATASETS) {
    const file = `${definition.id}.json`;
    const provenance = {
      id: definition.id,
      file,
      publisher: definition.publisher,
      sourceUrl: definition.sourceUrl,
      licence: definition.licence,
      licenceUrl: definition.licenceUrl,
      notice: definition.notice,
    };
    let failure = only.length > 0 && !only.includes(definition.id) ? 'skipped (DATA_ONLY)' : null;

    if (!failure) {
      try {
        const { data, version, count } = await definition.build();
        const validated = DATASET_SCHEMAS[definition.id].parse(data);
        if (count === 0) throw new Error('dataset is empty');
        const content = JSON.stringify(validated);
        await writeAtomic(join(OUTPUT, file), content);
        entries.push({ ...provenance, status: 'fresh', retrievedAt: new Date().toISOString(), version, count, sha256: sha256(content) });
        console.log(`fresh    ${definition.id}: ${count} records, ${(content.length / 1024).toFixed(0)} kB`);
        continue;
      } catch (error) {
        failure = error instanceof Error ? error.message.slice(0, 300) : 'unknown error';
      }
    }

    const previous = await previousCopy(definition, file);
    if (previous) {
      await writeAtomic(join(OUTPUT, file), previous.content);
      entries.push({ ...provenance, status: 'stale', retrievedAt: previous.entry.retrievedAt, version: previous.entry.version, count: previous.entry.count, sha256: sha256(previous.content) });
      console.log(`::warning::stale    ${definition.id}: ${failure}; last valid copy from ${previous.entry.retrievedAt} kept`);
    } else {
      entries.push({ ...provenance, status: 'missing', retrievedAt: null, version: null, count: 0, sha256: null });
      console.log(`::warning::missing  ${definition.id}: ${failure}; no valid copy available`);
    }
  }

  const generatedAt = new Date().toISOString();
  // The summary is an optimisation: without it the application computes the same figures itself.
  const overview = await writeOverview(entries, generatedAt).catch((error) => {
    console.log(`::warning::overview summary not published: ${error instanceof Error ? error.message : error}`);
    return null;
  });
  const manifest = manifestSchema.parse({
    schemaVersion: DATA_SCHEMA_VERSION,
    generatedAt,
    datasets: entries,
    ...(overview ? { overview } : {}),
  });
  await writeAtomic(join(OUTPUT, 'manifest.json'), JSON.stringify(manifest, null, 2));
  console.log(`manifest written: ${entries.filter((entry) => entry.status === 'fresh').length}/${entries.length} datasets fresh`);
}

run().catch((error) => {
  console.error(`Data pipeline failed: ${error instanceof Error ? error.message : error}`);
  process.exit(1);
});
