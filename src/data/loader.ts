import { summarizeKev, summarizeRecent } from './overview';
import {
  DATASET_SCHEMAS,
  manifestSchema,
  overviewSummarySchema,
  type KevSummary,
  type RecentSummary,
  type DatasetId,
  type DatasetTypes,
  type Manifest,
  type ManifestEntry,
} from './schemas';

/**
 * Outcome of loading a published dataset.
 * - ready: file present and valid.
 * - missing: the build ships no such dataset (pipeline never produced a valid copy).
 * - error: the file could not be fetched (network) or failed validation (invalid).
 */
export type DatasetResult<T> =
  | { status: 'ready'; data: T; entry: ManifestEntry }
  | { status: 'missing' }
  | { status: 'error'; reason: 'network' | 'invalid' };

export type ManifestResult =
  | { status: 'ready'; manifest: Manifest }
  | { status: 'missing' }
  | { status: 'error'; reason: 'network' | 'invalid' };

const cache = new Map<string, Promise<unknown>>();

function dataUrl(file: string): string {
  // Relative to the document, so the application works under any hosting sub-path.
  return new URL(`data/${file}`, document.baseURI).toString();
}

type Fetched = { kind: 'ok'; body: unknown } | { kind: 'missing' } | { kind: 'network' } | { kind: 'invalid' };

async function fetchJson(file: string): Promise<Fetched> {
  let response: Response;
  try {
    response = await fetch(dataUrl(file), { credentials: 'omit' });
  } catch {
    return { kind: 'network' };
  }
  if (response.status === 404) return { kind: 'missing' };
  if (!response.ok) return { kind: 'network' };
  try {
    return { kind: 'ok', body: await response.json() };
  } catch {
    return { kind: 'invalid' };
  }
}

function memoize<T>(key: string, load: () => Promise<T>, keep: (value: T) => boolean): Promise<T> {
  const existing = cache.get(key) as Promise<T> | undefined;
  if (existing) return existing;
  const pending = load().then((value) => {
    // Failures are not cached: the next view gets a fresh attempt.
    if (!keep(value)) cache.delete(key);
    return value;
  });
  cache.set(key, pending);
  return pending;
}

export function loadManifest(): Promise<ManifestResult> {
  return memoize<ManifestResult>(
    'manifest',
    async () => {
      const fetched = await fetchJson('manifest.json');
      if (fetched.kind === 'missing') return { status: 'missing' };
      if (fetched.kind !== 'ok') return { status: 'error', reason: fetched.kind };
      const parsed = manifestSchema.safeParse(fetched.body);
      return parsed.success
        ? { status: 'ready', manifest: parsed.data }
        : { status: 'error', reason: 'invalid' };
    },
    (result) => result.status !== 'error',
  );
}

export function loadDataset<K extends DatasetId>(id: K): Promise<DatasetResult<DatasetTypes[K]>> {
  return memoize<DatasetResult<DatasetTypes[K]>>(
    `dataset:${id}`,
    async () => {
      const manifest = await loadManifest();
      if (manifest.status !== 'ready') return manifest;
      const entry = manifest.manifest.datasets.find((item) => item.id === id);
      if (!entry || entry.status === 'missing') return { status: 'missing' };
      const fetched = await fetchJson(entry.file);
      if (fetched.kind === 'missing') return { status: 'missing' };
      if (fetched.kind !== 'ok') return { status: 'error', reason: fetched.kind };
      const parsed = DATASET_SCHEMAS[id].safeParse(fetched.body);
      return parsed.success
        ? { status: 'ready', data: parsed.data as DatasetTypes[K], entry }
        : { status: 'error', reason: 'invalid' };
    },
    (result) => result.status !== 'error',
  );
}

/** Overview figures for one dataset, with the manifest entry they describe. */
export type OverviewPart<T> = { status: 'ready'; data: T; entry: ManifestEntry } | { status: 'missing' } | { status: 'error'; reason: 'network' | 'invalid' };

export interface OverviewResult {
  kev: OverviewPart<KevSummary>;
  recent: OverviewPart<RecentSummary>;
  /** summary: the published overview.json; datasets: computed from the full kev and nvd-recent files. */
  source: 'summary' | 'datasets' | 'none';
}

/** The sha256 a summary must record for a dataset: null when the dataset is not published. */
function expectedSource(entry: ManifestEntry | undefined): string | null | undefined {
  if (!entry || entry.status === 'missing') return null;
  // A published dataset without a checksum cannot be matched: undefined never equals a recorded source.
  return entry.sha256 ?? undefined;
}

/**
 * Loads the Overview figures. The small derived summary is used when the manifest lists it and it
 * was computed from exactly the published kev and nvd-recent files; otherwise the figures are
 * computed from those files, with the same functions the pipeline uses.
 */
export function loadOverview(): Promise<OverviewResult> {
  return memoize<OverviewResult>(
    'overview',
    async () => {
      const manifest = await loadManifest();
      if (manifest.status !== 'ready') return { kev: manifest, recent: manifest, source: 'none' };
      const kevEntry = manifest.manifest.datasets.find((item) => item.id === 'kev');
      const recentEntry = manifest.manifest.datasets.find((item) => item.id === 'nvd-recent');

      if (manifest.manifest.overview) {
        const fetched = await fetchJson(manifest.manifest.overview.file);
        const parsed = fetched.kind === 'ok' ? overviewSummarySchema.safeParse(fetched.body) : null;
        if (
          parsed?.success &&
          parsed.data.sources.kev === expectedSource(kevEntry) &&
          parsed.data.sources['nvd-recent'] === expectedSource(recentEntry) &&
          (parsed.data.kev === null) === (parsed.data.sources.kev === null) &&
          (parsed.data.recent === null) === (parsed.data.sources['nvd-recent'] === null)
        ) {
          const { kev, recent } = parsed.data;
          return {
            kev: kev && kevEntry ? { status: 'ready', data: kev, entry: kevEntry } : { status: 'missing' },
            recent: recent && recentEntry ? { status: 'ready', data: recent, entry: recentEntry } : { status: 'missing' },
            source: 'summary',
          };
        }
      }

      const [kev, recent] = await Promise.all([loadDataset('kev'), loadDataset('nvd-recent')]);
      const kevIds = new Set(kev.status === 'ready' ? kev.data.items.map((item) => item.cve) : []);
      return {
        kev: kev.status === 'ready' ? { status: 'ready', data: summarizeKev(kev.data, kev.entry.retrievedAt), entry: kev.entry } : kev,
        recent: recent.status === 'ready' ? { status: 'ready', data: summarizeRecent(recent.data, kevIds), entry: recent.entry } : recent,
        source: 'datasets',
      };
    },
    (result) => result.kev.status !== 'error' && result.recent.status !== 'error',
  );
}

export function clearDatasetCache(): void {
  cache.clear();
}

export type FreshnessLevel = 'current' | 'aging' | 'outdated';

const HOUR = 3_600_000;

/** Age of a dataset, derived only from its recorded retrieval time. */
export function freshness(entry: Pick<ManifestEntry, 'retrievedAt'>, now: number = Date.now()) {
  const retrieved = entry.retrievedAt ? Date.parse(entry.retrievedAt) : Number.NaN;
  if (Number.isNaN(retrieved)) return { level: 'outdated' as FreshnessLevel, ageHours: null };
  const ageHours = Math.max(0, (now - retrieved) / HOUR);
  const level: FreshnessLevel = ageHours <= 48 ? 'current' : ageHours <= 24 * 7 ? 'aging' : 'outdated';
  return { level, ageHours };
}
