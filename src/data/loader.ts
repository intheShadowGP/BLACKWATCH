import {
  DATASET_SCHEMAS,
  manifestSchema,
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
