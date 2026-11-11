import { afterEach, describe, expect, it, vi } from 'vitest';
import { DATA_FILES, HOSTILE, kev, manifest } from '../test/fixtures';
import { mockDatasets, mockNoDatasets } from '../test/mock-data';
import { freshness, loadDataset, loadManifest } from './loader';
import { DATASET_IDS, DATASET_SCHEMAS, manifestSchema } from './schemas';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('fixtures', () => {
  it('are valid against the published schemas', () => {
    expect(manifestSchema.safeParse(manifest).success).toBe(true);
    for (const id of DATASET_IDS) {
      expect(DATASET_SCHEMAS[id].safeParse(DATA_FILES[`${id}.json`]).success, id).toBe(true);
    }
  });
});

describe('loadManifest', () => {
  it('loads a valid manifest', async () => {
    mockDatasets();
    await expect(loadManifest()).resolves.toMatchObject({ status: 'ready' });
  });

  it('reports a build without datasets as missing', async () => {
    mockNoDatasets();
    await expect(loadManifest()).resolves.toEqual({ status: 'missing' });
  });

  it('reports network failures', async () => {
    mockDatasets({ 'manifest.json': 'network-error' });
    await expect(loadManifest()).resolves.toEqual({ status: 'error', reason: 'network' });
  });

  it.each([
    ['malformed JSON', { rawBody: '{"schemaVersion": 1, ' }],
    ['an HTML error page', { rawBody: '<!doctype html><title>Oops</title>' }],
    ['a wrong schema version', { ...manifest, schemaVersion: 2 }],
    ['an unknown dataset id', { ...manifest, datasets: [{ ...manifest.datasets[0], id: 'evil' }] }],
    ['a path traversal in a file name', { ...manifest, datasets: [{ ...manifest.datasets[0], file: '../../secret.json' }] }],
    ['a javascript: source URL', { ...manifest, datasets: [{ ...manifest.datasets[0], sourceUrl: 'javascript:alert(1)' }] }],
    ['an array', []],
    ['null', null],
  ])('rejects %s', async (_label, body) => {
    mockDatasets({ 'manifest.json': body });
    await expect(loadManifest()).resolves.toEqual({ status: 'error', reason: 'invalid' });
  });
});

describe('loadDataset', () => {
  it('returns validated data with its provenance entry', async () => {
    mockDatasets();
    const result = await loadDataset('kev');
    expect(result.status).toBe('ready');
    if (result.status === 'ready') {
      expect(result.data.items).toHaveLength(kev.items.length);
      expect(result.entry.id).toBe('kev');
    }
  });

  it('fetches each file once and shares the result', async () => {
    const fetchMock = mockDatasets();
    await Promise.all([loadDataset('kev'), loadDataset('kev'), loadDataset('certfr')]);
    await loadDataset('kev');
    const urls = fetchMock.mock.calls.map((call) => String(call[0]));
    expect(urls.filter((url) => url.endsWith('/manifest.json'))).toHaveLength(1);
    expect(urls.filter((url) => url.endsWith('/kev.json'))).toHaveLength(1);
  });

  it('only requests files from the application origin', async () => {
    const fetchMock = mockDatasets();
    await loadDataset('attack');
    for (const call of fetchMock.mock.calls) {
      expect(new URL(String(call[0])).origin).toBe(window.location.origin);
    }
  });

  it('reports datasets the manifest marks as missing without requesting them', async () => {
    const fetchMock = mockDatasets({
      'manifest.json': { ...manifest, datasets: manifest.datasets.map((entry) => (entry.id === 'kev' ? { ...entry, status: 'missing', retrievedAt: null, count: 0 } : entry)) },
    });
    await expect(loadDataset('kev')).resolves.toEqual({ status: 'missing' });
    expect(fetchMock.mock.calls.some((call) => String(call[0]).endsWith('/kev.json'))).toBe(false);
  });

  it('reports a file absent from the server as missing', async () => {
    mockDatasets({ 'kev.json': 'not-found' });
    await expect(loadDataset('kev')).resolves.toEqual({ status: 'missing' });
  });

  it.each([
    ['malformed JSON', { rawBody: '{"items": [' }],
    ['a wrong structure', { items: 'nope' }],
    ['an invalid CVE id', { ...kev, items: [{ ...kev.items[0], cve: `CVE-${HOSTILE}` }] }],
    ['an unexpected enum value', { ...kev, items: [{ ...kev.items[0], ransomware: 'Definitely' }] }],
    ['an oversized field', { ...kev, items: [{ ...kev.items[0], description: 'x'.repeat(7000) }] }],
    ['an invalid date', { ...kev, items: [{ ...kev.items[0], dateAdded: 'yesterday' }] }],
  ])('discards a dataset with %s', async (_label, body) => {
    mockDatasets({ 'kev.json': body });
    await expect(loadDataset('kev')).resolves.toEqual({ status: 'error', reason: 'invalid' });
  });

  it('retries after a network failure instead of caching it', async () => {
    mockDatasets({ 'kev.json': 'network-error' });
    await expect(loadDataset('kev')).resolves.toEqual({ status: 'error', reason: 'network' });
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
      const name = String(input).split('/').pop() as string;
      return new Response(JSON.stringify(DATA_FILES[name]), { status: 200 });
    }));
    await expect(loadDataset('kev')).resolves.toMatchObject({ status: 'ready' });
  });
});

describe('freshness', () => {
  const now = Date.parse('2026-01-10T12:00:00.000Z');

  it.each([
    ['2026-01-10T06:00:00.000Z', 'current', 6],
    ['2026-01-08T12:00:00.000Z', 'current', 48],
    ['2026-01-06T12:00:00.000Z', 'aging', 96],
    ['2026-01-01T12:00:00.000Z', 'outdated', 216],
  ])('%s is %s', (retrievedAt, level, ageHours) => {
    expect(freshness({ retrievedAt }, now)).toEqual({ level, ageHours });
  });

  it('treats a missing or invalid retrieval time as outdated', () => {
    expect(freshness({ retrievedAt: null }, now)).toEqual({ level: 'outdated', ageHours: null });
    expect(freshness({ retrievedAt: 'garbage' }, now)).toEqual({ level: 'outdated', ageHours: null });
  });

  it('never reports a negative age for a clock that runs behind', () => {
    expect(freshness({ retrievedAt: '2026-01-11T00:00:00.000Z' }, now).ageHours).toBe(0);
  });
});
