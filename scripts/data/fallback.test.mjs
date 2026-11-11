import { describe, expect, it } from 'vitest';
import { kev, manifest } from '../../src/test/fixtures.ts';
import { selectPreviousCopy, sha256 } from './fallback.mjs';

const content = JSON.stringify(kev);
const withKevEntry = (overrides) => ({
  ...manifest,
  datasets: manifest.datasets.map((entry) => (entry.id === 'kev' ? { ...entry, ...overrides } : entry)),
});
const source = (manifestBody, body = content) => async () => ({ manifest: manifestBody, content: body });

describe('selectPreviousCopy', () => {
  it('returns a valid previous copy with its manifest entry', async () => {
    const result = await selectPreviousCopy('kev', [source(withKevEntry({ sha256: sha256(content) }))]);
    expect(result?.content).toBe(content);
    expect(result?.entry.retrievedAt).toBe(manifest.datasets[0].retrievedAt);
  });

  it('rejects a copy whose checksum does not match the manifest', async () => {
    const result = await selectPreviousCopy('kev', [source(withKevEntry({ sha256: sha256('something else') }))]);
    expect(result).toBeNull();
  });

  it('rejects a copy that fails the dataset schema', async () => {
    const invalid = JSON.stringify({ ...kev, items: [{ cve: 'not-a-cve' }] });
    expect(await selectPreviousCopy('kev', [source(withKevEntry({ sha256: sha256(invalid) }), invalid)])).toBeNull();
    expect(await selectPreviousCopy('kev', [source(withKevEntry({ sha256: null }), '{"items": [')])).toBeNull();
  });

  it('rejects entries marked missing or without a retrieval time, and invalid manifests', async () => {
    expect(await selectPreviousCopy('kev', [source(withKevEntry({ status: 'missing' }))])).toBeNull();
    expect(await selectPreviousCopy('kev', [source(withKevEntry({ retrievedAt: null }))])).toBeNull();
    expect(await selectPreviousCopy('kev', [source({ schemaVersion: 99 })])).toBeNull();
  });

  it('returns null when no copy exists', async () => {
    const failing = async () => {
      throw new Error('ENOENT');
    };
    expect(await selectPreviousCopy('kev', [])).toBeNull();
    expect(await selectPreviousCopy('kev', [failing, failing])).toBeNull();
  });

  it('falls through to the next source when the first one is unusable', async () => {
    const failing = async () => {
      throw new Error('ENOENT');
    };
    const result = await selectPreviousCopy('kev', [failing, source(withKevEntry({ sha256: sha256('x') })), source(withKevEntry({ sha256: sha256(content) }))]);
    expect(result?.content).toBe(content);
  });
});
