import { vi } from 'vitest';
import { clearDatasetCache } from '../data/loader';
import { DATA_FILES } from './fixtures';

type FileOverride = unknown | 'network-error' | 'not-found' | { rawBody: string };

/**
 * Replaces fetch with a stub that serves dataset files from memory.
 * Pass overrides to simulate missing files, network failures or corrupted bodies.
 */
export function mockDatasets(overrides: Record<string, FileOverride> = {}, base: Record<string, unknown> = DATA_FILES) {
  clearDatasetCache();
  const files: Record<string, FileOverride> = { ...base, ...overrides };
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    const name = url.slice(url.lastIndexOf('/') + 1);
    const body = files[name];
    if (body === 'network-error') throw new TypeError('Failed to fetch');
    if (body === undefined || body === 'not-found') return new Response('Not found', { status: 404 });
    if (typeof body === 'object' && body !== null && 'rawBody' in body) {
      return new Response((body as { rawBody: string }).rawBody, { status: 200 });
    }
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

/** No dataset published at all: every request answers 404. */
export function mockNoDatasets() {
  return mockDatasets({}, {});
}
