// Last-valid-copy selection for the data pipeline. Kept free of file and
// network access so that it can be tested with in-memory sources.

import { createHash } from 'node:crypto';
import { DATASET_SCHEMAS, manifestSchema } from '../../src/data/schemas.ts';

export const sha256 = (content) => createHash('sha256').update(content).digest('hex');

/**
 * Tries each source in order and returns the first previous copy of a dataset
 * that is still trustworthy: listed in a valid manifest as retrieved (not
 * "missing"), matching the recorded checksum, and valid against the dataset
 * schema. A source is an async function returning { manifest, content }; a
 * source that throws is skipped. Returns null when no source qualifies.
 */
export async function selectPreviousCopy(id, sources) {
  for (const load of sources) {
    try {
      const { manifest, content } = await load();
      const entry = manifestSchema.parse(manifest).datasets.find((item) => item.id === id);
      if (!entry || entry.status === 'missing' || !entry.retrievedAt) continue;
      if (entry.sha256 && entry.sha256 !== sha256(content)) continue;
      DATASET_SCHEMAS[id].parse(JSON.parse(content));
      return { entry, content };
    } catch {
      // Try the next source.
    }
  }
  return null;
}
