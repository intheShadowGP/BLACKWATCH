import { toHex } from './bytes';
import { md5 } from './md5';

export const HASH_ALGORITHMS = ['MD5', 'SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'] as const;
export type HashAlgorithm = (typeof HASH_ALGORITHMS)[number];

/** Hashes are computed in one pass over a buffer held in memory: inputs above this are refused. */
export const MAX_HASH_FILE_BYTES = 512 * 1024 * 1024;

export async function hashBytes(bytes: Uint8Array, algorithms: readonly HashAlgorithm[] = HASH_ALGORITHMS): Promise<Record<HashAlgorithm, string>> {
  const entries = await Promise.all(
    algorithms.map(async (algorithm) => {
      if (algorithm === 'MD5') return [algorithm, toHex(md5(bytes))] as const;
      const digest = await crypto.subtle.digest(algorithm, bytes as BufferSource);
      return [algorithm, toHex(new Uint8Array(digest))] as const;
    }),
  );
  return Object.fromEntries(entries) as Record<HashAlgorithm, string>;
}
