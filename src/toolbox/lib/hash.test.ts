import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { HASH_ALGORITHMS, hashBytes } from './hash';
import { Md5, md5 } from './md5';
import { toHex } from './bytes';

const NODE_NAMES = { MD5: 'md5', 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-384': 'sha384', 'SHA-512': 'sha512' } as const;

function expected(bytes: Uint8Array) {
  return Object.fromEntries(HASH_ALGORITHMS.map((algorithm) => [algorithm, createHash(NODE_NAMES[algorithm]).update(bytes).digest('hex')]));
}

describe('hashBytes', () => {
  it('matches node:crypto for the empty input', async () => {
    expect(await hashBytes(new Uint8Array())).toEqual(expected(new Uint8Array()));
  });

  // Lengths around the 64-byte block and 56-byte padding boundaries.
  it.each([1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000, 100_003])('matches node:crypto on %i random bytes', async (length) => {
    const bytes = new Uint8Array(randomBytes(length));
    expect(await hashBytes(bytes)).toEqual(expected(bytes));
  });

  it('computes only the requested algorithms', async () => {
    expect(Object.keys(await hashBytes(new Uint8Array([1]), ['SHA-256']))).toEqual(['SHA-256']);
  });
});

describe('MD5', () => {
  // Test suite of RFC 1321, appendix A.5.
  it.each([
    ['', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['a', '0cc175b9c0f1b6a831c399e269772661'],
    ['abc', '900150983cd24fb0d6963f7d28e17f72'],
    ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
    ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
    ['12345678901234567890123456789012345678901234567890123456789012345678901234567890', '57edf4a22be3c955ac49da2e2107b67a'],
  ])('md5(%j)', (input, digest) => {
    expect(toHex(md5(new TextEncoder().encode(input)))).toBe(digest);
  });

  it('gives the same result when fed in uneven chunks', () => {
    const bytes = new Uint8Array(randomBytes(5000));
    const incremental = new Md5();
    for (let offset = 0; offset < bytes.length; offset += 37) incremental.update(bytes.subarray(offset, offset + 37));
    expect(toHex(incremental.digest())).toBe(createHash('md5').update(bytes).digest('hex'));
  });
});
