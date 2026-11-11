// MD5 (RFC 1321). WebCrypto does not provide MD5, which is still the most common
// hash in indicator feeds. MD5 is broken for collision resistance: it is offered
// only to match existing indicators, never as a security control.

const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
const K = Array.from({ length: 64 }, (_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 2 ** 32) >>> 0);

/** Incremental MD5, so large files can be hashed in chunks. */
export class Md5 {
  private a = 0x67452301;
  private b = 0xefcdab89;
  private c = 0x98badcfe;
  private d = 0x10325476;
  private readonly block = new Uint8Array(64);
  private blockLength = 0;
  private totalLength = 0;
  private readonly words = new Uint32Array(16);

  update(data: Uint8Array): this {
    let offset = 0;
    this.totalLength += data.length;
    if (this.blockLength > 0) {
      const take = Math.min(64 - this.blockLength, data.length);
      this.block.set(data.subarray(0, take), this.blockLength);
      this.blockLength += take;
      offset = take;
      if (this.blockLength === 64) {
        this.compress(this.block, 0);
        this.blockLength = 0;
      }
    }
    for (; offset + 64 <= data.length; offset += 64) this.compress(data, offset);
    if (offset < data.length) {
      this.block.set(data.subarray(offset), 0);
      this.blockLength = data.length - offset;
    }
    return this;
  }

  digest(): Uint8Array {
    const bitLength = this.totalLength * 8;
    const padding = new Uint8Array(((this.blockLength < 56 ? 56 : 120) - this.blockLength) + 8);
    padding[0] = 0x80;
    const view = new DataView(padding.buffer);
    view.setUint32(padding.length - 8, bitLength >>> 0, true);
    view.setUint32(padding.length - 4, Math.floor(bitLength / 2 ** 32), true);
    this.update(padding);
    const out = new Uint8Array(16);
    const result = new DataView(out.buffer);
    [this.a, this.b, this.c, this.d].forEach((word, index) => result.setUint32(index * 4, word, true));
    return out;
  }

  private compress(source: Uint8Array, offset: number): void {
    const words = this.words;
    for (let index = 0; index < 16; index += 1) {
      const base = offset + index * 4;
      words[index] = ((source[base] as number) | ((source[base + 1] as number) << 8) | ((source[base + 2] as number) << 16) | ((source[base + 3] as number) << 24)) >>> 0;
    }
    let a = this.a;
    let b = this.b;
    let c = this.c;
    let d = this.d;
    for (let index = 0; index < 64; index += 1) {
      let f: number;
      let g: number;
      if (index < 16) {
        f = (b & c) | (~b & d);
        g = index;
      } else if (index < 32) {
        f = (d & b) | (~d & c);
        g = (5 * index + 1) % 16;
      } else if (index < 48) {
        f = b ^ c ^ d;
        g = (3 * index + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * index) % 16;
      }
      const temp = d;
      d = c;
      c = b;
      const sum = (a + f + (K[index] as number) + (words[g] as number)) >>> 0;
      const shift = S[index] as number;
      b = (b + ((sum << shift) | (sum >>> (32 - shift)))) >>> 0;
      a = temp;
    }
    this.a = (this.a + a) >>> 0;
    this.b = (this.b + b) >>> 0;
    this.c = (this.c + c) >>> 0;
    this.d = (this.d + d) >>> 0;
  }
}

export function md5(data: Uint8Array): Uint8Array {
  return new Md5().update(data).digest();
}
