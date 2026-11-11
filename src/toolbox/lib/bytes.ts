// Byte and text conversions shared by the toolbox. Everything is local and pure.

const encoder = new TextEncoder();
const strictDecoder = new TextDecoder('utf-8', { fatal: true });

export function utf8Encode(text: string): Uint8Array {
  return encoder.encode(text);
}

/** Decodes UTF-8 strictly: returns null when the bytes are not valid UTF-8 instead of inserting U+FFFD. */
export function utf8DecodeStrict(bytes: Uint8Array): string | null {
  try {
    return strictDecoder.decode(bytes);
  } catch {
    return null;
  }
}

export function toHex(bytes: Uint8Array, separator = ''): string {
  let out = '';
  for (let index = 0; index < bytes.length; index += 1) {
    if (index > 0 && separator) out += separator;
    out += (bytes[index] as number).toString(16).padStart(2, '0');
  }
  return out;
}

export type HexParseResult = { ok: true; bytes: Uint8Array } | { ok: false; reason: 'odd' | 'invalid'; position?: number };

/**
 * Parses hexadecimal text. Accepts whitespace, ':' and '-' separators, an optional
 * 0x prefix per byte and \x escapes, so dumps copied from most tools work as is.
 */
export function fromHex(input: string): HexParseResult {
  const cleaned = input.replace(/\\x|0x/gi, '').replace(/[\s:,-]/g, '');
  const invalid = cleaned.search(/[^0-9a-f]/i);
  if (invalid >= 0) return { ok: false, reason: 'invalid', position: invalid };
  if (cleaned.length % 2 !== 0) return { ok: false, reason: 'odd' };
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(cleaned.slice(index * 2, index * 2 + 2), 16);
  }
  return { ok: true, bytes };
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function base64Encode(bytes: Uint8Array, urlSafe = false): string {
  let out = '';
  for (let index = 0; index < bytes.length; index += 3) {
    const a = bytes[index] as number;
    const b = bytes[index + 1];
    const c = bytes[index + 2];
    const triple = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += B64[(triple >> 18) & 63];
    out += B64[(triple >> 12) & 63];
    out += b === undefined ? '=' : B64[(triple >> 6) & 63];
    out += c === undefined ? '=' : B64[triple & 63];
  }
  return urlSafe ? out.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : out;
}

export type Base64ParseResult = { ok: true; bytes: Uint8Array; variant: 'standard' | 'url' } | { ok: false; reason: 'invalid' | 'length'; position?: number };

/** Decodes standard or URL-safe Base64, with or without padding. Whitespace is ignored. */
export function base64Decode(input: string): Base64ParseResult {
  const compact = input.replace(/\s+/g, '');
  const invalid = compact.search(/[^A-Za-z0-9+/\-_=]/);
  if (invalid >= 0) return { ok: false, reason: 'invalid', position: invalid };
  const variant = /[-_]/.test(compact) ? 'url' : 'standard';
  if (variant === 'url' && /[+/]/.test(compact)) return { ok: false, reason: 'invalid' };
  const padIndex = compact.indexOf('=');
  if (padIndex >= 0 && !/^=+$/.test(compact.slice(padIndex))) return { ok: false, reason: 'invalid', position: padIndex };
  const body = compact.replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/');
  if (body.length % 4 === 1) return { ok: false, reason: 'length' };
  if (padIndex >= 0 && compact.length % 4 !== 0) return { ok: false, reason: 'length' };
  const bytes = new Uint8Array(Math.floor((body.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let offset = 0;
  for (const char of body) {
    buffer = (buffer << 6) | B64.indexOf(char);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset] = (buffer >> bits) & 0xff;
      offset += 1;
    }
  }
  return { ok: true, bytes, variant };
}

/** Text if the bytes are valid UTF-8 without control characters other than whitespace; otherwise null. */
export function printableText(bytes: Uint8Array): string | null {
  const text = utf8DecodeStrict(bytes);
  if (text === null) return null;
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(text) ? null : text;
}

/** Classic hex dump: offset, 16 bytes in hexadecimal, printable ASCII. */
export function hexDump(bytes: Uint8Array, limit = 4096): string {
  const lines: string[] = [];
  const end = Math.min(bytes.length, limit);
  for (let offset = 0; offset < end; offset += 16) {
    const row = bytes.subarray(offset, Math.min(offset + 16, end));
    const hex = toHex(row, ' ').padEnd(47, ' ');
    let ascii = '';
    for (const byte of row) ascii += byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.';
    lines.push(`${offset.toString(16).padStart(8, '0')}  ${hex}  ${ascii}`);
  }
  return lines.join('\n');
}
