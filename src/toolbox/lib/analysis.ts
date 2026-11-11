// Entropy, JSON analysis and JWT structural decoding. Pure functions only.

import { base64Decode, utf8DecodeStrict } from './bytes';

// ── Entropy ─────────────────────────────────────────────────────────────────

export interface EntropyResult {
  /** Shannon entropy in bits per byte, 0 to 8. */
  bitsPerByte: number;
  length: number;
  distinctBytes: number;
  /** Occurrences of each byte value 0..255. */
  histogram: Uint32Array;
}

export function shannonEntropy(bytes: Uint8Array): EntropyResult {
  const histogram = new Uint32Array(256);
  for (const byte of bytes) histogram[byte] = (histogram[byte] as number) + 1;
  let entropy = 0;
  let distinct = 0;
  for (const count of histogram) {
    if (count === 0) continue;
    distinct += 1;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return { bitsPerByte: bytes.length === 0 ? 0 : entropy, length: bytes.length, distinctBytes: distinct, histogram };
}

/** Entropy of each window, to locate packed or encrypted regions inside a file. */
export function entropyProfile(bytes: Uint8Array, windowSize = 4096, maxWindows = 256): number[] {
  if (bytes.length === 0) return [];
  const size = Math.max(windowSize, Math.ceil(bytes.length / maxWindows));
  const profile: number[] = [];
  for (let offset = 0; offset < bytes.length; offset += size) {
    profile.push(shannonEntropy(bytes.subarray(offset, offset + size)).bitsPerByte);
  }
  return profile;
}

// ── JSON ────────────────────────────────────────────────────────────────────

export interface JsonIssue {
  kind: 'duplicateKey' | 'unsafeInteger' | 'precisionLoss';
  /** Location in the input, 1-based. */
  line: number;
  column: number;
  detail: string;
}

export type JsonAnalysis =
  | { ok: true; value: unknown; issues: JsonIssue[]; depth: number }
  | { ok: false; message: string; line: number; column: number };

export const MAX_JSON_CHARS = 5_000_000;
const MAX_DEPTH = 512;
/** Only the first issues are reported; the interface says when the list is capped. */
export const MAX_JSON_ISSUES = 200;
const MAX_ISSUES = MAX_JSON_ISSUES;

/**
 * Strict JSON (RFC 8259) parser that reports the position of the first error
 * and the constructs that JSON.parse would silently alter: duplicate keys
 * (the last one wins) and numbers that cannot be represented exactly.
 */
export function analyzeJson(text: string): JsonAnalysis {
  let position = 0;
  let maxDepth = 0;
  const issues: JsonIssue[] = [];

  // Line starts are indexed once, so locating a position is a binary search
  // rather than a scan from the beginning of the text.
  let lineStarts: number[] | null = null;
  const location = (at: number) => {
    if (lineStarts === null) {
      lineStarts = [0];
      for (let index = 0; index < text.length; index += 1) if (text.charCodeAt(index) === 10) lineStarts.push(index + 1);
    }
    let low = 0;
    let high = lineStarts.length - 1;
    while (low < high) {
      const middle = (low + high + 1) >> 1;
      if ((lineStarts[middle] as number) <= at) low = middle;
      else high = middle - 1;
    }
    return { line: low + 1, column: at - (lineStarts[low] as number) + 1 };
  };
  const addIssue = (issue: Omit<JsonIssue, 'line' | 'column'>, at: number) => {
    if (issues.length < MAX_ISSUES) issues.push({ ...issue, ...location(at) });
  };

  class ParseError extends Error {
    constructor(
      message: string,
      readonly at: number,
    ) {
      super(message);
    }
  }
  const fail = (message: string, at = position): never => {
    throw new ParseError(message, at);
  };

  const skipWhitespace = () => {
    while (position < text.length && ' \t\n\r'.includes(text[position] as string)) position += 1;
  };

  const parseString = (): string => {
    const start = position;
    position += 1;
    let out = '';
    while (position < text.length) {
      const char = text[position] as string;
      if (char === '"') {
        position += 1;
        return out;
      }
      if (char === '\\') {
        const next = text[position + 1];
        const simple: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
        if (next !== undefined && next in simple) {
          out += simple[next];
          position += 2;
        } else if (next === 'u' && /^[0-9a-fA-F]{4}$/.test(text.slice(position + 2, position + 6))) {
          out += String.fromCharCode(parseInt(text.slice(position + 2, position + 6), 16));
          position += 6;
        } else {
          fail('Invalid escape sequence');
        }
        continue;
      }
      if (char.charCodeAt(0) < 0x20) fail('Unescaped control character in string');
      out += char;
      position += 1;
    }
    return fail('Unterminated string', start);
  };

  const parseNumber = (): number => {
    const start = position;
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(position, position + 400));
    if (!match) return fail('Invalid number');
    const literal = match[0];
    position += literal.length;
    const value = Number(literal);
    if (/^-?\d+$/.test(literal) && !Number.isSafeInteger(value)) {
      addIssue({ kind: 'unsafeInteger', detail: literal }, start);
    } else if (!Number.isFinite(value)) {
      addIssue({ kind: 'precisionLoss', detail: literal }, start);
    }
    return value;
  };

  const parseValue = (depth: number): unknown => {
    if (depth > MAX_DEPTH) fail(`Nesting deeper than ${MAX_DEPTH} levels`);
    maxDepth = Math.max(maxDepth, depth);
    skipWhitespace();
    const char = text[position];
    if (char === '{') {
      position += 1;
      const object: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const seen = new Set<string>();
      skipWhitespace();
      if (text[position] === '}') {
        position += 1;
        return object;
      }
      for (;;) {
        skipWhitespace();
        if (text[position] !== '"') fail('Expected a property name in double quotes');
        const keyAt = position;
        const key = parseString();
        if (seen.has(key)) addIssue({ kind: 'duplicateKey', detail: key.slice(0, 200) }, keyAt);
        seen.add(key);
        skipWhitespace();
        if (text[position] !== ':') fail("Expected ':' after property name");
        position += 1;
        object[key] = parseValue(depth + 1);
        skipWhitespace();
        if (text[position] === ',') {
          position += 1;
          continue;
        }
        if (text[position] === '}') {
          position += 1;
          return object;
        }
        fail("Expected ',' or '}'");
      }
    }
    if (char === '[') {
      position += 1;
      const array: unknown[] = [];
      skipWhitespace();
      if (text[position] === ']') {
        position += 1;
        return array;
      }
      for (;;) {
        array.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[position] === ',') {
          position += 1;
          continue;
        }
        if (text[position] === ']') {
          position += 1;
          return array;
        }
        fail("Expected ',' or ']'");
      }
    }
    if (char === '"') return parseString();
    if (char === '-' || (char !== undefined && char >= '0' && char <= '9')) return parseNumber();
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(literal, position)) {
        position += literal.length;
        return value;
      }
    }
    return fail(char === undefined ? 'Unexpected end of input' : `Unexpected character '${char}'`);
  };

  try {
    if (text.length > MAX_JSON_CHARS) fail(`Input longer than ${MAX_JSON_CHARS} characters`, 0);
    const value = parseValue(0);
    skipWhitespace();
    if (position < text.length) fail('Unexpected content after the JSON value');
    return { ok: true, value, issues, depth: maxDepth };
  } catch (error) {
    if (error instanceof ParseError) return { ok: false, message: error.message, ...location(error.at) };
    throw error;
  }
}

/** Formats the parsed value. Duplicate keys keep their last value, as in JSON.parse. */
export function formatJson(value: unknown, indent: number | null): string {
  return JSON.stringify(value, null, indent ?? undefined);
}

// ── JWT ─────────────────────────────────────────────────────────────────────

export type JwtDecodeResult =
  | {
      ok: true;
      kind: 'JWS' | 'JWE';
      header: Record<string, unknown>;
      payload: Record<string, unknown> | null;
      signaturePresent: boolean;
      warnings: JwtWarning[];
      times: { claim: 'exp' | 'nbf' | 'iat'; value: number; iso: string | null }[];
    }
  | { ok: false; reason: 'segments' | 'base64' | 'json'; segment?: number };

export type JwtWarning = 'algNone' | 'expired' | 'notYetValid' | 'noExpiry' | 'encrypted' | 'symmetricAlg';

const decodeSegment = (segment: string): Record<string, unknown> | 'base64' | 'json' => {
  const decoded = base64Decode(segment);
  if (!decoded.ok) return 'base64';
  const text = utf8DecodeStrict(decoded.bytes);
  if (text === null) return 'json';
  try {
    const value: unknown = JSON.parse(text);
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : 'json';
  } catch {
    return 'json';
  }
};

/** Decodes the structure of a JWT. It does NOT verify the signature or decrypt a JWE. */
export function decodeJwt(token: string, now: number = Date.now()): JwtDecodeResult {
  const segments = token.trim().split('.');
  if (segments.length !== 3 && segments.length !== 5) return { ok: false, reason: 'segments' };
  const header = decodeSegment(segments[0] as string);
  if (typeof header === 'string') return { ok: false, reason: header, segment: 1 };
  const warnings: JwtWarning[] = [];
  if (segments.length === 5) {
    warnings.push('encrypted');
    return { ok: true, kind: 'JWE', header, payload: null, signaturePresent: false, warnings, times: [] };
  }
  const payload = decodeSegment(segments[1] as string);
  if (typeof payload === 'string') return { ok: false, reason: payload, segment: 2 };
  const alg = typeof header.alg === 'string' ? header.alg : '';
  if (alg.toLowerCase() === 'none') warnings.push('algNone');
  if (/^HS\d+$/.test(alg)) warnings.push('symmetricAlg');
  const times: { claim: 'exp' | 'nbf' | 'iat'; value: number; iso: string | null }[] = [];
  for (const claim of ['exp', 'nbf', 'iat'] as const) {
    const value = payload[claim];
    if (typeof value === 'number' && Number.isFinite(value)) {
      const date = new Date(value * 1000);
      times.push({ claim, value, iso: Number.isNaN(date.getTime()) ? null : date.toISOString() });
    }
  }
  const exp = payload.exp;
  const nbf = payload.nbf;
  if (typeof exp !== 'number') warnings.push('noExpiry');
  else if (exp * 1000 < now) warnings.push('expired');
  if (typeof nbf === 'number' && nbf * 1000 > now) warnings.push('notYetValid');
  return { ok: true, kind: 'JWS', header, payload, signaturePresent: (segments[2] as string).length > 0, warnings, times };
}
