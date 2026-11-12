// Indicator of compromise extraction, validation and classification.
// Everything runs locally on text supplied by the user.
//
// Known limits (also shown in the interface):
// - Extraction is pattern based: a dotted version number such as 10.0.19.1 is
//   reported as an IPv4 address, and any 32/40/64/128 hexadecimal string as a hash.
// - Names ending with a common file extension (report.pdf, run.sh) are not
//   reported as domains during extraction, which also hides real domains under
//   TLDs such as .sh, .zip or .py. Use single-value validation for those.
// - A domain must end with a TLD present in the embedded IANA snapshot (tlds.ts).
//   Dotted identifiers in source code whose last part is a real TLD (for
//   example "request.post") are still reported as domains.
// - No reputation or geolocation is attached: the tool says what a value is, not whether it is malicious.

import { TLDS } from './tlds';

export type IocType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'email' | 'md5' | 'sha1' | 'sha256' | 'sha512';

export const IOC_TYPES: readonly IocType[] = ['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'sha512'];

export type IocClass =
  | 'public'
  | 'private'
  | 'loopback'
  | 'linkLocal'
  | 'sharedAddressSpace'
  | 'multicast'
  | 'reserved'
  | 'documentation'
  | 'unspecified'
  | 'uniqueLocal';

export interface Ioc {
  type: IocType;
  /** Normalised value: refanged, lower-cased where the type is case-insensitive. */
  value: string;
  /** Address class for IP addresses; null for other types. */
  addressClass: IocClass | null;
  /** Number of occurrences in the analysed text. */
  count: number;
}

export const MAX_IOC_INPUT_CHARS = 2_000_000;
export const MAX_IOC_RESULTS = 10_000;

const FILE_EXTENSIONS = new Set(
  'exe dll sys bat cmd ps1 psm1 vbs js mjs ts json xml html htm php asp aspx jsp txt log csv pdf doc docx xls xlsx ppt pptx zip rar gz tar tgz bz2 png jpg jpeg gif svg ico css py sh rb go rs java class jar yml yaml conf cfg ini tmp bak dat bin iso img lnk msi scr pif db sql md rtf evtx pcap pcapng yar yara rules local lan internal'.split(' '),
);

/** Reverses common defanging: hxxp, [.] (.) {.} [dot], [:] and [at] [@]. */
export function refang(text: string): string {
  return text
    .replace(/h(xx|XX)p(s?):\/\//g, 'http$2://')
    .replace(/h(xx|XX)p(s?)\[:\]\/\//g, 'http$2://')
    .replace(/\[:\]/g, ':')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[@\]|\[at\]|\(at\)/gi, '@');
}

/** Makes an indicator safe to paste into a report or a chat. */
export function defang(ioc: Pick<Ioc, 'type' | 'value'>): string {
  switch (ioc.type) {
    case 'url':
      return ioc.value.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
    case 'ipv4':
    case 'domain':
      return ioc.value.replace(/\./g, '[.]');
    case 'email':
      return ioc.value.replace('@', '[@]').replace(/\./g, '[.]');
    case 'ipv6':
      return ioc.value.replace(/:/g, '[:]');
    default:
      return ioc.value;
  }
}

// ── IPv4 ────────────────────────────────────────────────────────────────────

export function parseIpv4(value: string): [number, number, number, number] | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => (/^(0|[1-9]\d{0,2})$/.test(part) ? Number(part) : -1));
  return octets.every((octet) => octet >= 0 && octet <= 255) ? (octets as [number, number, number, number]) : null;
}

export function classifyIpv4(octets: readonly number[]): IocClass {
  const [a = 0, b = 0, c = 0] = octets;
  if (a === 0) return 'unspecified';
  if (a === 10) return 'private';
  if (a === 100 && b >= 64 && b <= 127) return 'sharedAddressSpace';
  if (a === 127) return 'loopback';
  if (a === 169 && b === 254) return 'linkLocal';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) {
    return 'documentation';
  }
  if (a === 198 && (b === 18 || b === 19)) return 'reserved';
  if (a >= 224 && a <= 239) return 'multicast';
  if (a >= 240) return 'reserved';
  return 'public';
}

// ── IPv6 ────────────────────────────────────────────────────────────────────

/** Parses an IPv6 address into eight 16-bit groups. Zone identifiers and prefixes are not accepted. */
export function parseIpv6(value: string): number[] | null {
  if (value.length < 2 || value.length > 45 || !/^[0-9a-f:.]+$/i.test(value)) return null;
  let text = value;
  const tail: number[] = [];
  const lastColon = text.lastIndexOf(':');
  if (text.includes('.')) {
    const v4 = parseIpv4(text.slice(lastColon + 1));
    if (!v4) return null;
    tail.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
    text = text.slice(0, lastColon + 1);
    // "::" before the IPv4 part is the zero-compression marker and must be kept.
    if (!text.endsWith('::')) text = text.slice(0, -1);
    if (text === '') return null;
  }
  const halves = text.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (part: string): number[] | null => {
    if (part === '') return [];
    const groups = part.split(':');
    if (!groups.every((group) => /^[0-9a-f]{1,4}$/i.test(group))) return null;
    return groups.map((group) => parseInt(group, 16));
  };
  const head = parseGroups(halves[0] as string);
  const rest = halves.length === 2 ? parseGroups(halves[1] as string) : [];
  if (!head || !rest) return null;
  const total = head.length + rest.length + tail.length;
  if (halves.length === 2) {
    if (total > 7) return null;
    return [...head, ...new Array<number>(8 - total).fill(0), ...rest, ...tail];
  }
  return total === 8 ? [...head, ...tail] : null;
}

export function classifyIpv6(groups: readonly number[]): IocClass {
  const first = groups[0] ?? 0;
  if (groups.every((group) => group === 0)) return 'unspecified';
  if (groups.slice(0, 7).every((group) => group === 0) && groups[7] === 1) return 'loopback';
  // IPv4-mapped addresses (::ffff:a.b.c.d, as Windows logs IPv4 clients) take the class of the IPv4 address.
  if (groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff) {
    const high = groups[6] ?? 0;
    const low = groups[7] ?? 0;
    return classifyIpv4([high >> 8, high & 255, low >> 8, low & 255]);
  }
  if ((first & 0xffc0) === 0xfe80) return 'linkLocal';
  if ((first & 0xfe00) === 0xfc00) return 'uniqueLocal';
  if ((first & 0xff00) === 0xff00) return 'multicast';
  if (first === 0x2001 && groups[1] === 0x0db8) return 'documentation';
  return 'public';
}

// ── Domains, e-mail, URLs, hashes ───────────────────────────────────────────

const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
const TLD = '(?:[a-z]{2,24}|xn--[a-z0-9]{2,59})';
const DOMAIN_SOURCE = `(?:${LABEL}\\.)+${TLD}`;
const DOMAIN_EXACT = new RegExp(`^${DOMAIN_SOURCE}$`, 'i');

export function isDomain(value: string): boolean {
  if (value.length > 253 || !DOMAIN_EXACT.test(value)) return false;
  return TLDS.has(value.slice(value.lastIndexOf('.') + 1).toLowerCase());
}

function normalizeUrl(candidate: string): string | null {
  const trimmed = candidate.replace(/[.,;:!?'"]+$/, '');
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    // URLs that embed credentials are rejected so that secrets never reach results or exports.
    if (!url.hostname || url.username || url.password) return null;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (!isDomain(host) && !parseIpv4(host) && !parseIpv6(host)) return null;
    return trimmed.length <= 2048 ? trimmed : null;
  } catch {
    return null;
  }
}

const HASH_TYPES: Record<number, IocType> = { 32: 'md5', 40: 'sha1', 64: 'sha256', 128: 'sha512' };

/** Validates and classifies a single value. Unlike extraction, no file-extension heuristic is applied. */
export function validateIoc(input: string): Omit<Ioc, 'count'> | null {
  const value = refang(input.trim());
  if (!value || value.length > 2048) return null;

  const v4 = parseIpv4(value);
  if (v4) return { type: 'ipv4', value, addressClass: classifyIpv4(v4) };
  const v6 = value.includes(':') && !value.includes('/') ? parseIpv6(value) : null;
  if (v6) return { type: 'ipv6', value: value.toLowerCase(), addressClass: classifyIpv6(v6) };
  if (/^[0-9a-f]+$/i.test(value) && HASH_TYPES[value.length]) {
    return { type: HASH_TYPES[value.length] as IocType, value: value.toLowerCase(), addressClass: null };
  }
  if (/^https?:\/\//i.test(value)) {
    const url = normalizeUrl(value);
    return url ? { type: 'url', value: url, addressClass: null } : null;
  }
  const at = value.lastIndexOf('@');
  if (at > 0) {
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    if (/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/i.test(local) && isDomain(domain)) {
      return { type: 'email', value: `${local}@${domain.toLowerCase()}`, addressClass: null };
    }
    return null;
  }
  if (isDomain(value)) return { type: 'domain', value: value.toLowerCase(), addressClass: null };
  return null;
}

// ── Extraction ──────────────────────────────────────────────────────────────

export interface ExtractionResult {
  iocs: Ioc[];
  /** True when the input was cut at MAX_IOC_INPUT_CHARS or results at MAX_IOC_RESULTS. */
  truncated: boolean;
}

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"'`|\\^{}[\]]+/gi;
const EMAIL_PATTERN = new RegExp(`[a-z0-9][a-z0-9._%+-]{0,63}@${DOMAIN_SOURCE}`, 'gi');
const HASH_PATTERN = /(?<![0-9a-f])(?:[0-9a-f]{128}|[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})(?![0-9a-f])/gi;
const IPV4_PATTERN = /(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\d|\.\d)/g;
const IPV6_PATTERN = /(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}(?:[0-9a-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?(?![\w:]|\.\w)/gi;
const DOMAIN_PATTERN = new RegExp(`(?<![a-z0-9@._-])${DOMAIN_SOURCE}(?![a-z0-9-])`, 'gi');

export function extractIocs(input: string): ExtractionResult {
  let truncated = input.length > MAX_IOC_INPUT_CHARS;
  let text = refang(truncated ? input.slice(0, MAX_IOC_INPUT_CHARS) : input);
  const found = new Map<string, Ioc>();

  const add = (type: IocType, value: string, addressClass: IocClass | null = null) => {
    const key = `${type}|${value}`;
    const existing = found.get(key);
    if (existing) {
      existing.count += 1;
    } else if (found.size < MAX_IOC_RESULTS) {
      found.set(key, { type, value, addressClass, count: 1 });
    } else {
      truncated = true;
    }
  };

  // Each pass blanks what it matched so that later, broader patterns do not report it again.
  const pass = (pattern: RegExp, handle: (match: string) => boolean) => {
    text = text.replace(pattern, (match) => (handle(match) ? ' '.repeat(match.length) : match));
  };

  pass(URL_PATTERN, (match) => {
    const url = normalizeUrl(match);
    if (url) add('url', url);
    return url !== null;
  });
  pass(EMAIL_PATTERN, (match) => {
    const email = validateIoc(match);
    if (email?.type === 'email') add('email', email.value);
    return email?.type === 'email';
  });
  pass(HASH_PATTERN, (match) => {
    add(HASH_TYPES[match.length] as IocType, match.toLowerCase());
    return true;
  });
  pass(IPV6_PATTERN, (match) => {
    const groups = match.includes('::') || match.split(':').length === 8 ? parseIpv6(match) : null;
    // A bare "::" is far more often a scope operator than an address: it is skipped.
    if (!groups || match === '::') return false;
    add('ipv6', match.toLowerCase(), classifyIpv6(groups));
    return true;
  });
  pass(IPV4_PATTERN, (match) => {
    const octets = parseIpv4(match);
    if (octets) add('ipv4', match, classifyIpv4(octets));
    return octets !== null;
  });
  pass(DOMAIN_PATTERN, (match) => {
    const tld = match.slice(match.lastIndexOf('.') + 1).toLowerCase();
    if (FILE_EXTENSIONS.has(tld) || !isDomain(match)) return false;
    add('domain', match.toLowerCase());
    return true;
  });

  const order = new Map(IOC_TYPES.map((type, index) => [type, index]));
  const iocs = [...found.values()].sort(
    (a, b) => (order.get(a.type) ?? 0) - (order.get(b.type) ?? 0) || b.count - a.count || a.value.localeCompare(b.value),
  );
  return { iocs, truncated };
}
