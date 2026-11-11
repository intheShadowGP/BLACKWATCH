// URL parsing and HTTP response header analysis. Both report observable facts
// with their source; neither assigns an overall grade.

export interface ParsedUrl {
  href: string;
  protocol: string;
  username: string;
  passwordPresent: boolean;
  hostname: string;
  port: string;
  defaultPort: boolean;
  pathname: string;
  search: string;
  hash: string;
  params: { key: string; value: string }[];
  findings: UrlFinding[];
}

export type UrlFinding =
  | 'userinfo'
  | 'punycode'
  | 'ipHost'
  | 'nonHttp'
  | 'nonDefaultPort'
  | 'encodedPath'
  | 'atInPath'
  | 'longUrl'
  | 'plainHttp';

export const MAX_URL_CHARS = 16_384;

/** Parses an absolute URL with the WHATWG URL parser. The result is never rendered as a live link. */
export function parseUrl(input: string): ParsedUrl | null {
  const text = input.trim();
  if (!text || text.length > MAX_URL_CHARS) return null;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return null;
  }
  const findings: UrlFinding[] = [];
  if (url.username || url.password) findings.push('userinfo');
  if (url.hostname.split('.').some((label) => label.startsWith('xn--'))) findings.push('punycode');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname) || url.hostname.startsWith('[')) findings.push('ipHost');
  if (url.protocol !== 'http:' && url.protocol !== 'https:') findings.push('nonHttp');
  if (url.protocol === 'http:') findings.push('plainHttp');
  if (url.port) findings.push('nonDefaultPort');
  if (/%[0-9a-f]{2}/i.test(url.pathname)) findings.push('encodedPath');
  if (url.pathname.includes('@')) findings.push('atInPath');
  if (text.length > 2000) findings.push('longUrl');
  return {
    href: url.href,
    protocol: url.protocol,
    username: decodeSafely(url.username),
    passwordPresent: url.password.length > 0,
    hostname: url.hostname,
    port: url.port,
    defaultPort: url.port === '',
    pathname: url.pathname,
    search: url.search,
    hash: url.hash,
    params: [...url.searchParams.entries()].slice(0, 500).map(([key, value]) => ({ key, value })),
    findings,
  };
}

function decodeSafely(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

// ── HTTP headers ────────────────────────────────────────────────────────────

export interface ParsedHeader {
  name: string;
  value: string;
}

export const MAX_HEADER_CHARS = 200_000;

/** Parses a raw HTTP response head (status line optional). Folded lines are joined. */
export function parseHeaders(raw: string): { status: string | null; headers: ParsedHeader[] } {
  const lines = raw.slice(0, MAX_HEADER_CHARS).split(/\r?\n/);
  let status: string | null = null;
  const headers: ParsedHeader[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    if (/^HTTP\/\d(\.\d)?\s+\d{3}/i.test(line)) {
      status = line.trim();
      continue;
    }
    if (/^[ \t]/.test(line) && headers.length > 0) {
      const last = headers[headers.length - 1] as ParsedHeader;
      last.value = `${last.value} ${line.trim()}`;
      continue;
    }
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name)) continue;
    headers.push({ name, value: line.slice(colon + 1).trim() });
  }
  return { status, headers };
}

export type HeaderCheckId =
  | 'hsts'
  | 'csp'
  | 'frameProtection'
  | 'contentTypeOptions'
  | 'referrerPolicy'
  | 'permissionsPolicy'
  | 'coop'
  | 'corp'
  | 'serverDisclosure'
  | 'poweredBy'
  | 'cookies'
  | 'cacheControl';

export type CheckState = 'present' | 'absent' | 'weak' | 'info';

export interface HeaderCheck {
  id: HeaderCheckId;
  state: CheckState;
  /** Machine-readable observations, translated by the interface. */
  notes: string[];
  values: string[];
  /** Specification that defines the header. */
  reference: { label: string; url: string };
}

const REFS: Record<HeaderCheckId, { label: string; url: string }> = {
  hsts: { label: 'RFC 6797', url: 'https://www.rfc-editor.org/rfc/rfc6797' },
  csp: { label: 'W3C CSP Level 3', url: 'https://www.w3.org/TR/CSP3/' },
  frameProtection: { label: 'RFC 7034 / CSP frame-ancestors', url: 'https://www.rfc-editor.org/rfc/rfc7034' },
  contentTypeOptions: { label: 'WHATWG Fetch', url: 'https://fetch.spec.whatwg.org/#x-content-type-options-header' },
  referrerPolicy: { label: 'W3C Referrer Policy', url: 'https://www.w3.org/TR/referrer-policy/' },
  permissionsPolicy: { label: 'W3C Permissions Policy', url: 'https://www.w3.org/TR/permissions-policy-1/' },
  coop: { label: 'WHATWG HTML (COOP)', url: 'https://html.spec.whatwg.org/multipage/browsers.html#cross-origin-opener-policies' },
  corp: { label: 'WHATWG Fetch (CORP)', url: 'https://fetch.spec.whatwg.org/#cross-origin-resource-policy-header' },
  serverDisclosure: { label: 'RFC 9110 §10.2.4', url: 'https://www.rfc-editor.org/rfc/rfc9110#section-10.2.4' },
  poweredBy: { label: 'Non-standard header', url: 'https://owasp.org/www-project-secure-headers/' },
  cookies: { label: 'RFC 6265', url: 'https://www.rfc-editor.org/rfc/rfc6265' },
  cacheControl: { label: 'RFC 9111', url: 'https://www.rfc-editor.org/rfc/rfc9111' },
};

export function analyzeHeaders(headers: readonly ParsedHeader[]): HeaderCheck[] {
  const all = (name: string) => headers.filter((header) => header.name === name).map((header) => header.value);
  const checks: HeaderCheck[] = [];
  const add = (id: HeaderCheckId, state: CheckState, values: string[], notes: string[] = []) =>
    checks.push({ id, state, values, notes, reference: REFS[id] });

  const hsts = all('strict-transport-security');
  if (hsts.length === 0) add('hsts', 'absent', []);
  else {
    const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts[0] as string)?.[1] ?? NaN);
    const notes: string[] = [];
    if (!Number.isFinite(maxAge)) notes.push('hstsNoMaxAge');
    else if (maxAge === 0) notes.push('hstsZero');
    else if (maxAge < 15_552_000) notes.push('hstsShort');
    if (/includesubdomains/i.test(hsts[0] as string)) notes.push('hstsSubdomains');
    if (/preload/i.test(hsts[0] as string)) notes.push('hstsPreload');
    add('hsts', notes.some((note) => ['hstsNoMaxAge', 'hstsZero', 'hstsShort'].includes(note)) ? 'weak' : 'present', hsts, notes);
  }

  const csp = all('content-security-policy');
  const cspReportOnly = all('content-security-policy-report-only');
  if (csp.length === 0) add('csp', 'absent', cspReportOnly, cspReportOnly.length > 0 ? ['cspReportOnlyOnly'] : []);
  else {
    const joined = csp.join('; ');
    const notes: string[] = [];
    if (/'unsafe-inline'/i.test(joined)) notes.push('cspUnsafeInline');
    if (/'unsafe-eval'/i.test(joined)) notes.push('cspUnsafeEval');
    if (!/(^|;)\s*(default-src|script-src)\b/i.test(joined)) notes.push('cspNoScriptSrc');
    if (/(^|;)\s*(default-src|script-src)[^;]*(\s|^)\*(\s|;|$)/i.test(joined)) notes.push('cspWildcard');
    // object-src falls back to default-src, so default-src 'none' already blocks plugins.
    if (!/object-src/i.test(joined) && !/(^|;)\s*default-src\s+'none'\s*(;|$)/i.test(joined)) notes.push('cspNoObjectSrc');
    add('csp', notes.length > 0 ? 'weak' : 'present', csp, notes);
  }

  const xfo = all('x-frame-options');
  const frameAncestors = csp.some((value) => /frame-ancestors/i.test(value));
  if (xfo.length === 0 && !frameAncestors) add('frameProtection', 'absent', []);
  else add('frameProtection', 'present', [...xfo, ...(frameAncestors ? ['CSP frame-ancestors'] : [])]);

  const xcto = all('x-content-type-options');
  if (xcto.length === 0) add('contentTypeOptions', 'absent', []);
  else add('contentTypeOptions', /^nosniff$/i.test((xcto[0] as string).trim()) ? 'present' : 'weak', xcto, /^nosniff$/i.test((xcto[0] as string).trim()) ? [] : ['xctoValue']);

  const referrer = all('referrer-policy');
  if (referrer.length === 0) add('referrerPolicy', 'absent', []);
  else add('referrerPolicy', /unsafe-url/i.test(referrer.join(',')) ? 'weak' : 'present', referrer, /unsafe-url/i.test(referrer.join(',')) ? ['referrerUnsafeUrl'] : []);

  const permissions = all('permissions-policy');
  add('permissionsPolicy', permissions.length === 0 ? 'absent' : 'present', permissions);
  const coop = all('cross-origin-opener-policy');
  add('coop', coop.length === 0 ? 'absent' : 'present', coop);
  const corp = all('cross-origin-resource-policy');
  add('corp', corp.length === 0 ? 'absent' : 'present', corp);

  const server = all('server');
  if (server.length > 0) add('serverDisclosure', /\d/.test(server.join(' ')) ? 'weak' : 'info', server, /\d/.test(server.join(' ')) ? ['serverVersion'] : []);
  const poweredBy = [...all('x-powered-by'), ...all('x-aspnet-version'), ...all('x-aspnetmvc-version')];
  if (poweredBy.length > 0) add('poweredBy', 'weak', poweredBy, ['techDisclosure']);

  const cookies = all('set-cookie');
  if (cookies.length > 0) {
    const notes: string[] = [];
    cookies.forEach((cookie) => {
      const name = cookie.split('=')[0]?.trim() ?? '';
      if (!/;\s*secure(\s*;|\s*$)/i.test(cookie)) notes.push(`cookieNoSecure:${name}`);
      if (!/;\s*httponly(\s*;|\s*$)/i.test(cookie)) notes.push(`cookieNoHttpOnly:${name}`);
      if (!/;\s*samesite\s*=/i.test(cookie)) notes.push(`cookieNoSameSite:${name}`);
      if (/;\s*samesite\s*=\s*none/i.test(cookie) && !/;\s*secure(\s*;|\s*$)/i.test(cookie)) notes.push(`cookieSameSiteNoneInsecure:${name}`);
    });
    add('cookies', notes.length > 0 ? 'weak' : 'present', cookies, notes);
  }

  const cache = all('cache-control');
  if (cache.length > 0) add('cacheControl', 'info', cache);
  return checks;
}

// ── Password ────────────────────────────────────────────────────────────────

export type PasswordFinding =
  | 'common'
  | 'commonWithAffixes'
  | 'keyboardSequence'
  | 'alphabeticSequence'
  | 'numericSequence'
  | 'repeated'
  | 'date'
  | 'leet'
  | 'short'
  | 'singleClass';

export interface PasswordAnalysis {
  length: number;
  classes: { lower: boolean; upper: boolean; digit: boolean; symbol: boolean; other: boolean };
  /** log2(alphabet^length): the entropy of a password chosen uniformly at random. An upper bound. */
  upperBoundBits: number;
  findings: PasswordFinding[];
  /** "weak" when any guessable pattern is found or length < 12; otherwise "no known weakness". */
  verdict: 'weak' | 'noKnownWeakness';
}

/** Small list of passwords that top every public breach compilation; used for exact and near matches. */
const COMMON = new Set(
  ('password passw0rd p@ssw0rd p@ssword 123456 1234567 12345678 123456789 1234567890 qwerty qwertyuiop azerty azertyuiop ' +
    'abc123 111111 000000 123123 iloveyou admin administrator welcome letmein monkey dragon football baseball ' +
    'sunshine princess master shadow superman trustno1 login starwars whatever freedom secret changeme default ' +
    'root toor test guest user hello soleil bonjour motdepasse loulou doudou chouchou marseille').split(' '),
);
const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'azertyuiop', 'qsdfghjklm', 'wxcvbn', '1234567890'];
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', $: 's', '!': 'i' };

function hasRun(lower: string, alphabet: string, minimum = 4): boolean {
  for (let index = 0; index + minimum <= lower.length; index += 1) {
    const chunk = lower.slice(index, index + minimum);
    if (alphabet.includes(chunk) || alphabet.split('').reverse().join('').includes(chunk)) return true;
  }
  return false;
}

export function analyzePassword(password: string): PasswordAnalysis {
  const chars = [...password];
  const classes = {
    lower: /[a-z]/.test(password),
    upper: /[A-Z]/.test(password),
    digit: /\d/.test(password),
    symbol: /[!-/:-@[-`{-~ ]/.test(password),
    other: /[^\x20-\x7e]/.test(password),
  };
  const alphabet = (classes.lower ? 26 : 0) + (classes.upper ? 26 : 0) + (classes.digit ? 10 : 0) + (classes.symbol ? 33 : 0) + (classes.other ? 100 : 0);
  const upperBoundBits = chars.length === 0 ? 0 : chars.length * Math.log2(Math.max(alphabet, 1));

  const findings: PasswordFinding[] = [];
  const lower = password.toLowerCase();
  const unleet = [...lower].map((char) => LEET[char] ?? char).join('');
  const core = lower.replace(/^[^a-z]+|[^a-z]+$/g, '');
  const coreUnleet = unleet.replace(/^[^a-z]+|[^a-z]+$/g, '');
  if (COMMON.has(lower)) findings.push('common');
  else {
    const viaCore = core.length >= 4 && COMMON.has(core);
    const viaSubstitution = !viaCore && ((coreUnleet.length >= 4 && COMMON.has(coreUnleet)) || COMMON.has(unleet));
    if (viaCore || viaSubstitution) findings.push('commonWithAffixes');
    if (viaSubstitution) findings.push('leet');
  }
  if (KEYBOARD_ROWS.some((row) => hasRun(lower, row))) findings.push('keyboardSequence');
  if (hasRun(lower, 'abcdefghijklmnopqrstuvwxyz')) findings.push('alphabeticSequence');
  if (hasRun(lower, '01234567890', 4)) findings.push('numericSequence');
  if (/(.)\1{2,}/.test(password) || (chars.length >= 4 && /^(.{1,4})\1+$/.test(password))) findings.push('repeated');
  if (/(19|20)\d{2}/.test(password) || /\b\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}\b/.test(password)) findings.push('date');
  if (chars.length < 12) findings.push('short');
  // A long passphrase is strong without mixed classes; only short single-class passwords are flagged.
  if (chars.length < 16 && Object.values(classes).filter(Boolean).length === 1) findings.push('singleClass');

  const verdict = findings.length > 0 ? 'weak' : 'noKnownWeakness';
  return { length: chars.length, classes, upperBoundBits, findings: [...new Set(findings)], verdict };
}
