// Log parsers. Each parser reads text and returns normalised events plus
// statistics; a line that cannot be parsed is counted and sampled, never
// silently dropped.

import { classifyAuthMessage, classifyWindows } from './classify';
import { child, parseXmlElements, XmlError } from './xml';
import {
  MAX_EVENTS,
  MAX_FIELDS,
  MAX_MESSAGE_CHARS,
  type EventCategory,
  type HttpInfo,
  type LogEvent,
  type LogFormat,
  type ParseStats,
  type TimeQuality,
  type TimeSettings,
} from './model';

export type ParsedFile = { events: Omit<LogEvent, 'id' | 'file'>[]; stats: ParseStats };

// ── Bytes to text ───────────────────────────────────────────────────────────

export type BinaryKind = 'evtx' | 'gzip' | 'zip' | 'bzip2' | 'xz' | 'pcap' | 'pcapng' | 'binary';

/** Recognises binary inputs that cannot be read as text logs. */
export function detectBinary(bytes: Uint8Array): BinaryKind | null {
  const starts = (...values: number[]) => values.every((value, index) => bytes[index] === value);
  if (starts(0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00)) return 'evtx';
  if (starts(0x1f, 0x8b)) return 'gzip';
  if (starts(0x50, 0x4b, 0x03, 0x04)) return 'zip';
  if (starts(0x42, 0x5a, 0x68)) return 'bzip2';
  if (starts(0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00)) return 'xz';
  if (starts(0xd4, 0xc3, 0xb2, 0xa1) || starts(0xa1, 0xb2, 0xc3, 0xd4)) return 'pcap';
  if (starts(0x0a, 0x0d, 0x0d, 0x0a)) return 'pcapng';
  // NUL bytes outside a UTF-16 text are a strong sign of binary content.
  const head = bytes.subarray(0, 4096);
  const utf16 = (head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff);
  if (!utf16 && head.includes(0)) return 'binary';
  return null;
}

/** Decodes UTF-8 or UTF-16 (with byte order mark); invalid UTF-8 sequences become U+FFFD. */
export function decodeText(bytes: Uint8Array): string {
  if (bytes[0] === 0xff && bytes[1] === 0xfe) return new TextDecoder('utf-16le').decode(bytes.subarray(2));
  if (bytes[0] === 0xfe && bytes[1] === 0xff) return new TextDecoder('utf-16be').decode(bytes.subarray(2));
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return new TextDecoder('utf-8').decode(bytes.subarray(3));
  return new TextDecoder('utf-8').decode(bytes);
}

// ── Format detection ────────────────────────────────────────────────────────

const SYSLOG_3164 = /^(?:<\d{1,3}>)?([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^:[\s]+)(?:\[(\d+)\])?: ?(.*)$/;
const SYSLOG_5424 = /^<(\d{1,3})>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+) ?(.*)$/;
const ISO_SYSLOG = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) ([^:[\s]+)(?:\[(\d+)\])?: ?(.*)$/;
const WEB_ACCESS = /^(\S+) (\S+) (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?/;
const APACHE_ERROR = /^\[([A-Z][a-z]{2} [A-Z][a-z]{2} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\] \[(?:([\w-]+):)?(\w+)\](?: \[pid (\d+)(?::tid \d+)?\])?(?: \[client ([^\]]+)\])? ?(.*)$/;
const NGINX_ERROR = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2}) \[(\w+)\] (\d+)#\d+: (.*)$/;

export function detectFormat(text: string, fileName = ''): LogFormat | null {
  const head = text.slice(0, 65536).replace(/^\uFEFF/, '');
  const trimmed = head.trimStart();
  if (trimmed.startsWith('<') && /<Event[\s>]/.test(trimmed.slice(0, 4096))) return 'windowsXml';
  // "[" alone is ambiguous: Apache error lines also start with a bracket.
  if (trimmed.startsWith('{') || /^\[\s*(\{|\])/.test(trimmed)) return 'json';
  const lines = head.split(/\r?\n/).filter((line) => line.trim() !== '').slice(0, 50);
  if (lines.length === 0) return null;
  const score = (pattern: RegExp) => lines.filter((line) => pattern.test(line)).length / lines.length;
  const candidates: [LogFormat, number][] = [
    ['webAccess', score(WEB_ACCESS)],
    ['syslog', Math.max(score(SYSLOG_3164), score(SYSLOG_5424), score(ISO_SYSLOG))],
    ['apacheError', score(APACHE_ERROR)],
    ['nginxError', score(NGINX_ERROR)],
  ];
  const best = candidates.sort((a, b) => b[1] - a[1])[0] as [LogFormat, number];
  if (best[1] >= 0.5) return best[0];
  if (/\.csv$/i.test(fileName) || (lines[0]?.includes(',') && lines.slice(0, 5).every((line) => line.split(',').length === (lines[0] as string).split(',').length))) return 'csv';
  return null;
}

// ── Time ────────────────────────────────────────────────────────────────────

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

/** Parses ISO 8601 with any number of fractional digits; local times use the configured offset. */
export function parseIso(value: string, settings: TimeSettings): { time: number; quality: TimeQuality } | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|[+-]\d{2}:?\d{2})?$/.exec(value.trim());
  if (!match) return null;
  const [, y, mo, d, h, mi, s = '0', fraction = '', zone] = match;
  const ms = Number(fraction.padEnd(3, '0').slice(0, 3));
  let time = Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms);
  if (!validDate(time, Number(y), Number(mo), Number(d), Number(h), Number(mi), Number(s))) return null;
  if (!zone) return { time: time - settings.offsetMinutes * 60_000, quality: 'inferred' };
  if (zone !== 'Z') {
    const sign = zone.startsWith('-') ? -1 : 1;
    const digits = zone.slice(1).replace(':', '');
    time -= sign * (Number(digits.slice(0, 2)) * 60 + Number(digits.slice(2, 4))) * 60_000;
  }
  return { time, quality: 'exact' };
}

function validDate(time: number, y: number, mo: number, d: number, h: number, mi: number, s: number): boolean {
  if (Number.isNaN(time) || mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 60) return false;
  const date = new Date(Date.UTC(y, mo - 1, d));
  return date.getUTCDate() === d;
}

/** Apache/Nginx access log time: 10/Oct/2000:13:55:36 -0700. */
function parseCommonLogTime(value: string): number | null {
  const match = /^(\d{2})\/([A-Z][a-z]{2})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(value);
  if (!match) return null;
  const month = MONTHS.indexOf(match[2] as string);
  if (month < 0) return null;
  const time = Date.UTC(Number(match[3]), month, Number(match[1]), Number(match[4]), Number(match[5]), Number(match[6]));
  if (!validDate(time, Number(match[3]), month + 1, Number(match[1]), Number(match[4]), Number(match[5]), Number(match[6]))) return null;
  const offset = (match[7] === '-' ? -1 : 1) * (Number(match[8]) * 60 + Number(match[9]));
  return time - offset * 60_000;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function newStats(format: LogFormat): ParseStats {
  return { format, read: 0, parsed: 0, unparsed: 0, unparsedSamples: [], timestamps: { exact: 0, inferred: 0, missing: 0 }, yearRollovers: 0, truncated: false };
}

function unparsed(stats: ParseStats, line: number, text: string) {
  stats.unparsed += 1;
  if (stats.unparsedSamples.length < 20) stats.unparsedSamples.push({ line, text: text.slice(0, 300) });
}

type Draft = Omit<LogEvent, 'id' | 'file'>;

function event(partial: Partial<Draft> & Pick<Draft, 'line' | 'format' | 'message'>): Draft {
  return {
    timestamp: null,
    timeQuality: 'missing',
    host: null,
    program: null,
    category: 'other',
    user: null,
    srcIp: null,
    count: 1,
    http: null,
    windows: null,
    fields: {},
    ...partial,
    message: partial.message.slice(0, MAX_MESSAGE_CHARS),
  };
}

function push(events: Draft[], stats: ParseStats, draft: Draft): boolean {
  if (events.length >= MAX_EVENTS) {
    stats.truncated = true;
    return false;
  }
  events.push(draft);
  stats.parsed += 1;
  stats.timestamps[draft.timeQuality] += 1;
  return true;
}

function lines(text: string): string[] {
  return text.split(/\r?\n/);
}

// ── Syslog (RFC 3164, RFC 5424, ISO timestamps) ─────────────────────────────

/** Year of each classic-syslog line, inferred backwards from the end year across December/January rollovers. */
function inferYears(months: (number | null)[], endYear: number): { years: (number | null)[]; rollovers: number } {
  let rollovers = 0;
  let previous: number | null = null;
  for (const month of months) {
    if (month === null) continue;
    if (previous !== null && month < previous - 5) rollovers += 1;
    previous = month;
  }
  let year = endYear - rollovers;
  previous = null;
  const years = months.map((month) => {
    if (month === null) return null;
    if (previous !== null && month < previous - 5) year += 1;
    previous = month;
    return year;
  });
  return { years, rollovers };
}

export function parseSyslog(text: string, settings: TimeSettings): ParsedFile {
  const stats = newStats('syslog');
  const events: Draft[] = [];
  const all = lines(text);
  const months = all.map((line) => {
    const match = SYSLOG_3164.exec(line);
    return match ? MONTHS.indexOf(match[1] as string) : null;
  });
  const { years, rollovers } = inferYears(months, settings.endYear);
  stats.yearRollovers = rollovers;

  for (let index = 0; index < all.length; index += 1) {
    const line = all[index] as string;
    if (line.trim() === '') continue;
    stats.read += 1;
    let host: string | null;
    let program: string | null;
    let message: string;
    let timestamp: number | null = null;
    let quality: TimeQuality = 'missing';
    let match: RegExpExecArray | null;
    if ((match = SYSLOG_3164.exec(line))) {
      const month = months[index] as number;
      const year = years[index] as number;
      const [, , day, h, mi, s] = match;
      const time = Date.UTC(year, month, Number(day), Number(h), Number(mi), Number(s));
      if (validDate(time, year, month + 1, Number(day), Number(h), Number(mi), Number(s))) {
        timestamp = time - settings.offsetMinutes * 60_000;
        quality = 'inferred';
      }
      host = match[6] as string;
      program = match[7] as string;
      message = match[9] as string;
    } else if ((match = SYSLOG_5424.exec(line))) {
      const parsed = match[2] === '-' ? null : parseIso(match[2] as string, settings);
      if (parsed) {
        timestamp = parsed.time;
        quality = parsed.quality;
      }
      host = match[3] === '-' ? null : (match[3] as string);
      program = match[4] === '-' ? null : (match[4] as string);
      message = (match[8] as string).replace(/^\uFEFF/, '');
    } else if ((match = ISO_SYSLOG.exec(line))) {
      const parsed = parseIso(match[1] as string, settings);
      if (parsed) {
        timestamp = parsed.time;
        quality = parsed.quality;
      }
      host = match[2] as string;
      program = match[3] as string;
      message = match[5] as string;
    } else {
      unparsed(stats, index + 1, line);
      continue;
    }
    const classified = classifyAuthMessage(program, message);
    if (!push(events, stats, event({ line: index + 1, format: 'syslog', timestamp, timeQuality: quality, host, program, message: line, category: classified.category, user: classified.user, srcIp: classified.srcIp, count: classified.count, fields: classified.detail }))) break;
  }
  return { events, stats };
}

// ── Web access logs (Apache and Nginx, common and combined) ─────────────────

const unescape = (value: string | undefined) => (value === undefined || value === '-' ? null : value.replace(/\\(.)/g, '$1'));

export function parseWebAccess(text: string): ParsedFile {
  const stats = newStats('webAccess');
  const events: Draft[] = [];
  const all = lines(text);
  for (let index = 0; index < all.length; index += 1) {
    const line = all[index] as string;
    if (line.trim() === '') continue;
    stats.read += 1;
    const match = WEB_ACCESS.exec(line);
    if (!match) {
      unparsed(stats, index + 1, line);
      continue;
    }
    const time = parseCommonLogTime(match[4] as string);
    const request = (match[5] as string).replace(/\\(.)/g, '$1');
    const parts = /^([A-Z]{3,10}) (\S+) (HTTP\/\d(?:\.\d)?)$/.exec(request);
    const http: HttpInfo = {
      method: parts ? (parts[1] as string) : null,
      path: parts ? (parts[2] as string) : request || null,
      protocol: parts ? (parts[3] as string) : null,
      status: match[6] === '-' ? null : Number(match[6]),
      bytes: match[7] === '-' ? null : Number(match[7]),
      referrer: unescape(match[8]),
      userAgent: unescape(match[9]),
      // Scanners send raw bytes or bare paths; these lines are kept and flagged.
      malformed: !parts,
    };
    const user = match[3] === '-' ? null : (match[3] as string);
    if (!push(events, stats, event({ line: index + 1, format: 'webAccess', timestamp: time, timeQuality: time === null ? 'missing' : 'exact', host: null, message: line, category: 'httpRequest', user, srcIp: match[1] as string, http }))) break;
  }
  return { events, stats };
}

// ── Apache and Nginx error logs ─────────────────────────────────────────────

export function parseApacheError(text: string, settings: TimeSettings): ParsedFile {
  const stats = newStats('apacheError');
  const events: Draft[] = [];
  const all = lines(text);
  for (let index = 0; index < all.length; index += 1) {
    const line = all[index] as string;
    if (line.trim() === '') continue;
    stats.read += 1;
    const match = APACHE_ERROR.exec(line);
    if (!match) {
      unparsed(stats, index + 1, line);
      continue;
    }
    // "Wed Oct 11 14:32:52.123 2000": local server time without a zone.
    const parts = /^[A-Z][a-z]{2} ([A-Z][a-z]{2}) (\d{1,2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d+))? (\d{4})$/.exec(match[1] as string);
    let timestamp: number | null = null;
    if (parts) {
      const month = MONTHS.indexOf(parts[1] as string);
      const iso = `${parts[7]}-${String(month + 1).padStart(2, '0')}-${String(parts[2]).padStart(2, '0')}T${parts[3]}:${parts[4]}:${parts[5]}${parts[6] ? `.${parts[6]}` : ''}`;
      timestamp = month < 0 ? null : parseIso(iso, settings)?.time ?? null;
    }
    const client = match[5] ? (match[5] as string).replace(/:\d+$/, '') : null;
    if (!push(events, stats, event({ line: index + 1, format: 'apacheError', timestamp, timeQuality: timestamp === null ? 'missing' : 'inferred', program: match[2] ?? 'apache', message: line, category: 'webError', srcIp: client, fields: { level: match[3] as string, ...(match[4] ? { pid: match[4] } : {}) } }))) break;
  }
  return { events, stats };
}

export function parseNginxError(text: string, settings: TimeSettings): ParsedFile {
  const stats = newStats('nginxError');
  const events: Draft[] = [];
  const all = lines(text);
  for (let index = 0; index < all.length; index += 1) {
    const line = all[index] as string;
    if (line.trim() === '') continue;
    stats.read += 1;
    const match = NGINX_ERROR.exec(line);
    if (!match) {
      unparsed(stats, index + 1, line);
      continue;
    }
    const parsed = parseIso(`${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}`, settings);
    const body = match[9] as string;
    const client = /client: ([0-9a-fA-F:.]+)/.exec(body)?.[1] ?? null;
    const request = /request: "([^"]*)"/.exec(body)?.[1] ?? null;
    if (!push(events, stats, event({ line: index + 1, format: 'nginxError', timestamp: parsed?.time ?? null, timeQuality: parsed ? 'inferred' : 'missing', program: 'nginx', message: line, category: 'webError', srcIp: client, fields: { level: match[7] as string, pid: match[8] as string, ...(request ? { request } : {}) } }))) break;
  }
  return { events, stats };
}

// ── JSON and CSV ────────────────────────────────────────────────────────────

/** Flattens nested objects into dotted keys, bounded in depth and number of fields. */
export function flatten(value: unknown, prefix = '', out: Record<string, string> = {}, depth = 0): Record<string, string> {
  if (Object.keys(out).length >= MAX_FIELDS) return out;
  if (value === null || value === undefined) return out;
  if (typeof value === 'object' && depth < 4) {
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      if (key === '__proto__') continue;
      flatten(inner, prefix ? `${prefix}.${key}` : key, out, depth + 1);
    }
    return out;
  }
  out[prefix || 'value'] = (typeof value === 'object' ? JSON.stringify(value) : String(value)).slice(0, 1000);
  return out;
}

const pick = (fields: Record<string, string>, names: readonly string[]) => {
  for (const name of names) {
    const exact = fields[name];
    if (exact !== undefined && exact !== '') return exact;
  }
  const lower = new Map(Object.entries(fields).map(([key, value]) => [key.toLowerCase(), value]));
  for (const name of names) {
    const value = lower.get(name.toLowerCase());
    if (value !== undefined && value !== '') return value;
  }
  return null;
};

const TIME_FIELDS = ['@timestamp', 'timestamp', 'time', 'ts', 'datetime', 'date', 'EventTime', 'TimeCreated', 'eventTime', '__REALTIME_TIMESTAMP'];
const MESSAGE_FIELDS = ['message', 'msg', 'MESSAGE', 'log', 'Message', 'event.original'];
const USER_FIELDS = ['user', 'username', 'user.name', 'TargetUserName', 'SubjectUserName', 'userIdentity.userName', 'usr'];
const IP_FIELDS = ['src_ip', 'source.ip', 'srcip', 'client_ip', 'clientip', 'remote_addr', 'IpAddress', 'sourceIPAddress', 'ip', 'client.ip'];
const HOST_FIELDS = ['host', 'hostname', 'host.name', '_HOSTNAME', 'Computer', 'computer'];
const PROGRAM_FIELDS = ['program', 'process', 'SYSLOG_IDENTIFIER', 'process.name', 'app', 'service'];

function recordToEvent(fields: Record<string, string>, line: number, format: LogFormat, settings: TimeSettings): Draft {
  const rawTime = pick(fields, TIME_FIELDS);
  let timestamp: number | null = null;
  let quality: TimeQuality = 'missing';
  if (rawTime !== null) {
    if (/^\d{16}$/.test(rawTime)) {
      // journald __REALTIME_TIMESTAMP: microseconds since the epoch.
      timestamp = Math.floor(Number(rawTime) / 1000);
      quality = 'exact';
    } else if (/^\d{10}(\.\d+)?$/.test(rawTime) || /^\d{13}$/.test(rawTime)) {
      timestamp = rawTime.length === 13 ? Number(rawTime) : Math.round(Number(rawTime) * 1000);
      quality = 'exact';
    } else {
      const parsed = parseIso(rawTime, settings);
      if (parsed) {
        timestamp = parsed.time;
        quality = parsed.quality;
      }
    }
  }
  const program = pick(fields, PROGRAM_FIELDS);
  const message = pick(fields, MESSAGE_FIELDS) ?? JSON.stringify(fields);
  const classified = program ? classifyAuthMessage(program, message) : null;
  const category: EventCategory = classified?.category ?? 'other';
  return event({
    line,
    format,
    timestamp,
    timeQuality: quality,
    host: pick(fields, HOST_FIELDS),
    program,
    message,
    category,
    user: classified?.user ?? pick(fields, USER_FIELDS),
    srcIp: classified?.srcIp ?? pick(fields, IP_FIELDS),
    count: classified?.count ?? 1,
    fields,
  });
}

export function parseJson(text: string, settings: TimeSettings): ParsedFile {
  const stats = newStats('json');
  const events: Draft[] = [];
  const trimmed = text.replace(/^\uFEFF/, '').trim();
  if (trimmed.startsWith('[')) {
    let records: unknown;
    try {
      records = JSON.parse(trimmed);
    } catch (error) {
      stats.read = 1;
      unparsed(stats, 1, (error as Error).message);
      return { events, stats };
    }
    const list = Array.isArray(records) ? records : [];
    for (let index = 0; index < list.length; index += 1) {
      stats.read += 1;
      const record = list[index];
      if (typeof record !== 'object' || record === null || Array.isArray(record)) {
        unparsed(stats, index + 1, JSON.stringify(record) ?? String(record));
        continue;
      }
      if (!push(events, stats, recordToEvent(flatten(record), index + 1, 'json', settings))) break;
    }
    return { events, stats };
  }
  // NDJSON / JSON Lines.
  const all = lines(trimmed);
  for (let index = 0; index < all.length; index += 1) {
    const line = all[index] as string;
    if (line.trim() === '') continue;
    stats.read += 1;
    let record: unknown;
    try {
      record = JSON.parse(line);
    } catch {
      unparsed(stats, index + 1, line);
      continue;
    }
    if (typeof record !== 'object' || record === null || Array.isArray(record)) {
      unparsed(stats, index + 1, line);
      continue;
    }
    if (!push(events, stats, recordToEvent(flatten(record), index + 1, 'json', settings))) break;
  }
  return { events, stats };
}

/** RFC 4180 rows; quoted fields may contain separators, quotes and line breaks. */
export function csvRows(text: string): { cells: string[]; line: number }[] {
  const rows: { cells: string[]; line: number }[] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  let line = 1;
  let rowLine = 1;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else quoted = false;
      } else {
        if (char === '\n') line += 1;
        field += char;
      }
    } else if (char === '"' && field === '') quoted = true;
    else if (char === ',') {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      rows.push({ cells: row, line: rowLine });
      row = [];
      field = '';
      line += 1;
      rowLine = line;
    } else if (char !== '\r') field += char;
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    rows.push({ cells: row, line: rowLine });
  }
  return rows;
}

export function parseCsv(text: string, settings: TimeSettings): ParsedFile {
  const stats = newStats('csv');
  const events: Draft[] = [];
  const rows = csvRows(text.replace(/^\uFEFF/, '')).filter((row) => row.cells.some((cell) => cell.trim() !== ''));
  const header = rows[0]?.cells.map((cell) => cell.trim()) ?? [];
  for (const row of rows.slice(1)) {
    stats.read += 1;
    if (row.cells.length !== header.length) {
      unparsed(stats, row.line, row.cells.join(','));
      continue;
    }
    const fields: Record<string, string> = {};
    header.slice(0, MAX_FIELDS).forEach((name, index) => {
      if (name && name !== '__proto__') fields[name] = (row.cells[index] ?? '').slice(0, 1000);
    });
    if (!push(events, stats, recordToEvent(fields, row.line, 'csv', settings))) break;
  }
  return { events, stats };
}

// ── Windows Event XML ───────────────────────────────────────────────────────

export function parseWindowsXml(text: string): ParsedFile {
  const stats = newStats('windowsXml');
  const events: Draft[] = [];
  const source = text.replace(/^\uFEFF/, '');
  let record = 0;
  const handle = (element: import('./xml').XmlElement) => {
    if (element.name === 'Events') {
      element.children.forEach(handle);
      return;
    }
    if (element.name !== 'Event') return;
    record += 1;
    stats.read += 1;
    const system = child(element, 'System');
    const eventId = Number(child(system, 'EventID')?.text.trim());
    if (!system || !Number.isInteger(eventId)) {
      unparsed(stats, record, '<Event> without System/EventID');
      return;
    }
    const provider = child(system, 'Provider')?.attributes.Name ?? null;
    const systemTime = child(system, 'TimeCreated')?.attributes.SystemTime ?? '';
    const parsed = parseIso(systemTime, { endYear: 0, offsetMinutes: 0 });
    const data: Record<string, string> = {};
    const eventData = child(element, 'EventData') ?? child(element, 'UserData');
    let unnamed = 0;
    const collect = (node: import('./xml').XmlElement) => {
      for (const item of node.children) {
        if (Object.keys(data).length >= MAX_FIELDS) return;
        if (item.name === 'Data') data[item.attributes.Name ?? `Data${(unnamed += 1)}`] = item.text.trim().slice(0, 1000);
        else if (item.children.length > 0) collect(item);
        else data[item.name] = item.text.trim().slice(0, 1000);
      }
    };
    if (eventData) collect(eventData);
    const rendered = child(child(element, 'RenderingInfo'), 'Message')?.text.trim() ?? null;
    const classified = classifyWindows(eventId, provider, data);
    const computer = child(system, 'Computer')?.text.trim() ?? null;
    const channel = child(system, 'Channel')?.text.trim() ?? null;
    const summary = rendered ?? `${provider ?? 'Event'} ${eventId} ${Object.entries(data).map(([key, value]) => `${key}=${value}`).join(' ')}`;
    push(events, stats, event({
      line: record,
      format: 'windowsXml',
      timestamp: parsed && parsed.quality === 'exact' ? parsed.time : null,
      timeQuality: parsed && parsed.quality === 'exact' ? 'exact' : 'missing',
      host: computer,
      program: provider,
      message: summary,
      category: classified.category,
      user: classified.user,
      srcIp: classified.srcIp,
      windows: { eventId, provider, channel, computer, data },
      fields: { EventID: String(eventId), ...(provider ? { Provider_Name: provider } : {}), ...(channel ? { Channel: channel } : {}), ...(computer ? { Computer: computer } : {}), ...data },
    }));
  };
  try {
    parseXmlElements(source, (element) => handle(element));
  } catch (error) {
    const offset = error instanceof XmlError ? error.offset : 0;
    const lineNumber = source.slice(0, offset).split('\n').length;
    unparsed(stats, lineNumber, `${(error as Error).message}: ${source.slice(offset, offset + 120)}`);
  }
  return { events, stats };
}

export function parseText(text: string, format: LogFormat, settings: TimeSettings): ParsedFile {
  switch (format) {
    case 'json':
      return parseJson(text, settings);
    case 'csv':
      return parseCsv(text, settings);
    case 'syslog':
      return parseSyslog(text, settings);
    case 'webAccess':
      return parseWebAccess(text);
    case 'apacheError':
      return parseApacheError(text, settings);
    case 'nginxError':
      return parseNginxError(text, settings);
    case 'windowsXml':
      return parseWindowsXml(text);
  }
}
