import { describe, expect, it } from 'vitest';
import { authLine, sampleAccessLog, sampleAuthLog, sampleWindowsXml } from '../fixtures';
import { classifyAuthMessage } from './classify';
import { csvRows, decodeText, detectBinary, detectFormat, parseCsv, parseJson, parseNginxError, parseApacheError, parseSyslog, parseWebAccess, parseWindowsXml, parseIso } from './parsers';
import { parseXmlElements } from './xml';

const UTC = { endYear: 2026, offsetMinutes: 0 };

describe('format detection', () => {
  it.each([
    [sampleAuthLog(), 'syslog'],
    [sampleAccessLog(), 'webAccess'],
    [sampleWindowsXml(), 'windowsXml'],
    ['{"a":1}\n{"a":2}\n', 'json'],
    ['[{"a":1}]', 'json'],
    ['time,user,action\n2026-01-01T00:00:00Z,alice,login\n', 'csv'],
    ['<34>1 2026-01-10T10:00:00Z host app 123 ID47 - message\n', 'syslog'],
    ['2026-01-10T10:00:00+01:00 host sshd[1]: Accepted password for a from 192.0.2.1 port 1 ssh2\n', 'syslog'],
    ['[Sat Jan 10 09:00:00.123456 2026] [core:error] [pid 42] [client 192.0.2.5:4000] AH00126: Invalid URI\n', 'apacheError'],
    ['2026/01/10 09:00:00 [error] 12#12: *3 open() failed, client: 192.0.2.6, server: x, request: "GET /x HTTP/1.1"\n', 'nginxError'],
    ['random words here\nnothing structured\n', null],
  ])('detects %#', (text, format) => {
    expect(detectFormat(text)).toBe(format);
  });

  it('recognises binary inputs instead of calling them unknown text', () => {
    expect(detectBinary(new Uint8Array([0x45, 0x6c, 0x66, 0x46, 0x69, 0x6c, 0x65, 0x00, 1]))).toBe('evtx');
    expect(detectBinary(new Uint8Array([0x1f, 0x8b, 8, 0]))).toBe('gzip');
    expect(detectBinary(new Uint8Array([0x41, 0x00, 0x42]))).toBe('binary');
    expect(detectBinary(new TextEncoder().encode('plain text'))).toBeNull();
    expect(detectBinary(new Uint8Array([0xff, 0xfe, 0x3c, 0x00]))).toBeNull();
  });

  it('decodes UTF-16 and UTF-8 with byte order marks', () => {
    const utf16 = new Uint8Array([0xff, 0xfe, ...[...'<Event>'].flatMap((char) => [char.charCodeAt(0), 0])]);
    expect(decodeText(utf16)).toBe('<Event>');
    expect(decodeText(new Uint8Array([0xef, 0xbb, 0xbf, 0x41]))).toBe('A');
  });
});

describe('timestamps', () => {
  it('parses ISO 8601 with any fraction and offset', () => {
    expect(parseIso('2026-11-11T09:03:15.5612994Z', UTC)).toEqual({ time: Date.parse('2026-11-11T09:03:15.561Z'), quality: 'exact' });
    expect(parseIso('2026-01-10T10:00:00+02:00', UTC)?.time).toBe(Date.parse('2026-01-10T08:00:00Z'));
    expect(parseIso('2026-01-10 10:00:00', { endYear: 2026, offsetMinutes: 60 })).toEqual({ time: Date.parse('2026-01-10T09:00:00Z'), quality: 'inferred' });
  });

  it.each(['2026-02-30T00:00:00Z', '2026-13-01T00:00:00Z', '2026-01-01T25:00:00Z', 'yesterday', ''])('rejects %j', (value) => {
    expect(parseIso(value, UTC)).toBeNull();
  });

  it('infers the year of classic syslog lines and handles the December to January rollover', () => {
    const text = [authLine('Dec', 31, 23 * 3600 + 3599, 'sshd', 'x'), authLine('Jan', 1, 5, 'sshd', 'y')].join('\n');
    const { events, stats } = parseSyslog(text, { endYear: 2026, offsetMinutes: 0 });
    expect(stats.yearRollovers).toBe(1);
    expect(events.map((event) => new Date(event.timestamp as number).toISOString())).toEqual(['2025-12-31T23:59:59.000Z', '2026-01-01T00:00:05.000Z']);
    expect(events.every((event) => event.timeQuality === 'inferred')).toBe(true);
  });

  it('applies the configured offset to times without a zone', () => {
    const { events } = parseSyslog(authLine('Jan', 10, 10 * 3600, 'sshd', 'x'), { endYear: 2026, offsetMinutes: 120 });
    expect(new Date(events[0]?.timestamp as number).toISOString()).toBe('2026-01-10T08:00:00.000Z');
  });

  it('keeps events with an impossible date and marks their time as missing', () => {
    const { events, stats } = parseSyslog('Feb 30 10:00:00 host sshd[1]: something', UTC);
    expect(events).toHaveLength(1);
    expect(events[0]?.timeQuality).toBe('missing');
    expect(stats.timestamps.missing).toBe(1);
  });
});

describe('SSH and auth classification', () => {
  it('counts one attempt per Failed line and N for "message repeated N times"', () => {
    const { events } = parseSyslog(sampleAuthLog(), UTC);
    const failures = events.filter((event) => event.category === 'authFailure');
    expect(failures.reduce((sum, event) => sum + event.count, 0)).toBe(15);
    expect(events.filter((event) => event.category === 'authInfo' && event.srcIp === '203.0.113.50').length).toBe(12);
    expect(failures[0]).toMatchObject({ user: 'user0', srcIp: '203.0.113.50', fields: { invalidUser: 'true', method: 'password' } });
  });

  it('classifies sudo, su and account changes', () => {
    const { events, stats } = parseSyslog(sampleAuthLog(), UTC);
    const by = (category: string) => events.filter((event) => event.category === category);
    expect(by('sudoNotAllowed')[0]).toMatchObject({ user: 'bob', fields: { targetUser: 'root', command: '/bin/bash' } });
    expect(by('sudoCommand')).toHaveLength(2);
    expect(by('suFailure')[0]).toMatchObject({ user: 'bob', fields: { targetUser: 'root' } });
    expect(by('accountCreated')[0]?.user).toBe('svc-backup');
    expect(by('groupMemberAdded')[0]).toMatchObject({ user: 'svc-backup', fields: { group: 'sudo' } });
    expect(by('authSuccess').map((event) => event.user)).toEqual(['alice', 'root']);
    expect(stats.unparsed).toBe(1);
    expect(stats.unparsedSamples[0]?.text).toBe('this line is not syslog');
  });

  it('counts sudo password attempts', () => {
    expect(classifyAuthMessage('sudo', 'bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/ls')).toMatchObject({ category: 'sudoFailure', count: 3, user: 'bob' });
  });

  it('extracts IPv6 sources', () => {
    expect(classifyAuthMessage('sshd', 'Failed password for root from 2001:db8::7 port 22 ssh2')).toMatchObject({ category: 'authFailure', srcIp: '2001:db8::7' });
  });
});

describe('web access logs', () => {
  it('parses combined lines and keeps malformed scanner requests', () => {
    const { events, stats } = parseWebAccess(sampleAccessLog());
    expect(stats.unparsed).toBe(0);
    expect(events[0]).toMatchObject({ srcIp: '198.51.100.20', http: { method: 'GET', path: '/', status: 200, bytes: 5120, userAgent: 'Mozilla/5.0 (X11; Linux x86_64)', malformed: false } });
    expect(new Date(events[0]?.timestamp as number).toISOString()).toBe('2026-01-10T09:00:00.000Z');
    const binary = events.find((event) => event.srcIp === '203.0.113.79');
    expect(binary?.http).toMatchObject({ method: null, malformed: true, status: 400 });
  });

  it('parses the common format and converts offsets', () => {
    const { events } = parseWebAccess('192.0.2.9 - frank [10/Oct/2000:13:55:36 -0700] "GET /a.gif HTTP/1.0" 200 2326');
    expect(events[0]).toMatchObject({ user: 'frank', http: { referrer: null, userAgent: null } });
    expect(new Date(events[0]?.timestamp as number).toISOString()).toBe('2000-10-10T20:55:36.000Z');
  });
});

describe('error logs', () => {
  it('parses Apache and Nginx error lines', () => {
    const apache = parseApacheError('[Sat Jan 10 09:00:00.123456 2026] [core:error] [pid 42:tid 7] [client 192.0.2.5:4000] AH00126: Invalid URI', UTC);
    expect(apache.events[0]).toMatchObject({ srcIp: '192.0.2.5', program: 'core', fields: { level: 'error', pid: '42' }, timeQuality: 'inferred' });
    const nginx = parseNginxError('2026/01/10 09:00:00 [error] 12#12: *3 open() "/x" failed, client: 192.0.2.6, server: x, request: "GET /x HTTP/1.1"', UTC);
    expect(nginx.events[0]).toMatchObject({ srcIp: '192.0.2.6', fields: { level: 'error', request: 'GET /x HTTP/1.1' } });
  });
});

describe('JSON and CSV', () => {
  it('reads NDJSON, including journald exports, and counts invalid lines', () => {
    const text = [
      JSON.stringify({ __REALTIME_TIMESTAMP: '1768039200000000', _HOSTNAME: 'bastion', SYSLOG_IDENTIFIER: 'sshd', MESSAGE: 'Failed password for root from 192.0.2.3 port 22 ssh2' }),
      '{broken',
      JSON.stringify({ '@timestamp': '2026-01-10T10:00:00Z', message: 'hello', source: { ip: '198.51.100.4' }, user: { name: 'eve' } }),
      '[1,2]',
    ].join('\n');
    const { events, stats } = parseJson(text, UTC);
    expect(stats).toMatchObject({ read: 4, parsed: 2, unparsed: 2 });
    expect(events[0]).toMatchObject({ host: 'bastion', program: 'sshd', category: 'authFailure', srcIp: '192.0.2.3', user: 'root', timeQuality: 'exact' });
    expect(new Date(events[0]?.timestamp as number).toISOString()).toBe('2026-01-10T10:00:00.000Z');
    expect(events[1]).toMatchObject({ srcIp: '198.51.100.4', user: 'eve', fields: { 'source.ip': '198.51.100.4' } });
  });

  it('reads a JSON array and rejects a malformed one as a whole', () => {
    expect(parseJson('[{"msg":"a"},{"msg":"b"}, 3]', UTC).stats).toMatchObject({ parsed: 2, unparsed: 1 });
    expect(parseJson('[{"msg":"a"},', UTC).stats).toMatchObject({ parsed: 0, unparsed: 1 });
  });

  it('ignores prototype keys in records', () => {
    const { events } = parseJson('{"__proto__": {"polluted": "yes"}, "msg": "x"}', UTC);
    expect(events[0]?.fields).toEqual({ msg: 'x' });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('reads CSV with quoted fields spanning lines and reports ragged rows', () => {
    const text = 'timestamp,user,message,src_ip\n2026-01-10T10:00:00Z,alice,"multi\nline, with comma",192.0.2.1\n2026-01-10T10:01:00Z,bob\n2026-01-10T10:02:00Z,carol,"say ""hi""",192.0.2.2\n';
    expect(csvRows(text)[1]).toEqual({ cells: ['2026-01-10T10:00:00Z', 'alice', 'multi\nline, with comma', '192.0.2.1'], line: 2 });
    const { events, stats } = parseCsv(text, UTC);
    expect(stats).toMatchObject({ read: 3, parsed: 2, unparsed: 1 });
    expect(stats.unparsedSamples[0]?.line).toBe(4);
    expect(events[1]).toMatchObject({ user: 'carol', srcIp: '192.0.2.2', message: 'say "hi"', line: 5 });
  });
});

describe('Windows Event XML', () => {
  it('reads an <Events> export with seven-digit fractions', () => {
    const { events, stats } = parseWindowsXml(sampleWindowsXml());
    expect(stats).toMatchObject({ read: 11, parsed: 11, unparsed: 0 });
    expect(events[0]).toMatchObject({ category: 'authFailure', user: 'administrator', srcIp: '192.0.2.44', host: 'WS01.corp.example', windows: { eventId: 4625 } });
    expect(new Date(events[0]?.timestamp as number).toISOString()).toBe('2026-01-10T10:00:00.123Z');
    expect(events.map((event) => event.category).slice(8)).toEqual(['authSuccess', 'groupMemberAdded', 'logCleared']);
    expect(events[9]?.user).toBe('CN=helpdesk,OU=Users,DC=corp,DC=example');
  });

  it('reads several <Event> roots without a wrapper', () => {
    const roots = sampleWindowsXml().split('\n').filter((line) => line.startsWith('<Event ')).slice(0, 2).join('\n');
    expect(parseWindowsXml(roots).stats).toMatchObject({ parsed: 2, unparsed: 0 });
  });

  it('refuses entity declarations and reports malformed documents', () => {
    const bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><Event><System><EventID>1</EventID></System></Event>';
    const result = parseWindowsXml(bomb);
    expect(result.stats.parsed).toBe(0);
    expect(result.stats.unparsedSamples[0]?.text).toContain('not accepted');
    const broken = parseWindowsXml(`${sampleWindowsXml().slice(0, 900)}`);
    expect(broken.stats.unparsed).toBe(1);
  });

  it('decodes entities and CDATA without interpreting markup', () => {
    const elements: string[] = [];
    parseXmlElements("<a x='1 &amp; 2'>&lt;b&gt; <![CDATA[<c>]]>&#65;</a>", (element) => elements.push(`${element.attributes.x}|${element.text}`));
    expect(elements).toEqual(['1 & 2|<b> <c>A']);
  });
});
