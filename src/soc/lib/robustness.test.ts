import { afterEach, describe, expect, it, vi } from 'vitest';
import { sampleAuthLog } from '../fixtures';
import { classifyAuthMessage } from './classify';
import { runDetections } from './detections';
import type { LogEvent } from './model';
import { parseJson, parseSyslog } from './parsers';

const UTC = { endYear: 2026, offsetMinutes: 0 };
const T0 = Date.parse('2026-01-10T10:00:00Z');

describe('source attribution cannot be forged through the user name', () => {
  it.each([
    ['Failed password for invalid user x from 192.0.2.1 port 1 from 203.0.113.9 port 51515 ssh2', 'authFailure', 'x from 192.0.2.1 port 1', '203.0.113.9'],
    ['Accepted password for a from 192.0.2.1 port 1 from 198.51.100.7 port 2222 ssh2', 'authSuccess', 'a from 192.0.2.1 port 1', '198.51.100.7'],
    ['Invalid user y from 192.0.2.1 port 9 from 203.0.113.10 port 4000', 'authInvalidUser', 'y from 192.0.2.1 port 9', '203.0.113.10'],
    ['Accepted publickey for alice from 198.51.100.10 port 50122 ssh2: ED25519 SHA256:abc', 'authSuccess', 'alice', '198.51.100.10'],
  ])('%s', (message, category, user, ip) => {
    expect(classifyAuthMessage('sshd', message)).toMatchObject({ category, user, srcIp: ip });
  });
});

describe('journald JSON and syslog text give the same findings', () => {
  it('produces identical rule hits for the sample auth log in both forms', () => {
    const syslog = parseSyslog(sampleAuthLog(), UTC).events;
    const journald = syslog
      .filter((event) => event.program !== null)
      .map((event) => {
        const message = / bastion [^:]+: (.*)$/.exec(event.message)?.[1] ?? '';
        return JSON.stringify({ __REALTIME_TIMESTAMP: String((event.timestamp as number) * 1000), _HOSTNAME: 'bastion', SYSLOG_IDENTIFIER: event.program, MESSAGE: message });
      })
      .join('\n');
    const fromJson = parseJson(journald, UTC).events;
    const number = (events: Omit<LogEvent, 'id' | 'file'>[]) => events.map((event, index) => ({ ...event, id: index, file: 0 }));
    const summary = (events: LogEvent[]) => runDetections(events).findings.map((finding) => `${finding.rule}|${finding.entity.value}|${finding.count}`).sort();
    expect(summary(number(fromJson))).toEqual(summary(number(syslog)));
    expect(summary(number(fromJson)).some((entry) => entry.startsWith('rootLogin'))).toBe(true);
    expect(summary(number(fromJson)).some((entry) => entry.startsWith('privilegeEscalation'))).toBe(true);
  });
});

describe('detections at attack scale', () => {
  const make = (count: number, build: (index: number) => Partial<LogEvent>): LogEvent[] =>
    Array.from({ length: count }, (_, index) => ({
      id: index,
      file: 0,
      line: index + 1,
      timestamp: T0 + index * 10,
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
      fields: { service: 'ssh' },
      ...build(index),
    }));

  it('handles 300,000 failures from one address with rotating accounts and thousands of successes', () => {
    const events = make(303_000, (index) =>
      index % 101 === 100
        ? { category: 'authSuccess', srcIp: '203.0.113.66', user: `user${index % 5000}` }
        : { category: 'authFailure', srcIp: '203.0.113.66', user: `user${index % 5000}` },
    );
    const started = performance.now();
    const result = runDetections(events);
    const elapsed = performance.now() - started;
    expect(elapsed).toBeLessThan(15_000);
    const brute = result.findings.find((finding) => finding.rule === 'remoteBruteForce');
    expect(brute?.count).toBeGreaterThan(290_000);
    expect(brute?.first).toBe(T0);
    expect(result.findings.some((finding) => finding.rule === 'passwordSpraying')).toBe(true);
    const after = result.findings.filter((finding) => finding.rule === 'successAfterFailures');
    expect(after.length).toBeGreaterThan(2000);
    expect(after.every((finding) => finding.eventIds.length <= 401)).toBe(true);
  });

  it('handles 300,000 matching web requests from one address', () => {
    const events = make(300_000, () => ({ category: 'httpRequest', format: 'webAccess', srcIp: '203.0.113.67', http: { method: 'GET', path: '/x?f=../../etc/passwd', protocol: 'HTTP/1.1', status: 404, bytes: 0, referrer: null, userAgent: 'curl', malformed: false } }));
    const started = performance.now();
    const result = runDetections(events);
    expect(performance.now() - started).toBeLessThan(15_000);
    expect(result.findings.find((finding) => finding.rule === 'suspiciousWebRequest')?.eventIds).toHaveLength(300_000);
    expect(result.findings.some((finding) => finding.rule === 'webScanning')).toBe(true);
    expect(result.findings.some((finding) => finding.rule === 'requestBurst')).toBe(true);
  });
});

describe('analysis requests are matched to their replies', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it('delivers each reply to the request that asked for it, even out of order', async () => {
    // A fake worker that answers the second request before the first.
    class FakeWorker {
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: (() => void) | null = null;
      private queue: { id: number; offset: number }[] = [];
      postMessage(message: { id: number; settings: { offsetMinutes: number } }) {
        this.queue.push({ id: message.id, offset: message.settings.offsetMinutes });
        if (this.queue.length === 2) {
          for (const item of [...this.queue].reverse()) {
            setTimeout(() => this.onmessage?.({ data: { id: item.id, kind: 'analysis', result: { settings: { endYear: 2026, offsetMinutes: item.offset } } } } as MessageEvent), 0);
          }
        }
      }
      terminate() {}
    }
    vi.stubGlobal('Worker', FakeWorker);
    const { analyzeFiles } = await import('../client');
    const [first, second] = await Promise.all([
      analyzeFiles([], { endYear: 2026, offsetMinutes: 60 }, {}),
      analyzeFiles([], { endYear: 2026, offsetMinutes: 120 }, {}),
    ]);
    expect(first.settings.offsetMinutes).toBe(60);
    expect(second.settings.offsetMinutes).toBe(120);
  });
});
