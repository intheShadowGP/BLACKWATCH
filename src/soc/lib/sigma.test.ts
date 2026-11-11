import { describe, expect, it } from 'vitest';
import { sampleAccessLog, sampleAuthLog, sampleWindowsXml } from '../fixtures';
import type { LogEvent } from './model';
import { parseSyslog, parseWebAccess, parseWindowsXml } from './parsers';
import { evaluateSigma, globMatch } from './sigma';

const UTC = { endYear: 2026, offsetMinutes: 0 };
const index = (events: Omit<LogEvent, 'id' | 'file'>[], offset: number) => events.map((event, position) => ({ ...event, id: offset + position, file: 0 }));
const events: LogEvent[] = [
  ...index(parseWindowsXml(sampleWindowsXml()).events, 0),
  ...index(parseSyslog(sampleAuthLog(), UTC).events, 100),
  ...index(parseWebAccess(sampleAccessLog()).events, 1000),
];

// Rules below are written for these tests.
const rule = (body: string) => `title: Test rule\nlevel: high\n${body}`;

describe('globMatch', () => {
  it.each([
    ['*.exe', 'C:\\Windows\\cmd.EXE', true],
    ['adm?n', 'admin', true],
    ['a*b*c', 'axxbyyc', true],
    ['a*b*c', 'axxbyy', false],
    ['literal\\*star', 'literal*star', true],
    ['literal\\*star', 'literalXstar', false],
    ['*', '', true],
  ])('%s vs %s', (pattern, value, expected) => {
    expect(globMatch(pattern, value)).toBe(expected);
  });

  it('stays fast on adversarial patterns', () => {
    const started = performance.now();
    globMatch(`${'*a'.repeat(50)}b`, 'a'.repeat(5000));
    expect(performance.now() - started).toBeLessThan(1000);
  });
});

describe('evaluateSigma', () => {
  it('matches Windows events with field selections and EventID lists', async () => {
    const [outcome] = await evaluateSigma(rule('logsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID:\n      - 4625\n      - 4771\n    TargetUserName: Administrator\n  condition: selection'), events);
    expect(outcome).toMatchObject({ status: 'matched', candidates: 11 });
    expect(outcome?.status === 'matched' && outcome.eventIds).toHaveLength(8);
  });

  it('supports contains, startswith, endswith, all, keywords and boolean conditions', async () => {
    const outcomes = await evaluateSigma(
      [
        rule("logsource:\n  category: webserver\ndetection:\n  sel_uri:\n    cs-uri-query|contains: 'UNION'\n  sel_agent:\n    cs-user-agent|startswith: sqlmap\n  condition: all of sel_*"),
        rule("logsource:\n  category: webserver\ndetection:\n  sel:\n    cs-uri|contains|all:\n      - '../'\n      - passwd\n  filter:\n    sc-status: 200\n  condition: sel and not filter"),
        rule("logsource:\n  product: linux\n  service: auth\ndetection:\n  keywords:\n    - 'NOT in sudoers'\n  condition: keywords"),
        rule("logsource:\n  product: linux\ndetection:\n  a:\n    message|endswith: 'ssh2'\n  b:\n    message|contains: 'root'\n  condition: (a and b) or 1 of c*\n  c1:\n    message|contains: 'never-present'"),
      ].join('\n---\n'),
      events,
    );
    expect(outcomes.map((outcome) => outcome.status)).toEqual(['matched', 'matched', 'matched', 'matched']);
    expect(outcomes[0]?.status === 'matched' && outcomes[0].eventIds).toHaveLength(1);
  });

  it('reports no match, distinct from not applicable', async () => {
    const [noMatch] = await evaluateSigma(rule("logsource:\n  category: webserver\ndetection:\n  sel:\n    cs-uri-stem: '/does-not-exist'\n  condition: sel"), events);
    expect(noMatch).toMatchObject({ status: 'noMatch' });
    const [noSource] = await evaluateSigma(rule("logsource:\n  product: macos\ndetection:\n  sel:\n    x: y\n  condition: sel"), events);
    expect(noSource).toMatchObject({ status: 'notApplicable', reason: 'noLogsource' });
    const [noFields] = await evaluateSigma(rule("logsource:\n  product: windows\ndetection:\n  sel:\n    TargetFilename|endswith: '.exe'\n  condition: sel"), events);
    expect(noFields).toMatchObject({ status: 'notApplicable', reason: 'noFields', detail: 'TargetFilename' });
  });

  it.each([
    ["sel:\n    CommandLine|re: 'a.*b'\n  condition: sel", 'modifier "re"'],
    ["sel:\n    SourceIp|cidr: '10.0.0.0/8'\n  condition: sel", 'modifier "cidr"'],
    ["sel:\n    x: y\n  condition: sel | count() by SourceIp > 5", 'aggregation'],
    ["sel:\n    x: y\n  timeframe: 5m\n  condition: sel", 'timeframe'],
    ["sel:\n    x: y\n  condition: 2 of sel*", '"2 of" quantifier'],
    ["sel:\n    x: y\n  condition: other", 'unknown selection'],
  ])('rejects unsupported constructs without evaluating them (%#)', async (detection, reason) => {
    const [outcome] = await evaluateSigma(rule(`logsource:\n  product: windows\ndetection:\n  ${detection}`), events);
    expect(outcome?.status).toBe('unsupported');
    expect(outcome?.status === 'unsupported' && outcome.reason).toContain(reason);
  });

  it('reports invalid YAML and rules without detection', async () => {
    expect((await evaluateSigma('title: [broken', events))[0]?.status).toBe('invalid');
    expect((await evaluateSigma('title: x\nlogsource: {}', events))[0]?.status).toBe('invalid');
  });
});
