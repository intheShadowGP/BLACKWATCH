import { describe, expect, it } from 'vitest';
import { attack, kev, nvdKev, nvdRecent } from '../test/fixtures';
import { attackUrl, buildAttackIndex, kindOfAttackId, matchesQuery } from './attack';
import { csvCell, fileStamp, toCsv } from './export';
import { formatAge, formatDate } from './format';
import { bestCvss, filterRows, prioritize, toRow, type VulnRow } from './vulnerabilities';

const critical = nvdRecent.items[0]!;
const medium = nvdRecent.items[1]!;
const unscored = nvdRecent.items[2]!;
const kevCve = nvdKev.items[0]!;
const kevEntry = kev.items[0]!;

describe('prioritize', () => {
  it('puts KEV entries first and records ransomware use', () => {
    expect(prioritize(kevCve, kevEntry)).toEqual({ level: 1, factors: ['kev', 'ransomware', 'high', 'patchReference'] });
  });

  it('ranks by the highest published score otherwise', () => {
    expect(prioritize(critical, null).level).toBe(2);
    expect(prioritize({ ...critical, cvss3: { ...critical.cvss3!, score: 7 } }, null).level).toBe(3);
    expect(prioritize(medium, null)).toEqual({ level: 4, factors: ['medium'] });
    expect(prioritize({ ...critical, cvss3: { ...critical.cvss3!, score: 3.9 } }, null).level).toBe(5);
  });

  it('treats a missing score as unknown, not as a factor of safety', () => {
    expect(prioritize(unscored, null)).toEqual({ level: 5, factors: ['unscored'] });
    expect(prioritize(null, kev.items[1]!)).toEqual({ level: 1, factors: ['kev', 'unscored'] });
  });

  it('never claims a patch without a tagged reference', () => {
    expect(prioritize(medium, null).factors).not.toContain('patchReference');
  });
});

describe('bestCvss', () => {
  it('returns the highest score across CVSS versions', () => {
    expect(bestCvss(kevCve)?.version).toBe('4.0');
    expect(bestCvss(unscored)).toBeNull();
    expect(bestCvss(null)).toBeNull();
  });
});

describe('filterRows', () => {
  const rows = [toRow(critical, null), toRow(medium, null), toRow(unscored, null), toRow(kevCve, kevEntry), toRow(null, kev.items[1]!)].filter(
    (row): row is VulnRow => row !== null,
  );
  const ids = (list: VulnRow[]) => list.map((row) => row.id);

  it('returns null for a row without any record', () => {
    expect(toRow(null, null)).toBeNull();
  });

  it('searches ids, text, products and CWEs with every word required', () => {
    expect(ids(filterRows(rows, { text: 'cve-2026-10002', severity: 'all', sort: 'date' }))).toEqual(['CVE-2026-10002']);
    expect(ids(filterRows(rows, { text: 'othervendor injection', severity: 'all', sort: 'date' }))).toEqual(['CVE-2024-30001']);
    expect(ids(filterRows(rows, { text: 'CWE-269', severity: 'all', sort: 'date' }))).toEqual(['CVE-2025-20001']);
    expect(filterRows(rows, { text: 'examplevendor nomatch', severity: 'all', sort: 'date' })).toEqual([]);
  });

  it('filters by severity, including unscored records', () => {
    expect(ids(filterRows(rows, { text: '', severity: 'CRITICAL', sort: 'date' }))).toEqual(['CVE-2026-10001']);
    expect(ids(filterRows(rows, { text: '', severity: 'UNSCORED', sort: 'date' })).sort()).toEqual(['CVE-2024-30001', 'CVE-2026-10003']);
  });

  it('sorts by score and by priority', () => {
    expect(ids(filterRows(rows, { text: '', severity: 'all', sort: 'score' }))[0]).toBe('CVE-2026-10001');
    expect(ids(filterRows(rows, { text: '', severity: 'all', sort: 'priority' })).slice(0, 2)).toEqual(['CVE-2025-20001', 'CVE-2024-30001']);
  });

  it('treats regular expression characters in the query as plain text', () => {
    expect(filterRows(rows, { text: '.*(', severity: 'all', sort: 'date' })).toEqual([]);
  });
});

describe('CSV export', () => {
  it('quotes separators, quotes and line breaks', () => {
    expect(csvCell('a,b')).toBe('"a,b"');
    expect(csvCell('say "hi"')).toBe('"say ""hi"""');
    expect(csvCell('line\nbreak')).toBe('"line\nbreak"');
    expect(csvCell(null)).toBe('');
    expect(csvCell(9.8)).toBe('9.8');
  });

  it.each(['=HYPERLINK("http://evil.example","x")', '+1+1', '-2+3', '@SUM(A1)', '\tcmd', '\rcmd'])('neutralises the formula %j', (value) => {
    expect(csvCell(value).replace(/^"/, '').startsWith("'")).toBe(true);
  });

  it('builds a document with CRLF line endings', () => {
    expect(toCsv(['a', 'b'], [[1, 'x,y']])).toBe('a,b\r\n1,"x,y"\r\n');
  });

  it('builds file-system-safe stamps', () => {
    expect(fileStamp(new Date('2026-03-04T05:06:07.089Z'))).toBe('2026-03-04T05-06-07Z');
  });
});

describe('formatting', () => {
  it('formats dates in UTC and tolerates invalid input', () => {
    expect(formatDate('2026-01-05T23:30:00.000Z', 'en')).toBe('5 Jan 2026');
    expect(formatDate('2026-01-05T23:30:00.000Z', 'fr')).toBe('5 janv. 2026');
    expect(formatDate('not a date', 'en')).toBe('—');
    expect(formatDate(null, 'en')).toBe('—');
  });

  it('expresses dataset age in minutes, hours or days', () => {
    expect(formatAge(0.5, 'en')).toBe('30 minutes ago');
    expect(formatAge(5, 'en')).toBe('5 hours ago');
    expect(formatAge(72, 'en')).toBe('3 days ago');
    expect(formatAge(null, 'en')).toBe('—');
  });
});

describe('ATT&CK index', () => {
  const index = buildAttackIndex(attack);

  it('recognises identifier kinds', () => {
    expect(kindOfAttackId('T1059.001')).toBe('technique');
    expect(kindOfAttackId('TA0001')).toBe('tactic');
    expect(kindOfAttackId('DET0103')).toBe('detection');
    expect(kindOfAttackId('G0016')).toBe('group');
    expect(kindOfAttackId('../../etc/passwd')).toBeNull();
    expect(kindOfAttackId('T1059<script>')).toBeNull();
  });

  it('builds canonical MITRE URLs', () => {
    expect(attackUrl('T1059.001')).toBe('https://attack.mitre.org/techniques/T1059/001/');
    expect(attackUrl('G9001')).toBe('https://attack.mitre.org/groups/G9001/');
    expect(attackUrl('javascript:alert(1)')).toBeNull();
  });

  it('resolves relationships in both directions', () => {
    expect(index.related('groupTechnique', 'G9001')).toEqual(['T1059.001', 'T1566']);
    expect(index.relatedTo('groupTechnique', 'T1566')).toEqual(['G9001']);
    expect(index.relatedTo('mitigationTechnique', 'T1059')).toEqual(['M9001']);
    expect(index.related('campaignGroup', 'C9001')).toEqual(['G9001']);
  });

  it('drops relationships that point to unknown objects', () => {
    expect(index.related('groupTechnique', 'G9001')).not.toContain('T9999');
    expect(index.get('T9999')).toBeNull();
  });

  it('groups techniques by tactic and sub-techniques by parent', () => {
    expect(index.techniquesOfTactic('execution').map((technique) => technique.id)).toEqual(['T1059']);
    expect(index.subTechniques('T1059').map((technique) => technique.id)).toEqual(['T1059.001']);
    expect(index.techniquesOfTactic('unknown')).toEqual([]);
  });

  it('matches queries on any field, all words required', () => {
    expect(matchesQuery('power', 'T1059.001', 'PowerShell')).toBe(true);
    expect(matchesQuery('t1059 shell', 'T1059.001', 'PowerShell')).toBe(true);
    expect(matchesQuery('alias', 'G9001', 'Test Group', ['TG-Alias'])).toBe(true);
    expect(matchesQuery('nomatch', 'G9001', 'Test Group')).toBe(false);
    expect(matchesQuery('   ', 'anything')).toBe(true);
  });
});
