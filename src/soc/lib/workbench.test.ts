import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BlackwatchDb } from '../../lib/db';
import { sampleAccessLog, sampleAuthLog, sampleWindowsXml } from '../fixtures';
import { analyzeInputs, type AnalysisResult } from './analysis';
import { deleteInvestigation, listInvestigations, loadInvestigation, MAX_SAVED_EVENTS, saveInvestigation } from './investigations';
import { buildMarkdownReport, eventsToCsv, fence, inline } from './report';

const UTC = { endYear: 2026, offsetMinutes: 0 };
const input = (name: string, content: string | Uint8Array) => {
  const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
  return { name, size: bytes.length, lastModified: 0, bytes };
};

describe('analyzeInputs', () => {
  it('parses several formats, numbers events globally and reports each file', async () => {
    const result = await analyzeInputs(
      [input('auth.log', sampleAuthLog()), input('access.log', sampleAccessLog()), input('security.xml', sampleWindowsXml()), input('empty.log', ''), input('archive.gz', new Uint8Array([0x1f, 0x8b, 8, 0])), input('notes.txt', 'just words\nnothing else\n')],
      UTC,
    );
    expect(result.files.map((file) => [file.name, file.status, file.format])).toEqual([
      ['auth.log', 'parsed', 'syslog'],
      ['access.log', 'parsed', 'webAccess'],
      ['security.xml', 'parsed', 'windowsXml'],
      ['empty.log', 'empty', null],
      ['archive.gz', 'binary', null],
      ['notes.txt', 'unknownFormat', null],
    ]);
    expect(result.files[4]?.binary).toBe('gzip');
    expect(result.files[0]?.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.events.map((event) => event.id)).toEqual(result.events.map((_, index) => index));
    expect(new Set(result.events.map((event) => event.file))).toEqual(new Set([0, 1, 2]));
    expect(result.detections.findings.length).toBeGreaterThan(0);
  });

  it('applies a manual format override', async () => {
    const result = await analyzeInputs([input('notes.txt', 'just words\nnothing else\n')], UTC, { 0: 'syslog' });
    expect(result.files[0]).toMatchObject({ status: 'parsed', format: 'syslog', detectedFormat: null, stats: { read: 2, parsed: 0, unparsed: 2 } });
  });

  it('refuses files above the size limit without reading them', async () => {
    const result = await analyzeInputs([{ name: 'huge.log', size: 200 * 1024 * 1024, lastModified: 0, bytes: null }], UTC);
    expect(result.files[0]?.status).toBe('tooLarge');
  });
});

describe('report', () => {
  it('builds fences longer than any backtick run in the content', () => {
    expect(fence('plain')).toBe('```text\nplain\n```');
    const hostile = 'a ```` b\n```\n# heading';
    const fenced = fence(hostile);
    expect(fenced.startsWith('`````text\n')).toBe(true);
    expect(fenced.endsWith('\n`````')).toBe(true);
  });

  it('escapes Markdown and removes line breaks in inline text', () => {
    expect(inline('<img src=x> **bold** [link](javascript:x)\n# title')).toBe('\\<img src=x\\> \\*\\*bold\\*\\* \\[link\\]\\(javascript:x\\) \\# title');
  });

  it('documents the time assumptions, sources and findings', async () => {
    const result = await analyzeInputs([input('auth.log', sampleAuthLog())], { endYear: 2026, offsetMinutes: -300 });
    const report = buildMarkdownReport({ title: 'Case', notes: 'Analyst ```note```', result, flagged: new Set([0]), labels: { rule: (id) => id, format: (format) => format }, generatedAt: new Date('2026-01-11T00:00:00Z') });
    expect(report).toContain('read as UTC-05:00');
    expect(report).toContain('last line falls in 2026');
    expect(report).toContain(result.files[0]?.sha256 as string);
    expect(report).toContain('### remoteBruteForce');
    expect(report).toContain('Rule parameters: threshold=10, windowMinutes=5');
    expect(report).toContain('````text\nAnalyst ```note```\n````');
    expect(report).not.toContain('<');
  });

  it('exports events as CSV with formula neutralisation', async () => {
    const result = await analyzeInputs([input('a.json', '{"message":"=HYPERLINK(\\"http://x\\")","user":"+alice"}')], UTC);
    const csv = eventsToCsv(result.events, ['a.json']);
    expect(csv).toContain(`"'=HYPERLINK(""http://x"")"`);
    expect(csv).toContain("'+alice");
  });
});

describe('investigations', () => {
  let database: BlackwatchDb;
  let result: AnalysisResult;
  let sequence = 0;

  beforeEach(async () => {
    sequence += 1;
    database = new BlackwatchDb(`blackwatch-investigations-${sequence}`);
    result = await analyzeInputs([input('auth.log', sampleAuthLog())], UTC);
  });

  afterEach(async () => {
    await database.delete();
  });

  it('saves, lists, loads and deletes an investigation', async () => {
    const saved = await saveInvestigation({ version: 1, title: 'Case 1', notes: 'n', flagged: [1, 2], result }, undefined, database);
    expect(saved.ok).toBe(true);
    const id = saved.ok ? saved.id : '';
    expect(await listInvestigations(database)).toEqual([expect.objectContaining({ id, title: 'Case 1', events: result.events.length, findings: result.detections.findings.length })]);
    const loaded = await loadInvestigation(id, database);
    expect(loaded?.result.events).toHaveLength(result.events.length);
    expect(loaded?.flagged).toEqual([1, 2]);
    await deleteInvestigation(id, database);
    expect(await listInvestigations(database)).toEqual([]);
  });

  it('refuses investigations above the tested size', async () => {
    const big = { ...result, events: new Array(MAX_SAVED_EVENTS + 1).fill(result.events[0]) };
    expect(await saveInvestigation({ version: 1, title: 'big', notes: '', flagged: [], result: big }, undefined, database)).toEqual({ ok: false, reason: 'tooLarge' });
  });

  it('rejects a corrupted record on load', async () => {
    await database.investigations.put({ id: 'bad', title: 'bad', data: { version: 1, title: 'x', notes: '', flagged: [], result: { events: 'nope' } }, updatedAt: 'x' });
    expect(await loadInvestigation('bad', database)).toBeNull();
    expect(await loadInvestigation('missing', database)).toBeNull();
  });
});
