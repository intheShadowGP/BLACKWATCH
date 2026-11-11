// Investigation report export. Log content is attacker-controlled, so reports
// are Markdown with excerpts in code fences longer than any backtick run in
// the excerpt (the fence cannot be closed from inside), and CSV goes through
// the formula-neutralising cell encoder. No HTML is produced.

import { toCsv } from '../../lib/export';
import { RULES, type Finding } from './detections';
import type { AnalysisResult } from './analysis';
import type { LogEvent } from './model';

export function fence(text: string): string {
  const longest = Math.max(0, ...(text.match(/`+/g) ?? []).map((run) => run.length));
  const marker = '`'.repeat(Math.max(3, longest + 1));
  return `${marker}text\n${text}\n${marker}`;
}

/** Inline text for Markdown: escapes characters with Markdown meaning and removes line breaks. */
export function inline(text: string): string {
  return text.replace(/[\r\n]+/g, ' ').replace(/([\\`*_[\]{}()#+\-.!|<>~])/g, '\\$1').slice(0, 500);
}

const iso = (time: number | null) => (time === null ? 'n/a' : new Date(time).toISOString());

export interface ReportLabels {
  rule: (id: Finding['rule']) => string;
  format: (format: string) => string;
}

export interface ReportInput {
  title: string;
  notes: string;
  result: AnalysisResult;
  flagged: ReadonlySet<number>;
  labels: ReportLabels;
  generatedAt?: Date;
}

export function buildMarkdownReport({ title, notes, result, flagged, labels, generatedAt = new Date() }: ReportInput): string {
  const byId = new Map(result.events.map((event) => [event.id, event]));
  const offset = result.settings.offsetMinutes;
  const zone = `UTC${offset >= 0 ? '+' : '-'}${String(Math.floor(Math.abs(offset) / 60)).padStart(2, '0')}:${String(Math.abs(offset) % 60).padStart(2, '0')}`;
  const out: string[] = [];
  out.push(`# ${inline(title || 'Investigation report')}`, '');
  out.push(`Generated ${generatedAt.toISOString()} by BLACKWATCH (local analysis). Analysis run ${result.analysedAt}.`, '');
  out.push('## Time assumptions', '');
  out.push(`- Timestamps without a time zone were read as ${zone}.`);
  out.push(`- Timestamps without a year (classic syslog) were dated so that the last line falls in ${result.settings.endYear}.`);
  out.push('- Events without a readable timestamp are excluded from time-window rules.', '');
  out.push('## Sources', '');
  out.push('| File | Size (bytes) | SHA-256 | Format | Read | Parsed | Unparsed | Exact / inferred / missing times |');
  out.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
  for (const file of result.files) {
    const stats = file.stats;
    out.push(`| ${inline(file.name)} | ${file.size} | ${file.sha256 ?? 'n/a'} | ${file.format ? labels.format(file.format) : inline(file.status)} | ${stats?.read ?? 0} | ${stats?.parsed ?? 0} | ${stats?.unparsed ?? 0} | ${stats ? `${stats.timestamps.exact} / ${stats.timestamps.inferred} / ${stats.timestamps.missing}` : 'n/a'} |`);
  }
  if (result.truncated) out.push('', `Note: the event limit was reached; later events were not analysed.`);
  out.push('', `## Findings (${result.detections.findings.length})`, '');
  for (const finding of result.detections.findings) {
    const rule = RULES.find((candidate) => candidate.id === finding.rule);
    out.push(`### ${inline(labels.rule(finding.rule))} — ${inline(finding.entity.value)}`, '');
    out.push(`- Severity: ${finding.severity}`);
    out.push(`- Period: ${iso(finding.first)} to ${iso(finding.last)}`);
    out.push(`- Occurrences: ${finding.count} (events: ${finding.eventIds.length})`);
    if (rule && Object.keys(rule.params).length > 0) out.push(`- Rule parameters: ${Object.entries(rule.params).map(([key, value]) => `${key}=${value}`).join(', ')}`);
    if (rule && rule.techniques.length > 0) out.push(`- ATT&CK: ${rule.techniques.join(', ')}`);
    const details = Object.entries(finding.detail).map(([key, value]) => `${key}=${String(value)}`).join(', ');
    if (details) out.push(`- Details: ${inline(details)}`);
    const excerpt = finding.eventIds.slice(0, 10).map((id) => byId.get(id)?.message ?? '').join('\n');
    out.push('', fence(excerpt), '');
    if (finding.eventIds.length > 10) out.push(`(${finding.eventIds.length - 10} more events not shown)`, '');
  }
  const excluded = Object.entries(result.detections.excludedWithoutTime);
  if (excluded.length > 0) {
    out.push('## Events excluded from time-window rules', '');
    for (const [rule, count] of excluded) out.push(`- ${inline(labels.rule(rule as Finding['rule']))}: ${count} events without a usable timestamp`);
    out.push('');
  }
  if (flagged.size > 0) {
    out.push(`## Flagged events (${flagged.size})`, '');
    const lines = [...flagged].map((id) => byId.get(id)).filter((event): event is LogEvent => event !== undefined).slice(0, 200).map((event) => `[${iso(event.timestamp)}] ${event.message}`);
    out.push(fence(lines.join('\n')), '');
  }
  if (notes.trim()) out.push('## Analyst notes', '', fence(notes.trim()), '');
  out.push('---', 'Detections are heuristics: verify every finding against the source logs before acting on it.', '');
  return out.join('\n');
}

export function eventsToCsv(events: readonly LogEvent[], fileNames: readonly string[]): string {
  return toCsv(
    ['id', 'file', 'line', 'timestamp_utc', 'time_quality', 'category', 'host', 'program', 'user', 'source_ip', 'count', 'http_method', 'http_path', 'http_status', 'windows_event_id', 'message'],
    events.map((event) => [
      event.id,
      fileNames[event.file] ?? '',
      event.line,
      event.timestamp === null ? '' : new Date(event.timestamp).toISOString(),
      event.timeQuality,
      event.category,
      event.host ?? '',
      event.program ?? '',
      event.user ?? '',
      event.srcIp ?? '',
      event.count,
      event.http?.method ?? '',
      event.http?.path ?? '',
      event.http?.status ?? '',
      event.windows?.eventId ?? '',
      event.message,
    ]),
  );
}
