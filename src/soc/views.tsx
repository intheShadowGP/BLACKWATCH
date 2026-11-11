import { useEffect, useId, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useI18n } from '../app/preferences-context';
import { EmptyState, Pagination, SelectField, Tag, TextField, paginate } from '../components/data';
import { ConfirmDialog } from '../components/Modal';
import { Button, Panel } from '../components/ui';
import type { MessageKey } from '../i18n';
import { downloadText, fileStamp } from '../lib/export';
import { formatDateTime } from '../lib/format';
import { classifyIpv4, classifyIpv6, parseIpv4, parseIpv6 } from '../lib/ioc';
import { formatBytes } from '../toolbox/ui';
import { RULES, type Finding, type RuleId, type Severity } from './lib/detections';
import { deleteInvestigation, listInvestigations, loadInvestigation, MAX_SAVED_EVENTS, saveInvestigation, type InvestigationSummary } from './lib/investigations';
import { LOG_FORMATS, MAX_EVENTS, MAX_FILE_BYTES, type EventCategory, type LogEvent, type LogFormat } from './lib/model';
import { buildMarkdownReport, eventsToCsv } from './lib/report';
import { useSoc } from './SocContext';

const SEVERITY_TONE: Record<Severity, 'alert' | 'gold' | 'neutral'> = { high: 'alert', medium: 'gold', low: 'neutral' };
const utc = (time: number | null) => (time === null ? '—' : new Date(time).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z'));

export function zoneLabel(offsetMinutes: number): string {
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absolute = Math.abs(offsetMinutes);
  return `UTC${sign}${String(Math.floor(absolute / 60)).padStart(2, '0')}:${String(absolute % 60).padStart(2, '0')}`;
}

// ── Import ──────────────────────────────────────────────────────────────────

export function ImportPanel() {
  const { t, language } = useI18n();
  const soc = useSoc();
  const inputId = useId();
  const [confirming, setConfirming] = useState(false);
  const loadSamples = async () => {
    const { sampleAccessLog, sampleAuthLog, sampleWindowsXml } = await import('./fixtures');
    const lastModified = Date.parse('2026-01-10T12:00:00Z');
    soc.importFiles([
      new File([sampleAuthLog()], 'sample-auth.log', { type: 'text/plain', lastModified }),
      new File([sampleAccessLog()], 'sample-access.log', { type: 'text/plain', lastModified }),
      new File([sampleWindowsXml()], 'sample-security.xml', { type: 'application/xml', lastModified }),
    ]);
  };
  return (
    <Panel title={t('soc.import')}>
      <p className="text-sm text-muted">{t('soc.importHelp')}</p>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <label htmlFor={inputId} className="inline-flex min-h-9 cursor-pointer items-center rounded-sm border border-accent-fill bg-accent-fill px-3 text-sm font-medium text-on-accent hover:brightness-110 has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-gold">
          {t('soc.import')}
          <input
            id={inputId}
            type="file"
            multiple
            className="sr-only"
            onChange={(event) => {
              const files = [...(event.target.files ?? [])].slice(0, 50);
              event.target.value = '';
              if (files.length > 0) soc.importFiles(files);
            }}
          />
        </label>
        <Button onClick={() => void loadSamples()}>{t('soc.loadSamples')}</Button>
        <Button variant="ghost" onClick={() => setConfirming(true)} disabled={soc.status === 'idle'}>
          {t('soc.clear')}
        </Button>
      </div>
      <p className="mt-2 text-xs text-subtle">{t('soc.limits', { size: formatBytes(MAX_FILE_BYTES, language), events: MAX_EVENTS.toLocaleString(language === 'fr' ? 'fr-FR' : 'en-GB') })}</p>
      <ConfirmDialog
        open={confirming}
        title={t('soc.clearConfirmTitle')}
        body={t('soc.clearConfirmBody')}
        confirmLabel={t('soc.clear')}
        onCancel={() => setConfirming(false)}
        onConfirm={() => {
          setConfirming(false);
          soc.clear();
        }}
      />
    </Panel>
  );
}

const OFFSETS = Array.from({ length: (14 + 12) * 4 + 1 }, (_, index) => -12 * 60 + index * 15).filter((minutes) => minutes % 60 === 0 || [-570, -210, 210, 270, 330, 345, 390, 525, 570, 630, 765, 825].includes(minutes));

export function TimeSettingsPanel() {
  const { t } = useI18n();
  const soc = useSoc();
  const yearId = useId();
  const currentYear = new Date().getUTCFullYear();
  return (
    <Panel title={t('soc.time.title')}>
      <p className="text-sm text-muted">{t('soc.time.help')}</p>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <div>
          <label htmlFor={yearId} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
            {t('soc.time.year')}
          </label>
          <select
            id={yearId}
            value={soc.settings.endYear}
            disabled={soc.fromSaved}
            onChange={(event) => soc.setSettings({ ...soc.settings, endYear: Number(event.target.value) })}
            className="min-h-9 w-full rounded-sm border border-line-strong bg-bg px-2.5 text-sm text-fg"
          >
            {Array.from({ length: 12 }, (_, index) => currentYear + 1 - index).map((year) => (
              <option key={year} value={year}>{year}</option>
            ))}
          </select>
        </div>
        <SelectField
          label={t('soc.time.offset')}
          value={String(soc.settings.offsetMinutes)}
          onChange={(value) => soc.setSettings({ ...soc.settings, offsetMinutes: Number(value) })}
          options={OFFSETS.map((minutes) => ({ value: String(minutes), label: zoneLabel(minutes) }))}
        />
      </div>
      <p className="mt-3 text-xs text-gold">{t('soc.time.current', { zone: zoneLabel(soc.settings.offsetMinutes), year: soc.settings.endYear })}</p>
    </Panel>
  );
}

export function FilesPanel() {
  const { t, language } = useI18n();
  const soc = useSoc();
  const result = soc.result;
  if (!result) return null;
  return (
    <Panel title={t('soc.files.title')}>
      {soc.fromSaved ? <p className="mb-3 text-sm text-gold">{t('soc.inv.fromSaved')}</p> : null}
      {result.truncated ? <p className="mb-3 text-sm text-accent">{t('soc.files.truncated', { n: MAX_EVENTS.toLocaleString(language) })}</p> : null}
      <ul className="divide-y divide-line">
        {result.files.map((file) => (
          <li key={file.index} className="py-3 text-sm">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="break-all font-medium text-fg">{file.name}</span>
              <span className="text-xs text-subtle">{formatBytes(file.size, language)}</span>
              {file.status === 'parsed' ? <Tag tone="gold">{t(`soc.format.${file.format}` as MessageKey)}</Tag> : <Tag tone="alert">{file.status}</Tag>}
            </div>
            {file.sha256 ? <p className="mt-1 break-all font-mono text-xs text-subtle">SHA-256 {file.sha256}</p> : null}
            {file.status === 'binary' ? <p className="mt-1 text-gold">{t(`soc.files.status.binary.${file.binary}` as MessageKey)}</p> : null}
            {file.status === 'tooLarge' ? <p className="mt-1 text-gold">{t('soc.files.status.tooLarge', { max: formatBytes(MAX_FILE_BYTES, language) })}</p> : null}
            {file.status === 'empty' ? <p className="mt-1 text-gold">{t('soc.files.status.empty')}</p> : null}
            {file.status === 'unknownFormat' ? <p className="mt-1 text-gold">{t('soc.files.status.unknownFormat')}</p> : null}
            {(file.status === 'parsed' || file.status === 'unknownFormat') && !soc.fromSaved ? (
              <SelectField
                className="mt-2 max-w-xs"
                label={t('soc.files.format')}
                value={soc.overrides[file.index] ?? ''}
                onChange={(value) => soc.setOverride(file.index, value === '' ? null : (value as LogFormat))}
                options={[
                  { value: '', label: `${t('soc.files.auto')}${file.detectedFormat ? ` (${t('soc.files.detected', { format: t(`soc.format.${file.detectedFormat}` as MessageKey) })})` : ''}` },
                  ...LOG_FORMATS.map((format) => ({ value: format, label: t(`soc.format.${format}` as MessageKey) })),
                ]}
              />
            ) : null}
            {file.stats ? (
              <dl className="mt-2 grid grid-cols-1 gap-x-6 gap-y-1 text-xs sm:grid-cols-2">
                <div>
                  <dt className="inline text-muted">{t('soc.files.lines')}: </dt>
                  <dd className="inline font-mono text-fg">
                    {file.stats.read} / {file.stats.parsed} / <span className={file.stats.unparsed > 0 ? 'text-accent' : ''}>{file.stats.unparsed}</span>
                  </dd>
                </div>
                <div>
                  <dt className="inline text-muted">{t('soc.files.times')}: </dt>
                  <dd className="inline font-mono text-fg">
                    {file.stats.timestamps.exact} / <span className={file.stats.timestamps.inferred > 0 ? 'text-gold' : ''}>{file.stats.timestamps.inferred}</span> / <span className={file.stats.timestamps.missing > 0 ? 'text-accent' : ''}>{file.stats.timestamps.missing}</span>
                  </dd>
                </div>
                {file.stats.yearRollovers > 0 ? <p className="text-gold sm:col-span-2">{t('soc.files.rollovers', { n: file.stats.yearRollovers })}</p> : null}
              </dl>
            ) : null}
            {file.stats && file.stats.unparsedSamples.length > 0 ? (
              <details className="mt-2">
                <summary className="cursor-pointer text-xs text-muted">{t('soc.files.unparsedSamples', { n: file.stats.unparsedSamples.length })}</summary>
                <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-sm border border-line bg-bg p-2 font-mono text-xs text-muted">
                  {file.stats.unparsedSamples.map((sample) => `${sample.line}: ${sample.text}`).join('\n')}
                </pre>
              </details>
            ) : null}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

// ── Findings ────────────────────────────────────────────────────────────────

export function ruleDescription(t: (key: MessageKey, params?: Record<string, string | number>) => string, id: RuleId): string {
  const rule = RULES.find((candidate) => candidate.id === id);
  return t(`soc.rule.${id}.desc` as MessageKey, rule?.params ?? {});
}

function findingDetail(t: (key: MessageKey, params?: Record<string, string | number>) => string, finding: Finding): string {
  const parts: string[] = [];
  const detail = finding.detail;
  if (typeof detail.reason === 'string') parts.push(t(`soc.detail.reason.${detail.reason}` as MessageKey, detail));
  if (detail.users !== undefined) parts.push(t('soc.detail.users', detail));
  if (detail.sources !== undefined) parts.push(t('soc.detail.sources', detail));
  if (detail.failures !== undefined) parts.push(t('soc.detail.failures', detail));
  if (detail.kinds !== undefined) parts.push(t('soc.detail.kinds', detail));
  return parts.join(' · ');
}

export function FindingsView({ onShowEvents }: { onShowEvents: (ids: number[]) => void }) {
  const { t } = useI18n();
  const { result } = useSoc();
  if (!result) return null;
  const { findings, excludedWithoutTime } = result.detections;
  return (
    <div className="space-y-4">
      {Object.entries(excludedWithoutTime).map(([rule, count]) => (
        <p key={rule} className="text-sm text-gold">
          {t('soc.findings.excluded', { rule: t(`soc.rule.${rule}` as MessageKey), n: count })}
        </p>
      ))}
      {findings.length === 0 ? (
        <EmptyState>{t('soc.findings.none')}</EmptyState>
      ) : (
        <ul className="space-y-3">
          {findings.map((finding) => {
            const rule = RULES.find((candidate) => candidate.id === finding.rule);
            return (
              <li key={finding.key} className="rounded-sm border border-line bg-surface p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <Tag tone={SEVERITY_TONE[finding.severity]}>{t(`soc.severity.${finding.severity}` as MessageKey)}</Tag>
                  <span className="font-medium text-fg">{t(`soc.rule.${finding.rule}` as MessageKey)}</span>
                  <span className="break-all font-mono text-xs text-accent">{finding.entity.value}</span>
                </div>
                <p className="mt-1 text-muted">{findingDetail(t, finding)}</p>
                <p className="mt-1 text-xs text-subtle">
                  {t('soc.findings.period')}: {utc(finding.first)} → {utc(finding.last)} · {t('soc.findings.occurrences', { n: finding.count })}
                </p>
                <p className="mt-1 text-xs text-subtle">{ruleDescription(t, finding.rule)}</p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {rule?.techniques.map((technique) => (
                    <Link key={technique} to={`/attack/${technique}`} className="font-mono text-xs text-accent hover:underline">{technique}</Link>
                  ))}
                  <Button variant="ghost" className="min-h-7 px-2 text-xs" onClick={() => onShowEvents(finding.eventIds)}>
                    {t('soc.findings.events', { n: finding.eventIds.length })}
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      <details className="rounded-sm border border-line p-3 text-sm">
        <summary className="cursor-pointer text-muted">{t('soc.findings.coverage')}</summary>
        <ul className="mt-2 space-y-2">
          {RULES.map((rule) => (
            <li key={rule.id}>
              <span className="font-medium text-fg">{t(`soc.rule.${rule.id}` as MessageKey)}</span> <span className="text-xs text-subtle">{rule.techniques.join(', ')}</span>
              <p className="text-xs text-muted">{ruleDescription(t, rule.id)}</p>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

// ── Events ──────────────────────────────────────────────────────────────────

const CATEGORIES: EventCategory[] = ['authFailure', 'authSuccess', 'authInvalidUser', 'authInfo', 'sudoCommand', 'sudoFailure', 'sudoNotAllowed', 'suSuccess', 'suFailure', 'accountCreated', 'groupMemberAdded', 'accountLockout', 'logCleared', 'processCreated', 'httpRequest', 'webError', 'other'];

export function EventsView({ focus, onClearFocus }: { focus: number[] | null; onClearFocus: () => void }) {
  const { t } = useI18n();
  const soc = useSoc();
  const [text, setText] = useState('');
  const [category, setCategory] = useState<'all' | EventCategory>('all');
  const [file, setFile] = useState('all');
  const [onlyFlagged, setOnlyFlagged] = useState(false);
  const [page, setPage] = useState(1);
  const events = useMemo(() => soc.result?.events ?? [], [soc.result]);
  const filtered = useMemo(() => {
    const ids = focus ? new Set(focus) : null;
    const needles = text.toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8);
    return events.filter(
      (event) =>
        (!ids || ids.has(event.id)) &&
        (category === 'all' || event.category === category) &&
        (file === 'all' || String(event.file) === file) &&
        (!onlyFlagged || soc.flagged.has(event.id)) &&
        (needles.length === 0 || needles.every((needle) => `${event.message} ${event.user ?? ''} ${event.srcIp ?? ''} ${event.host ?? ''}`.toLowerCase().includes(needle))),
    );
  }, [events, focus, text, category, file, onlyFlagged, soc.flagged]);
  const { slice, pageCount, page: current } = paginate(filtered, page, 50);
  const reset = <T,>(setter: (value: T) => void) => (value: T) => {
    setter(value);
    setPage(1);
  };
  if (!soc.result) return null;

  return (
    <div className="space-y-3">
      {focus ? (
        <p className="flex flex-wrap items-center gap-2 text-sm text-gold">
          {t('soc.events.filtered')}
          <Button variant="ghost" className="min-h-7 px-2 text-xs" onClick={onClearFocus}>{t('soc.events.clearFilter')}</Button>
        </p>
      ) : null}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_12rem_12rem] sm:items-end">
        <TextField label={t('soc.events.search')} value={text} onChange={reset(setText)} />
        <SelectField label={t('soc.events.category')} value={category} onChange={reset(setCategory)} options={[{ value: 'all', label: t('common.all') }, ...CATEGORIES.map((value) => ({ value, label: t(`soc.category.${value}` as MessageKey) }))]} />
        <SelectField label={t('soc.events.file')} value={file} onChange={reset(setFile)} options={[{ value: 'all', label: t('common.all') }, ...soc.result.files.filter((entry) => entry.status === 'parsed').map((entry) => ({ value: String(entry.index), label: entry.name }))]} />
      </div>
      <label className="flex items-center gap-2 text-sm text-muted">
        <input type="checkbox" checked={onlyFlagged} onChange={(event) => reset(setOnlyFlagged)(event.target.checked)} />
        {t('soc.events.onlyFlagged')} ({soc.flagged.size})
      </label>
      <p role="status" className="text-sm text-muted">{t('common.results', { n: filtered.length, total: events.length })}</p>
      {filtered.length === 0 ? (
        <EmptyState>{t('common.noResults')}</EmptyState>
      ) : (
        <div className="overflow-x-auto rounded-sm border border-line">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface uppercase tracking-wider text-subtle">
              <tr>
                <th scope="col" className="px-2 py-2 font-medium"><span className="sr-only">{t('soc.events.flag')}</span></th>
                <th scope="col" className="px-2 py-2 font-medium">{t('soc.events.time')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('soc.events.category')}</th>
                <th scope="col" className="hidden px-2 py-2 font-medium md:table-cell">{t('soc.events.source')}</th>
                <th scope="col" className="hidden px-2 py-2 font-medium md:table-cell">{t('soc.events.user')}</th>
                <th scope="col" className="px-2 py-2 font-medium">{t('soc.events.message')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {slice.map((event) => (
                <EventRow key={event.id} event={event} flagged={soc.flagged.has(event.id)} onToggle={() => soc.toggleFlag(event.id)} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pagination page={current} pageCount={pageCount} onChange={setPage} />
    </div>
  );
}

function EventRow({ event, flagged, onToggle }: { event: LogEvent; flagged: boolean; onToggle: () => void }) {
  const { t } = useI18n();
  return (
    <tr className={`align-top ${flagged ? 'bg-raised' : ''}`}>
      <td className="px-2 py-1.5">
        <input type="checkbox" checked={flagged} onChange={onToggle} aria-label={`${t('soc.events.flag')} #${event.id}`} />
      </td>
      <td className="whitespace-nowrap px-2 py-1.5 font-mono text-muted">
        {utc(event.timestamp)}
        {event.timeQuality === 'inferred' ? <span className="block text-[0.625rem] text-gold">{t('soc.events.inferred')}</span> : null}
        {event.timeQuality === 'missing' ? <span className="block text-[0.625rem] text-accent">{t('soc.events.noTime')}</span> : null}
      </td>
      <td className="whitespace-nowrap px-2 py-1.5 text-muted">{t(`soc.category.${event.category}` as MessageKey)}{event.count > 1 ? ` ×${event.count}` : ''}</td>
      <td className="hidden break-all px-2 py-1.5 font-mono text-fg md:table-cell">{event.srcIp ?? '—'}</td>
      <td className="hidden break-all px-2 py-1.5 font-mono text-fg md:table-cell">{event.user ?? '—'}</td>
      <td className="break-all px-2 py-1.5 font-mono text-fg">{event.message}</td>
    </tr>
  );
}

// ── Timeline ────────────────────────────────────────────────────────────────

const BUCKETS: [number, string][] = [
  [1000, '1 s'],
  [60_000, '1 min'],
  [5 * 60_000, '5 min'],
  [15 * 60_000, '15 min'],
  [3_600_000, '1 h'],
  [6 * 3_600_000, '6 h'],
  [86_400_000, '1 day'],
  [7 * 86_400_000, '7 days'],
];

export function TimelineView({ onShowEvents }: { onShowEvents: (ids: number[]) => void }) {
  const { t } = useI18n();
  const { result } = useSoc();
  const data = useMemo(() => {
    const times = (result?.events ?? []).map((event) => event.timestamp).filter((time): time is number => time !== null);
    if (times.length === 0) return null;
    const min = Math.min(...times);
    const max = Math.max(...times);
    const [size, label] = BUCKETS.find(([bucket]) => (max - min) / bucket <= 120) ?? (BUCKETS[BUCKETS.length - 1] as [number, string]);
    const start = Math.floor(min / size) * size;
    const counts = new Array<number>(Math.floor((max - start) / size) + 1).fill(0);
    for (const time of times) counts[Math.floor((time - start) / size)] = (counts[Math.floor((time - start) / size)] ?? 0) + 1;
    return { start, size, label, counts, missing: (result?.events.length ?? 0) - times.length };
  }, [result]);
  if (!result) return null;
  if (!data) return <EmptyState>{t('soc.timeline.noTime')}</EmptyState>;
  const peak = Math.max(...data.counts, 1);
  const findings = [...result.detections.findings].filter((finding) => finding.first !== null).sort((a, b) => (a.first as number) - (b.first as number));
  return (
    <div className="space-y-4">
      <Panel title={t('soc.timeline.title')}>
        <svg viewBox={`0 0 ${data.counts.length} 100`} preserveAspectRatio="none" className="block h-40 w-full" role="img" aria-label={t('soc.timeline.title')}>
          {data.counts.map((count, index) => (
            <rect key={index} x={index + 0.1} width={0.8} y={100 - (count / peak) * 100} height={(count / peak) * 100} className="fill-gold" />
          ))}
        </svg>
        <div className="mt-1 flex justify-between font-mono text-[0.625rem] text-subtle">
          <span>{utc(data.start)}</span>
          <span>{utc(data.start + data.counts.length * data.size)}</span>
        </div>
        <p className="mt-2 text-xs text-subtle">{t('soc.timeline.bucket', { size: data.label })} · max {peak}</p>
        {data.missing > 0 ? <p className="mt-1 text-xs text-gold">{t('soc.timeline.excluded', { n: data.missing })}</p> : null}
      </Panel>
      <Panel title={t('soc.timeline.findings')}>
        {findings.length === 0 ? (
          <p className="text-sm text-muted">{t('soc.findings.none')}</p>
        ) : (
          <ol className="space-y-2 border-l border-line-strong pl-4 text-sm">
            {findings.map((finding) => (
              <li key={finding.key}>
                <span className="font-mono text-xs text-subtle">{utc(finding.first)}</span>{' '}
                <Tag tone={SEVERITY_TONE[finding.severity]}>{t(`soc.severity.${finding.severity}` as MessageKey)}</Tag>{' '}
                <button type="button" onClick={() => onShowEvents(finding.eventIds)} className="text-left text-fg hover:underline">
                  {t(`soc.rule.${finding.rule}` as MessageKey)} — <span className="font-mono text-xs text-accent">{finding.entity.value}</span>
                </button>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

// ── Entities ────────────────────────────────────────────────────────────────

function addressClass(value: string): string {
  const v4 = parseIpv4(value);
  if (v4) return classifyIpv4(v4);
  const v6 = parseIpv6(value);
  return v6 ? classifyIpv6(v6) : '';
}

export function EntitiesView({ onShowEvents }: { onShowEvents: (ids: number[]) => void }) {
  const { t } = useI18n();
  const { result } = useSoc();
  const tables = useMemo(() => {
    const build = (key: (event: LogEvent) => string | null, findingKind: 'ip' | 'user') => {
      const rows = new Map<string, { ids: number[]; failures: number; findings: number }>();
      for (const event of result?.events ?? []) {
        const value = key(event);
        if (!value) continue;
        const row = rows.get(value) ?? { ids: [], failures: 0, findings: 0 };
        row.ids.push(event.id);
        if (event.category === 'authFailure' || event.category === 'sudoFailure' || event.category === 'suFailure') row.failures += event.count;
        rows.set(value, row);
      }
      for (const finding of result?.detections.findings ?? []) {
        const row = finding.entity.kind === findingKind ? rows.get(finding.entity.value) ?? [...rows.entries()].find(([name]) => name.toLowerCase() === finding.entity.value)?.[1] : undefined;
        if (row) row.findings += 1;
      }
      return [...rows.entries()].sort((a, b) => b[1].findings - a[1].findings || b[1].failures - a[1].failures || b[1].ids.length - a[1].ids.length).slice(0, 50);
    };
    return { ips: build((event) => event.srcIp, 'ip'), users: build((event) => event.user, 'user') };
  }, [result]);
  if (!result) return null;
  const table = (title: string, rows: typeof tables.ips, withClass: boolean) => (
    <Panel title={title}>
      {rows.length === 0 ? (
        <p className="text-sm text-muted">—</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="uppercase tracking-wider text-subtle">
              <tr>
                <th scope="col" className="py-1.5 pr-2 font-medium">{title}</th>
                {withClass ? <th scope="col" className="py-1.5 pr-2 font-medium">{t('soc.entities.class')}</th> : null}
                <th scope="col" className="py-1.5 pr-2 text-right font-medium">{t('soc.entities.events')}</th>
                <th scope="col" className="py-1.5 pr-2 text-right font-medium">{t('soc.entities.failures')}</th>
                <th scope="col" className="py-1.5 text-right font-medium">{t('soc.entities.findings')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.map(([name, row]) => (
                <tr key={name}>
                  <td className="py-1.5 pr-2">
                    <button type="button" className="break-all text-left font-mono text-accent hover:underline" onClick={() => onShowEvents(row.ids)}>{name}</button>
                  </td>
                  {withClass ? <td className="py-1.5 pr-2 text-muted">{addressClass(name) ? t(`ioc.class.${addressClass(name)}` as MessageKey) : '—'}</td> : null}
                  <td className="py-1.5 pr-2 text-right font-mono">{row.ids.length}</td>
                  <td className="py-1.5 pr-2 text-right font-mono">{row.failures}</td>
                  <td className={`py-1.5 text-right font-mono ${row.findings > 0 ? 'text-accent' : ''}`}>{row.findings}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      {table(t('soc.entities.ips'), tables.ips, true)}
      {table(t('soc.entities.users'), tables.users, false)}
    </div>
  );
}

// ── Sigma ───────────────────────────────────────────────────────────────────

export function SigmaView({ onShowEvents }: { onShowEvents: (ids: number[]) => void }) {
  const { t } = useI18n();
  const soc = useSoc();
  const id = useId();
  const [running, setRunning] = useState(false);
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">{t('soc.sigma.help')}</p>
      <p className="text-xs text-subtle">{t('soc.sigma.subset')}</p>
      <p className="text-xs text-subtle">{t('soc.sigma.fields')}</p>
      <label htmlFor={id} className="block text-xs font-medium uppercase tracking-wider text-subtle">{t('tb.rules.input')}</label>
      <textarea id={id} value={soc.sigmaSource} onChange={(event) => soc.setSigmaSource(event.target.value)} rows={10} maxLength={1_000_000} spellCheck={false} className="w-full rounded-sm border border-line-strong bg-bg p-2.5 font-mono text-xs text-fg" />
      <Button
        variant="danger"
        disabled={running || soc.sigmaSource.trim() === '' || !soc.result}
        onClick={() => {
          setRunning(true);
          void soc.evaluateSigmaRules().finally(() => setRunning(false));
        }}
      >
        {running ? t('soc.working') : t('soc.sigma.run')}
      </Button>
      {soc.sigmaOutcomes ? (
        <ul className="space-y-2">
          {soc.sigmaOutcomes.map((outcome, index) => (
            <li key={index} className="rounded-sm border border-line bg-surface p-3 text-sm">
              {'title' in outcome ? <p className="font-medium text-fg">{outcome.title}</p> : null}
              {outcome.status === 'matched' ? (
                <p className="mt-1 flex flex-wrap items-center gap-2 text-accent">
                  {t('soc.sigma.status.matched', { n: outcome.eventIds.length, candidates: outcome.candidates })}
                  <Button variant="ghost" className="min-h-7 px-2 text-xs" onClick={() => onShowEvents(outcome.eventIds)}>{t('soc.findings.events', { n: outcome.eventIds.length })}</Button>
                </p>
              ) : outcome.status === 'noMatch' ? (
                <p className="mt-1 text-muted">{t('soc.sigma.status.noMatch', { candidates: outcome.candidates })}</p>
              ) : outcome.status === 'notApplicable' ? (
                <p className="mt-1 text-gold">{t(`soc.sigma.status.notApplicable.${outcome.reason}` as MessageKey, { detail: outcome.detail })}</p>
              ) : outcome.status === 'unsupported' ? (
                <p className="mt-1 text-gold">{t('soc.sigma.status.unsupported', { reason: outcome.reason })}</p>
              ) : (
                <p className="mt-1 text-accent">{t('soc.sigma.status.invalid', { reason: outcome.reason })}</p>
              )}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

// ── Investigation and reports ───────────────────────────────────────────────

export function InvestigationView() {
  const { t, language } = useI18n();
  const soc = useSoc();
  const titleId = useId();
  const notesId = useId();
  const [saved, setSaved] = useState<InvestigationSummary[] | 'unavailable' | null>(null);
  const [message, setMessage] = useState<{ tone: 'info' | 'error'; text: string } | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const refresh = () => listInvestigations().then(setSaved, () => setSaved('unavailable'));
  useEffect(() => {
    let cancelled = false;
    listInvestigations().then(
      (list) => !cancelled && setSaved(list),
      () => !cancelled && setSaved('unavailable'),
    );
    return () => {
      cancelled = true;
    };
  }, []);

  const result = soc.result;
  const labels = { rule: (id: RuleId) => t(`soc.rule.${id}` as MessageKey), format: (format: string) => t(`soc.format.${format}` as MessageKey) };
  const stamp = fileStamp();

  const save = async () => {
    if (!result) return;
    const outcome = await saveInvestigation({ version: 1, title: soc.title || 'Investigation', notes: soc.notes, flagged: [...soc.flagged], result }, soc.savedId ?? undefined);
    if (outcome.ok) {
      soc.setSavedId(outcome.id);
      setMessage({ tone: 'info', text: t('soc.inv.saved') });
    } else setMessage({ tone: 'error', text: outcome.reason === 'tooLarge' ? t('soc.inv.saveTooLarge', { n: MAX_SAVED_EVENTS.toLocaleString(language === 'fr' ? 'fr-FR' : 'en-GB') }) : t(outcome.reason === 'quota' ? 'soc.inv.saveQuota' : 'soc.inv.saveUnavailable') });
    await refresh();
  };

  const open = async (id: string) => {
    const investigation = await loadInvestigation(id).catch(() => null);
    if (!investigation) {
      setMessage({ tone: 'error', text: t('soc.inv.loadFailed') });
      return;
    }
    soc.loadSaved(id, investigation);
    setMessage(null);
  };

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <Panel title={t('soc.tab.report')}>
        <div className="space-y-3">
          <div>
            <label htmlFor={titleId} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">{t('soc.inv.title')}</label>
            <input id={titleId} value={soc.title} onChange={(event) => soc.setTitle(event.target.value)} maxLength={200} className="min-h-9 w-full rounded-sm border border-line-strong bg-bg px-2.5 text-sm text-fg" />
          </div>
          <div>
            <label htmlFor={notesId} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">{t('soc.inv.notes')}</label>
            <textarea id={notesId} value={soc.notes} onChange={(event) => soc.setNotes(event.target.value)} maxLength={100_000} rows={8} className="w-full rounded-sm border border-line-strong bg-bg p-2.5 text-sm text-fg" />
          </div>
          <Button variant="danger" disabled={!result} onClick={() => void save()}>{t('soc.inv.save')}</Button>
          <p className="text-xs text-subtle">{t('soc.inv.saveNote')}</p>
          {message ? <p role="status" className={`text-sm ${message.tone === 'error' ? 'text-accent' : 'text-gold'}`}>{message.text}</p> : null}
        </div>
      </Panel>
      <div className="flex flex-col gap-4">
        <Panel title={t('soc.report.title')}>
          <div className="flex flex-wrap gap-2">
            <Button disabled={!result} onClick={() => result && downloadText(`blackwatch-investigation-${stamp}.md`, buildMarkdownReport({ title: soc.title, notes: soc.notes, result, flagged: soc.flagged, labels }), 'text/markdown;charset=utf-8')}>
              {t('soc.report.markdown')}
            </Button>
            <Button disabled={!result} onClick={() => result && downloadText(`blackwatch-events-${stamp}.csv`, eventsToCsv(result.events, result.files.map((file) => file.name)), 'text/csv;charset=utf-8')}>
              {t('soc.report.csv')}
            </Button>
            <Button disabled={!result} onClick={() => result && downloadText(`blackwatch-findings-${stamp}.json`, JSON.stringify({ analysedAt: result.analysedAt, settings: result.settings, files: result.files, findings: result.detections.findings, excludedWithoutTime: result.detections.excludedWithoutTime }, null, 2), 'application/json')}>
              {t('soc.report.findings')}
            </Button>
          </div>
          <p className="mt-3 text-xs text-subtle">{t('soc.report.note')}</p>
        </Panel>
        <Panel title={t('soc.inv.list')}>
          {saved === null ? (
            <p className="text-sm text-muted">{t('app.loading')}</p>
          ) : saved === 'unavailable' ? (
            <p className="text-sm text-gold">{t('settings.data.unavailable')}</p>
          ) : saved.length === 0 ? (
            <p className="text-sm text-muted">{t('soc.inv.none')}</p>
          ) : (
            <ul className="-my-2 divide-y divide-line">
              {saved.map((entry) => (
                <li key={entry.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                  <span className="min-w-0">
                    <span className="block break-all text-fg">{entry.title}</span>
                    <span className="text-xs text-subtle">{formatDateTime(entry.updatedAt, language)} · {t('soc.inv.counts', { events: entry.events, findings: entry.findings })}</span>
                  </span>
                  <span className="flex gap-1">
                    <Button variant="ghost" className="min-h-7 px-2 text-xs" onClick={() => void open(entry.id)}>{t('soc.inv.load')}</Button>
                    <Button variant="ghost" className="min-h-7 px-2 text-xs" onClick={() => setDeleting(entry.id)}>{t('soc.inv.delete')}</Button>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <ConfirmDialog
        open={deleting !== null}
        title={t('soc.inv.deleteTitle')}
        body={t('soc.inv.deleteBody')}
        confirmLabel={t('soc.inv.delete')}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          const id = deleting;
          setDeleting(null);
          if (id) void deleteInvestigation(id).then(refresh, () => setSaved('unavailable'));
        }}
      />
    </div>
  );
}
