import { useId, useRef, type KeyboardEvent, type ReactNode } from 'react';
import { useI18n } from '../app/preferences-context';
import { freshness } from '../data/loader';
import type { ManifestEntry } from '../data/schemas';
import type { MessageKey } from '../i18n';
import type { Severity } from '../lib/cvss';
import { formatAge, formatDateTime, formatNumber } from '../lib/format';
import type { PriorityLevel } from '../lib/vulnerabilities';
import { Button, Panel } from './ui';

/** Link to another site. Opens in a new tab without leaking the opener or the referrer. */
export function ExternalLink({ href, children, className = '' }: { href: string; children: ReactNode; className?: string }) {
  const { t } = useI18n();
  // Dataset URLs are validated as http(s) by the schemas; this guard is a second line of defence.
  if (!/^https?:\/\//i.test(href)) return <span className={className}>{children}</span>;
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={`text-accent underline decoration-accent/40 underline-offset-2 hover:decoration-accent ${className}`}
    >
      {children}
      <span className="sr-only"> {t('common.newTab')}</span>
    </a>
  );
}

const SEVERITY_STYLES: Record<Severity | 'UNSCORED', string> = {
  CRITICAL: 'border-accent-fill bg-accent-fill text-on-accent',
  HIGH: 'border-accent text-accent',
  MEDIUM: 'border-gold/60 text-gold',
  LOW: 'border-line-strong text-muted',
  NONE: 'border-line-strong text-subtle',
  UNSCORED: 'border-line text-subtle',
};

export function SeverityBadge({ severity, score }: { severity: Severity | null; score?: number | null }) {
  const { t } = useI18n();
  const key = severity ?? 'UNSCORED';
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-[0.6875rem] font-semibold uppercase tracking-wider ${SEVERITY_STYLES[key]}`}
    >
      {typeof score === 'number' ? <span className="font-mono">{score.toFixed(1)}</span> : null}
      {t(`severity.${key}` as MessageKey)}
    </span>
  );
}

export function PriorityBadge({ level }: { level: PriorityLevel }) {
  const { t } = useI18n();
  return (
    <span
      title={t(`priority.level.${level}` as MessageKey)}
      className={`inline-flex min-w-7 justify-center rounded-sm border px-1 py-0.5 font-mono text-[0.6875rem] font-semibold ${
        level === 1 ? 'border-accent-fill bg-accent-fill text-on-accent' : level === 2 ? 'border-accent text-accent' : 'border-line-strong text-muted'
      }`}
    >
      P{level}
      <span className="sr-only"> — {t(`priority.level.${level}` as MessageKey)}</span>
    </span>
  );
}

export function Tag({ children, tone = 'neutral' }: { children: ReactNode; tone?: 'neutral' | 'alert' | 'gold' }) {
  const tones = { neutral: 'border-line-strong text-muted', alert: 'border-accent text-accent', gold: 'border-gold/60 text-gold' };
  return (
    <span className={`inline-flex whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-[0.6875rem] font-medium uppercase tracking-wider ${tones[tone]}`}>
      {children}
    </span>
  );
}

type LoadState = { status: 'loading' } | { status: 'missing' } | { status: 'error'; reason: 'network' | 'invalid' } | { status: 'ready' };

/** Loading, missing and error states of a dataset. Renders nothing once the dataset is ready. */
export function DatasetState({ state }: { state: LoadState }) {
  const { t } = useI18n();
  if (state.status === 'ready') return null;
  if (state.status === 'loading') {
    return <p role="status" className="py-6 text-sm text-muted">{t('data.loading')}</p>;
  }
  const key: MessageKey =
    state.status === 'missing' ? 'data.missing' : state.reason === 'network' ? 'data.error.network' : 'data.error.invalid';
  return (
    <div role="alert" className="rounded-sm border border-line-strong bg-surface p-4 text-sm text-gold">
      {t(key)}
    </div>
  );
}

export function FreshnessTag({ entry }: { entry: ManifestEntry }) {
  const { t } = useI18n();
  if (entry.status === 'missing') return <Tag tone="alert">{t('data.status.missing')}</Tag>;
  const { level } = freshness(entry);
  if (entry.status === 'stale') return <Tag tone="alert">{t('data.status.stale')}</Tag>;
  return <Tag tone={level === 'current' ? 'gold' : level === 'aging' ? 'neutral' : 'alert'}>{t(`data.level.${level}` as MessageKey)}</Tag>;
}

/** Provenance block: where the data shown on a page comes from, under which terms, and how old it is. */
export function SourceNote({ entries }: { entries: readonly ManifestEntry[] }) {
  const { t, language } = useI18n();
  if (entries.length === 0) return null;
  return (
    <Panel title={t('data.sources')} className="mt-6 print:hidden">
      <ul className="-my-3 divide-y divide-line">
        {entries.map((entry) => {
          const { ageHours } = freshness(entry);
          return (
            <li key={entry.id} className="py-3 text-sm">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <ExternalLink href={entry.sourceUrl} className="font-medium">
                  {entry.publisher}
                </ExternalLink>
                <FreshnessTag entry={entry} />
                <span className="text-muted">
                  {t('data.retrieved', { date: formatDateTime(entry.retrievedAt, language), age: formatAge(ageHours, language) })}
                </span>
              </div>
              <p className="mt-1 text-muted">
                {t('data.records', { n: formatNumber(entry.count, language) })}
                {entry.version ? ` · ${t('data.version', { version: entry.version })}` : ''} · {t('data.licence')}{' '}
                <ExternalLink href={entry.licenceUrl}>{entry.licence}</ExternalLink>
              </p>
              <p className="mt-1 text-xs text-subtle">{entry.notice}</p>
              {entry.status === 'stale' ? <p className="mt-1 text-xs text-accent">{t('data.staleNote')}</p> : null}
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}

export function Pagination({ page, pageCount, onChange }: { page: number; pageCount: number; onChange: (page: number) => void }) {
  const { t } = useI18n();
  if (pageCount <= 1) return null;
  return (
    <nav aria-label={t('page.label')} className="mt-4 flex items-center justify-between gap-3 print:hidden">
      <Button onClick={() => onChange(page - 1)} disabled={page <= 1}>
        {t('page.prev')}
      </Button>
      <p className="text-sm text-muted" aria-live="polite">
        {t('page.status', { page, count: pageCount })}
      </p>
      <Button onClick={() => onChange(page + 1)} disabled={page >= pageCount}>
        {t('page.next')}
      </Button>
    </nav>
  );
}

export function paginate<T>(items: readonly T[], page: number, pageSize: number): { slice: T[]; pageCount: number; page: number } {
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const current = Math.min(Math.max(1, page), pageCount);
  return { slice: items.slice((current - 1) * pageSize, current * pageSize), pageCount, page: current };
}

export interface TabItem<T extends string> {
  id: T;
  label: string;
  count?: number;
}

/** Tab list following the WAI-ARIA tabs pattern (arrow keys move between tabs). */
export function Tabs<T extends string>({ label, tabs, active, onChange, panelId }: { label: string; tabs: readonly TabItem<T>[]; active: T; onChange: (id: T) => void; panelId: string }) {
  const refs = useRef(new Map<T, HTMLButtonElement>());
  const onKeyDown = (event: KeyboardEvent) => {
    const index = tabs.findIndex((tab) => tab.id === active);
    const next =
      event.key === 'ArrowRight' ? tabs[(index + 1) % tabs.length]
      : event.key === 'ArrowLeft' ? tabs[(index - 1 + tabs.length) % tabs.length]
      : event.key === 'Home' ? tabs[0]
      : event.key === 'End' ? tabs[tabs.length - 1]
      : undefined;
    if (!next) return;
    event.preventDefault();
    onChange(next.id);
    refs.current.get(next.id)?.focus();
  };
  return (
    <div role="tablist" aria-label={label} onKeyDown={onKeyDown} className="mb-5 flex gap-1 overflow-x-auto overflow-y-hidden border-b border-line print:hidden">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          ref={(element) => {
            if (element) refs.current.set(tab.id, element);
            else refs.current.delete(tab.id);
          }}
          type="button"
          role="tab"
          id={`${panelId}-tab-${tab.id}`}
          aria-selected={tab.id === active}
          aria-controls={panelId}
          tabIndex={tab.id === active ? 0 : -1}
          onClick={() => onChange(tab.id)}
          className={`-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm ${
            tab.id === active ? 'border-accent text-fg' : 'border-transparent text-muted hover:text-fg'
          }`}
        >
          {tab.label}
          {tab.count !== undefined ? <span className="ml-2 font-mono text-xs text-subtle">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

const FIELD = 'min-h-9 w-full rounded-sm border border-line-strong bg-bg px-2.5 text-sm text-fg placeholder:text-subtle';

export function TextField({ label, value, onChange, placeholder, type = 'search', className = '' }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string; type?: 'search' | 'text'; className?: string }) {
  const id = useId();
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        maxLength={200}
        autoComplete="off"
        spellCheck={false}
        className={FIELD}
      />
    </div>
  );
}

export function SelectField<T extends string>({ label, value, options, onChange, className = '' }: { label: string; value: T; options: readonly { value: T; label: string }[]; onChange: (value: T) => void; className?: string }) {
  const id = useId();
  return (
    <div className={className}>
      <label htmlFor={id} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
        {label}
      </label>
      <select id={id} value={value} onChange={(event) => onChange(event.target.value as T)} className={FIELD}>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export interface BarDatum {
  label: string;
  value: number;
  tone?: 'accent' | 'gold' | 'neutral';
}

/**
 * Horizontal bar chart. Every value is also printed as text, so the chart
 * carries no information that is unavailable to assistive technology.
 */
export function BarChart({ data, caption }: { data: readonly BarDatum[]; caption: string }) {
  const { language } = useI18n();
  const max = Math.max(1, ...data.map((datum) => datum.value));
  const fills = { accent: 'fill-accent-fill', gold: 'fill-gold', neutral: 'fill-line-strong' };
  return (
    <table className="w-full text-sm">
      <caption className="sr-only">{caption}</caption>
      <tbody>
        {data.map((datum) => (
          <tr key={datum.label}>
            <th scope="row" className="w-px whitespace-nowrap py-1 pr-3 text-left font-normal text-muted">
              {datum.label}
            </th>
            <td className="w-full py-1" aria-hidden="true">
              <svg className="block h-3 w-full" preserveAspectRatio="none" viewBox="0 0 100 10">
                <rect width="100" height="10" className="fill-raised" />
                <rect width={(datum.value / max) * 100} height="10" className={fills[datum.tone ?? 'neutral']} />
              </svg>
            </td>
            <td className="w-px whitespace-nowrap py-1 pl-3 text-right font-mono text-fg">{formatNumber(datum.value, language)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function EmptyState({ children }: { children: ReactNode }) {
  return <p className="rounded-sm border border-dashed border-line-strong px-4 py-8 text-center text-sm text-muted">{children}</p>;
}
