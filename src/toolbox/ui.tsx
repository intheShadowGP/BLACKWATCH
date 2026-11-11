import { useId, useState, type ReactNode } from 'react';
import { useI18n } from '../app/preferences-context';
import { Button } from '../components/ui';

const FIELD = 'w-full rounded-sm border border-line-strong bg-bg p-2.5 font-mono text-xs text-fg placeholder:text-subtle';

export function TextArea({
  label,
  value,
  onChange,
  maxLength,
  rows = 6,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  maxLength: number;
  rows?: number;
  placeholder?: string;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
        {label}
      </label>
      <textarea
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        maxLength={maxLength}
        rows={rows}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        className={FIELD}
      />
    </div>
  );
}

export function TextLine({
  label,
  value,
  onChange,
  maxLength = 500,
  placeholder,
  type = 'text',
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  maxLength?: number;
  placeholder?: string;
  type?: 'text' | 'password';
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium uppercase tracking-wider text-subtle">
        {label}
      </label>
      <input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        maxLength={maxLength}
        spellCheck={false}
        autoComplete="off"
        autoCapitalize="off"
        placeholder={placeholder}
        className={`${FIELD} min-h-9 text-sm`}
      />
    </div>
  );
}

export function CopyButton({ text }: { text: string }) {
  const { t } = useI18n();
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  return (
    <Button
      variant="ghost"
      className="min-h-7 px-2 text-xs"
      disabled={text === ''}
      onClick={() => {
        navigator.clipboard
          .writeText(text)
          .then(() => setState('copied'))
          .catch(() => setState('failed'));
        window.setTimeout(() => setState('idle'), 1500);
      }}
    >
      {state === 'copied' ? t('toolbox.copied') : state === 'failed' ? t('toolbox.copyFailed') : t('toolbox.copy')}
    </Button>
  );
}

/** Read-only output rendered as text in a <pre>. */
export function Output({ label, text, maxHeight = 'max-h-96' }: { label: string; text: string; maxHeight?: string }) {
  return (
    <div className="min-w-0">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wider text-subtle">{label}</span>
        <CopyButton text={text} />
      </div>
      <pre className={`${maxHeight} overflow-auto whitespace-pre-wrap break-all rounded-sm border border-line bg-surface p-2.5 font-mono text-xs text-fg`}>
        {text}
      </pre>
    </div>
  );
}

export interface Row {
  label: string;
  value: ReactNode;
  copy?: string;
}

export function KeyValues({ rows }: { rows: readonly Row[] }) {
  return (
    <dl className="divide-y divide-line rounded-sm border border-line bg-surface text-sm">
      {rows.map((row) => (
        <div key={row.label} className="grid grid-cols-1 gap-1 px-3 py-2 sm:grid-cols-[14rem_minmax(0,1fr)_auto] sm:items-center sm:gap-3">
          <dt className="text-muted">{row.label}</dt>
          <dd className="min-w-0 break-all font-mono text-xs text-fg">{row.value}</dd>
          {row.copy !== undefined ? <CopyButton text={row.copy} /> : <span className="hidden sm:block" />}
        </div>
      ))}
    </dl>
  );
}

export function FilePicker({ onFile, accept }: { onFile: (file: File) => void; accept?: string }) {
  const { t } = useI18n();
  const id = useId();
  return (
    <label
      htmlFor={id}
      className="inline-flex min-h-9 cursor-pointer items-center rounded-sm border border-line-strong bg-raised px-3 text-sm font-medium text-fg hover:border-subtle has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-gold"
    >
      {t('toolbox.chooseFile')}
      <input
        id={id}
        type="file"
        accept={accept}
        className="sr-only"
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = '';
          if (file) onFile(file);
        }}
      />
    </label>
  );
}

export function Message({ tone = 'info', children }: { tone?: 'info' | 'error' | 'warning'; children: ReactNode }) {
  const tones = { info: 'text-muted', error: 'text-accent', warning: 'text-gold' };
  return (
    <p role={tone === 'error' ? 'alert' : 'status'} className={`text-sm ${tones[tone]}`}>
      {children}
    </p>
  );
}

export function formatBytes(size: number, language: 'en' | 'fr'): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let value = size;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const number = new Intl.NumberFormat(language === 'fr' ? 'fr-FR' : 'en-GB', { maximumFractionDigits: unit === 0 ? 0 : 1 }).format(value);
  return `${number} ${language === 'fr' ? units[unit]?.replace('B', 'o') : units[unit]}`;
}
