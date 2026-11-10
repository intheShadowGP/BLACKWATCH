import { useEffect, useId, type ButtonHTMLAttributes, type ReactNode } from 'react';
import type { ModuleStatus } from '../app/modules';
import { useI18n } from '../app/preferences-context';

export const APP_NAME = 'BLACKWATCH';

export function Brand({ className = '' }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2.5 font-semibold tracking-[0.18em] text-fg ${className}`}>
      <span aria-hidden="true" className="inline-block size-2.5 bg-accent-fill" />
      {APP_NAME}
    </span>
  );
}

type ButtonVariant = 'default' | 'danger' | 'ghost';

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  default: 'border-line-strong bg-raised text-fg hover:border-subtle',
  danger: 'border-accent-fill bg-accent-fill text-on-accent hover:brightness-110',
  ghost: 'border-transparent text-muted hover:bg-raised hover:text-fg',
};

export function Button({
  variant = 'default',
  className = '',
  type = 'button',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      type={type}
      className={`inline-flex min-h-9 items-center justify-center gap-2 rounded-sm border px-3 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${BUTTON_VARIANTS[variant]} ${className}`}
      {...props}
    />
  );
}

/** Page title block. Also keeps the document title in sync with the current view. */
export function PageHeader({ title, intro, aside }: { title: string; intro?: string; aside?: ReactNode }) {
  useEffect(() => {
    document.title = `${title} — ${APP_NAME}`;
  }, [title]);

  return (
    <header className="mb-6 flex flex-wrap items-start justify-between gap-3 border-b border-line pb-5">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-fg">{title}</h1>
        {intro ? <p className="mt-1.5 max-w-3xl text-sm text-muted">{intro}</p> : null}
      </div>
      {aside}
    </header>
  );
}

export function Panel({
  title,
  children,
  className = '',
}: {
  title: string;
  children: ReactNode;
  className?: string;
}) {
  const headingId = useId();
  return (
    <section aria-labelledby={headingId} className={`rounded-sm border border-line bg-surface ${className}`}>
      <h2
        id={headingId}
        className="border-b border-line px-4 py-2.5 text-xs font-semibold uppercase tracking-[0.12em] text-muted"
      >
        {title}
      </h2>
      <div className="p-4">{children}</div>
    </section>
  );
}

export function StatusBadge({ status, milestone }: { status: ModuleStatus; milestone?: number }) {
  const { t } = useI18n();
  const available = status === 'available';
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-[0.6875rem] font-medium uppercase tracking-wider ${
        available ? 'border-gold/50 text-gold' : 'border-line-strong text-subtle'
      }`}
    >
      {available ? t('status.available') : t('status.planned')}
      {!available && milestone !== undefined ? (
        <span className="normal-case tracking-normal">· {t('status.milestone', { n: milestone })}</span>
      ) : null}
    </span>
  );
}

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

/** Radio group rendered as a segmented control. Native inputs keep keyboard behaviour intact. */
export function Segmented<T extends string>({
  legend,
  name,
  value,
  options,
  onChange,
}: {
  legend: string;
  name: string;
  value: T;
  options: readonly SegmentedOption<T>[];
  onChange: (value: T) => void;
}) {
  return (
    <fieldset className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 py-3">
      <legend className="float-left text-sm text-fg">{legend}</legend>
      <div className="inline-flex rounded-sm border border-line-strong">
        {options.map((option) => (
          <label
            key={option.value}
            className="relative cursor-pointer border-r border-line-strong px-3 py-1.5 text-sm text-muted last:border-r-0 hover:text-fg has-[:checked]:bg-raised has-[:checked]:text-fg has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-gold"
          >
            <input
              type="radio"
              name={name}
              value={option.value}
              checked={option.value === value}
              onChange={() => onChange(option.value)}
              className="sr-only"
            />
            {option.label}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
