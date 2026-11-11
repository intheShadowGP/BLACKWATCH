import type { Language } from '../i18n';

const LOCALES: Record<Language, string> = { en: 'en-GB', fr: 'fr-FR' };

/** Calendar date in UTC, so a record shows the same day for every analyst. */
export function formatDate(iso: string | null | undefined, language: Language): string {
  if (!iso) return '—';
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return '—';
  return new Intl.DateTimeFormat(LOCALES[language], { dateStyle: 'medium', timeZone: 'UTC' }).format(time);
}

export function formatDateTime(iso: string | null | undefined, language: Language): string {
  if (!iso) return '—';
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return '—';
  return `${new Intl.DateTimeFormat(LOCALES[language], {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'UTC',
  }).format(time)} UTC`;
}

export function formatNumber(value: number, language: Language): string {
  return new Intl.NumberFormat(LOCALES[language]).format(value);
}

/** "3 hours ago" style label for a dataset age expressed in hours. */
export function formatAge(ageHours: number | null, language: Language): string {
  if (ageHours === null) return '—';
  const formatter = new Intl.RelativeTimeFormat(LOCALES[language], { numeric: 'always' });
  if (ageHours < 1) return formatter.format(-Math.max(1, Math.round(ageHours * 60)), 'minute');
  if (ageHours < 48) return formatter.format(-Math.round(ageHours), 'hour');
  return formatter.format(-Math.round(ageHours / 24), 'day');
}
