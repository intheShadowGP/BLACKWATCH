import { z } from 'zod';
import { LANGUAGES, detectLanguage } from '../i18n';

export const THEMES = ['dark', 'light', 'system'] as const;
export const DENSITIES = ['comfortable', 'compact'] as const;
export const MOTIONS = ['system', 'reduced', 'full'] as const;

export const preferencesSchema = z.object({
  language: z.enum(LANGUAGES),
  theme: z.enum(THEMES),
  density: z.enum(DENSITIES),
  motion: z.enum(MOTIONS),
});

export type Preferences = z.infer<typeof preferencesSchema>;

export function defaultPreferences(browserLanguages: readonly string[] = []): Preferences {
  return {
    language: detectLanguage(browserLanguages),
    theme: 'dark',
    density: 'comfortable',
    motion: 'system',
  };
}

/**
 * Validates stored preferences field by field. Stored data is untrusted:
 * any field that is missing or invalid falls back to its default while
 * valid fields are kept.
 */
export function parsePreferences(raw: unknown, fallback: Preferences): Preferences {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ...fallback };
  const source = raw as Record<string, unknown>;
  const pick = <K extends keyof Preferences>(key: K): Preferences[K] => {
    const result = preferencesSchema.shape[key].safeParse(source[key]);
    return result.success ? (result.data as Preferences[K]) : fallback[key];
  };
  return {
    language: pick('language'),
    theme: pick('theme'),
    density: pick('density'),
    motion: pick('motion'),
  };
}
