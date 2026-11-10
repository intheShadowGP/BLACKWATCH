import { en, type MessageKey } from './en';
import { fr } from './fr';

export type { MessageKey };

export const LANGUAGES = ['en', 'fr'] as const;
export type Language = (typeof LANGUAGES)[number];

export const dictionaries: Record<Language, Record<MessageKey, string>> = { en, fr };

export type MessageParams = Record<string, string | number>;
export type Translate = (key: MessageKey, params?: MessageParams) => string;

/**
 * Resolves a message and substitutes `{name}` placeholders.
 * The result is plain text: it is always rendered through React, never as HTML.
 */
export function translate(language: Language, key: MessageKey, params?: MessageParams): string {
  const template = dictionaries[language][key] ?? en[key] ?? key;
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : match,
  );
}

/** Picks the first supported language from a browser language list; English otherwise. */
export function detectLanguage(candidates: readonly string[]): Language {
  for (const candidate of candidates) {
    const primary = candidate.toLowerCase().split('-')[0];
    const match = LANGUAGES.find((language) => language === primary);
    if (match) return match;
  }
  return 'en';
}
