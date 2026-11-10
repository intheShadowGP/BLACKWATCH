import { describe, expect, it } from 'vitest';
import { detectLanguage, dictionaries, translate, type MessageKey } from './index';

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((match) => match[1]).sort();

describe('dictionaries', () => {
  const keys = Object.keys(dictionaries.en) as MessageKey[];

  it('defines the same keys in French and English', () => {
    expect(Object.keys(dictionaries.fr).sort()).toEqual([...keys].sort());
  });

  it('has no empty message', () => {
    for (const language of ['en', 'fr'] as const) {
      for (const key of keys) {
        expect(dictionaries[language][key].trim(), `${language}:${key}`).not.toBe('');
      }
    }
  });

  it('uses the same placeholders in both languages', () => {
    for (const key of keys) {
      expect(placeholders(dictionaries.fr[key]), key).toEqual(placeholders(dictionaries.en[key]));
    }
  });
});

describe('translate', () => {
  it('returns the message in the requested language', () => {
    expect(translate('en', 'nav.overview')).toBe('Overview');
    expect(translate('fr', 'nav.overview')).toBe('Vue d’ensemble');
  });

  it('substitutes placeholders', () => {
    expect(translate('en', 'status.milestone', { n: 3 })).toBe('Milestone 3');
  });

  it('leaves unknown placeholders untouched', () => {
    expect(translate('en', 'status.milestone', { other: 1 })).toBe('Milestone {n}');
  });

  it('does not resolve placeholders from the object prototype', () => {
    expect(translate('en', 'notFound.body', {})).toBe('No page matches {path}.');
  });

  it('inserts parameter values verbatim, without re-interpreting them', () => {
    const hostile = '<img src=x onerror=alert(1)>{path}';
    expect(translate('en', 'notFound.body', { path: hostile })).toBe(`No page matches ${hostile}.`);
  });

  it('falls back to the key for an unknown message', () => {
    expect(translate('en', 'missing.key' as MessageKey)).toBe('missing.key');
  });
});

describe('detectLanguage', () => {
  it('matches on the primary subtag', () => {
    expect(detectLanguage(['fr-CA', 'en'])).toBe('fr');
    expect(detectLanguage(['EN-us'])).toBe('en');
  });

  it('skips unsupported languages', () => {
    expect(detectLanguage(['de-DE', 'fr'])).toBe('fr');
  });

  it('defaults to English', () => {
    expect(detectLanguage([])).toBe('en');
    expect(detectLanguage(['ja', ''])).toBe('en');
  });
});
