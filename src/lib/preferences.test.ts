import { describe, expect, it } from 'vitest';
import { defaultPreferences, parsePreferences, preferencesSchema } from './preferences';

const fallback = defaultPreferences(['en']);

describe('defaultPreferences', () => {
  it('uses the dark theme and the browser language', () => {
    expect(defaultPreferences(['fr-FR'])).toEqual({
      language: 'fr',
      theme: 'dark',
      density: 'comfortable',
      motion: 'system',
    });
  });

  it('produces a value accepted by the schema', () => {
    expect(preferencesSchema.safeParse(defaultPreferences()).success).toBe(true);
  });
});

describe('parsePreferences', () => {
  it('accepts a valid record', () => {
    const stored = { language: 'fr', theme: 'light', density: 'compact', motion: 'reduced' };
    expect(parsePreferences(stored, fallback)).toEqual(stored);
  });

  it.each([undefined, null, 'dark', 42, [], ['fr']])('falls back entirely for %j', (raw) => {
    expect(parsePreferences(raw, fallback)).toEqual(fallback);
  });

  it('keeps valid fields and replaces invalid ones', () => {
    const stored = { language: 'fr', theme: 'neon', density: 7, motion: null };
    expect(parsePreferences(stored, fallback)).toEqual({ ...fallback, language: 'fr' });
  });

  it('drops unknown properties', () => {
    const stored = { ...fallback, theme: 'light', injected: '<script>alert(1)</script>' };
    expect(parsePreferences(stored, fallback)).toEqual({ ...fallback, theme: 'light' });
  });

  it('ignores values inherited from a polluted prototype', () => {
    const stored = JSON.parse('{"__proto__": {"theme": "light"}, "language": "fr"}') as unknown;
    expect(parsePreferences(stored, fallback)).toEqual({ ...fallback, language: 'fr' });
  });

  it('never returns the fallback object itself', () => {
    expect(parsePreferences(null, fallback)).not.toBe(fallback);
  });
});
