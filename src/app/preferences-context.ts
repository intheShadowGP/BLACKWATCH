import { createContext, useContext, useMemo } from 'react';
import { translate, type Language, type Translate } from '../i18n';
import type { Preferences } from '../lib/preferences';

export interface PreferencesContextValue {
  preferences: Preferences;
  /** False when IndexedDB is unavailable and preferences live in memory only. */
  persistent: boolean;
  update: (patch: Partial<Preferences>) => void;
  /** Restores default preferences in memory, without writing them to storage. */
  reset: () => void;
}

export const PreferencesContext = createContext<PreferencesContextValue | null>(null);

export function usePreferences(): PreferencesContextValue {
  const value = useContext(PreferencesContext);
  if (!value) throw new Error('usePreferences must be used inside PreferencesProvider');
  return value;
}

export function useI18n(): { language: Language; t: Translate } {
  const { language } = usePreferences().preferences;
  return useMemo(
    () => ({ language, t: (key, params) => translate(language, key, params) }),
    [language],
  );
}
