import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import { defaultPreferences, type Preferences } from '../lib/preferences';
import { loadPreferences, savePreferences } from '../lib/storage';
import { PreferencesContext, type PreferencesContextValue } from './preferences-context';

const LIGHT_QUERY = '(prefers-color-scheme: light)';

/** IndexedDB can stall (blocked upgrade, slow disk): the interface never waits longer than this. */
export const PREFERENCES_TIMEOUT_MS = 2500;

function subscribeToSystemTheme(onChange: () => void): () => void {
  if (typeof window.matchMedia !== 'function') return () => undefined;
  const query = window.matchMedia(LIGHT_QUERY);
  query.addEventListener('change', onChange);
  return () => query.removeEventListener('change', onChange);
}

function systemPrefersLight(): boolean {
  return typeof window.matchMedia === 'function' && window.matchMedia(LIGHT_QUERY).matches;
}

function browserDefaults(): Preferences {
  return defaultPreferences(navigator.languages ?? [navigator.language]);
}

interface State {
  preferences: Preferences;
  persistent: boolean;
  ready: boolean;
}

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<State>(() => ({
    preferences: browserDefaults(),
    persistent: true,
    ready: false,
  }));
  // Mirror of the current preferences for event handlers, so updates never read stale state.
  const latest = useRef(state.preferences);
  // Until the stored record has been read, changes are kept here and not written,
  // so a slow read can never be overwritten by defaults.
  const storedLoaded = useRef(false);
  const pendingPatch = useRef<Partial<Preferences>>({});
  const prefersLight = useSyncExternalStore(subscribeToSystemTheme, systemPrefersLight, () => false);

  useEffect(() => {
    let cancelled = false;
    // Show the interface with defaults if storage is slow, but keep waiting for the real record.
    const timer = window.setTimeout(() => {
      if (!cancelled) setState((current) => (current.ready ? current : { ...current, ready: true }));
    }, PREFERENCES_TIMEOUT_MS);
    void loadPreferences(browserDefaults()).then((loaded) => {
      window.clearTimeout(timer);
      if (cancelled) return;
      storedLoaded.current = true;
      const patch = pendingPatch.current;
      pendingPatch.current = {};
      const next = { ...loaded.preferences, ...patch };
      latest.current = next;
      setState({ preferences: next, persistent: loaded.persistent, ready: true });
      if (Object.keys(patch).length > 0 && loaded.persistent) {
        void savePreferences(next).then((saved) => {
          if (!saved) setState((current) => ({ ...current, persistent: false }));
        });
      }
    });
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, []);

  const { preferences } = state;
  const resolvedTheme =
    preferences.theme === 'system' ? (prefersLight ? 'light' : 'dark') : preferences.theme;

  useEffect(() => {
    const root = document.documentElement;
    root.lang = preferences.language;
    root.dataset.theme = resolvedTheme;
    root.dataset.density = preferences.density;
    root.dataset.motion = preferences.motion;
  }, [preferences.language, preferences.density, preferences.motion, resolvedTheme]);

  const update = useCallback((patch: Partial<Preferences>) => {
    const next = { ...latest.current, ...patch };
    latest.current = next;
    setState((current) => ({ ...current, preferences: next }));
    if (!storedLoaded.current) {
      pendingPatch.current = { ...pendingPatch.current, ...patch };
      return;
    }
    void savePreferences(next).then((saved) => {
      if (!saved) setState((current) => (current.persistent ? { ...current, persistent: false } : current));
    });
  }, []);

  const reset = useCallback(() => {
    const next = browserDefaults();
    latest.current = next;
    setState((current) => ({ ...current, preferences: next }));
  }, []);

  const value = useMemo<PreferencesContextValue>(
    () => ({ preferences, persistent: state.persistent, update, reset }),
    [preferences, state.persistent, update, reset],
  );

  // Rendering waits for stored preferences so the interface never flashes in the wrong language.
  if (!state.ready) return null;

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}
