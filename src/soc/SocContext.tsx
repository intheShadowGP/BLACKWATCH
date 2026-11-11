import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react';
// The analysis engine is loaded on first use, so the shell does not carry it.
const client = () => import('./client');
import type { AnalysisResult } from './lib/analysis';
import type { LogFormat, TimeSettings } from './lib/model';
import type { SigmaOutcome } from './lib/sigma';
import type { StoredInvestigation } from './lib/investigations';

export type SocStatus = 'idle' | 'working' | 'ready' | 'error';

interface SocState {
  status: SocStatus;
  files: File[];
  overrides: Record<number, LogFormat>;
  settings: TimeSettings;
  result: AnalysisResult | null;
  title: string;
  notes: string;
  flagged: Set<number>;
  sigmaSource: string;
  sigmaOutcomes: SigmaOutcome[] | null;
  savedId: string | null;
  /** True when the result was loaded from a saved investigation (source files are not available). */
  fromSaved: boolean;
}

interface SocContextValue extends SocState {
  importFiles: (files: File[]) => void;
  setSettings: (settings: TimeSettings) => void;
  setOverride: (fileIndex: number, format: LogFormat | null) => void;
  setTitle: (title: string) => void;
  setNotes: (notes: string) => void;
  toggleFlag: (eventId: number) => void;
  setSigmaSource: (source: string) => void;
  evaluateSigmaRules: () => Promise<void>;
  loadSaved: (id: string, investigation: StoredInvestigation) => void;
  setSavedId: (id: string) => void;
  clear: () => void;
}

const SocContext = createContext<SocContextValue | null>(null);

const initial = (): SocState => ({
  status: 'idle',
  files: [],
  overrides: {},
  settings: { endYear: new Date().getUTCFullYear(), offsetMinutes: 0 },
  result: null,
  title: '',
  notes: '',
  flagged: new Set(),
  sigmaSource: '',
  sigmaOutcomes: null,
  savedId: null,
  fromSaved: false,
});

/**
 * Holds the workbench state above the routes, so following a link to a CVE or
 * a tool and coming back keeps the import. Nothing is persisted unless the
 * analyst saves an investigation; reloading the page clears it.
 */
export function SocProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<SocState>(initial);
  const run = useRef(0);

  const analyse = useCallback((files: File[], settings: TimeSettings, overrides: Record<number, LogFormat>) => {
    run.current += 1;
    const current = run.current;
    setState((previous) => ({ ...previous, status: 'working', files, settings, overrides, sigmaOutcomes: null, flagged: new Set(), fromSaved: false }));
    client()
      .then(({ analyzeFiles }) => analyzeFiles(files, settings, overrides))
      .then((result) => {
        if (current === run.current) setState((previous) => ({ ...previous, status: 'ready', result }));
      })
      .catch(() => {
        if (current === run.current) setState((previous) => ({ ...previous, status: 'error', result: null }));
      });
  }, []);

  const value = useMemo<SocContextValue>(
    () => ({
      ...state,
      importFiles: (files) => analyse(files, state.settings, {}),
      setSettings: (settings) => (state.files.length > 0 && !state.fromSaved ? analyse(state.files, settings, state.overrides) : setState((previous) => ({ ...previous, settings }))),
      setOverride: (fileIndex, format) => {
        const overrides: Record<number, LogFormat> = Object.fromEntries(Object.entries(state.overrides).filter(([key]) => Number(key) !== fileIndex));
        if (format !== null) overrides[fileIndex] = format;
        analyse(state.files, state.settings, overrides);
      },
      setTitle: (title) => setState((previous) => ({ ...previous, title })),
      setNotes: (notes) => setState((previous) => ({ ...previous, notes })),
      toggleFlag: (eventId) =>
        setState((previous) => {
          const flagged = new Set(previous.flagged);
          if (flagged.has(eventId)) flagged.delete(eventId);
          else flagged.add(eventId);
          return { ...previous, flagged };
        }),
      setSigmaSource: (sigmaSource) => setState((previous) => ({ ...previous, sigmaSource })),
      evaluateSigmaRules: async () => {
        const { runSigma } = await client();
        const outcomes = await runSigma(state.sigmaSource, state.result?.events ?? []);
        setState((previous) => ({ ...previous, sigmaOutcomes: outcomes }));
      },
      loadSaved: (id, investigation) => {
        run.current += 1;
        void client().then(({ resetWorker }) => resetWorker());
        setState({ ...initial(), status: 'ready', result: investigation.result, settings: investigation.result.settings, title: investigation.title, notes: investigation.notes, flagged: new Set(investigation.flagged), savedId: id, fromSaved: true });
      },
      setSavedId: (id) => setState((previous) => ({ ...previous, savedId: id })),
      clear: () => {
        run.current += 1;
        void client().then(({ resetWorker }) => resetWorker());
        setState(initial());
      },
    }),
    [state, analyse],
  );

  return <SocContext.Provider value={value}>{children}</SocContext.Provider>;
}

export function useSoc(): SocContextValue {
  const value = useContext(SocContext);
  if (!value) throw new Error('useSoc must be used inside SocProvider');
  return value;
}
