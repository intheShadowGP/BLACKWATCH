// Runs analyses in a dedicated worker; falls back to the main thread when
// workers are unavailable (the work is the same, only responsiveness differs).
// Every request carries an id and every reply is matched to its request, so
// overlapping analyses can never receive each other's results.

import { analyzeInputs, type AnalysisResult } from './lib/analysis';
import type { LogEvent, LogFormat, TimeSettings } from './lib/model';
import { evaluateSigma, type SigmaOutcome } from './lib/sigma';
import type { SocRequest, SocResponse } from './workers/soc.worker';

type Pending = (response: SocResponse) => void;

let worker: Worker | null = null;
let nextId = 0;
const pending = new Map<number, Pending>();
let fallbackEvents: LogEvent[] = [];

function ensureWorker(): Worker {
  if (worker) return worker;
  const created = new Worker(new URL('./workers/soc.worker.ts', import.meta.url), { type: 'module' });
  created.onmessage = (event: MessageEvent<SocResponse>) => {
    const resolve = pending.get(event.data.id);
    if (!resolve) return;
    pending.delete(event.data.id);
    resolve(event.data);
  };
  created.onerror = () => {
    for (const [id, resolve] of pending) resolve({ id, kind: 'error', message: 'worker' });
    pending.clear();
    created.terminate();
    if (worker === created) worker = null;
  };
  worker = created;
  return created;
}

type Outgoing = { kind: 'analyze'; files: File[]; settings: TimeSettings; overrides: Record<number, LogFormat> } | { kind: 'sigma'; source: string };

function request(message: Outgoing): Promise<SocResponse> {
  const target = ensureWorker();
  nextId += 1;
  const id = nextId;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    target.postMessage({ ...message, id } as SocRequest);
  });
}

export async function analyzeFiles(files: readonly File[], settings: TimeSettings, overrides: Record<number, LogFormat>): Promise<AnalysisResult> {
  if (typeof Worker === 'undefined') {
    const inputs = files.map((file) => ({ name: file.name, size: file.size, lastModified: file.lastModified, bytes: async () => new Uint8Array(await file.arrayBuffer()) }));
    const result = await analyzeInputs(inputs, settings, overrides);
    fallbackEvents = result.events;
    return result;
  }
  const response = await request({ kind: 'analyze', files: [...files], settings, overrides });
  if (response.kind !== 'analysis') throw new Error(response.kind === 'error' ? response.message : 'unexpected response');
  return response.result;
}

/** Evaluates Sigma rules against the events of the last analysis. */
export async function runSigma(source: string, events: readonly LogEvent[]): Promise<SigmaOutcome[]> {
  if (typeof Worker === 'undefined' || worker === null) return evaluateSigma(source, events.length > 0 ? events : fallbackEvents);
  const response = await request({ kind: 'sigma', source });
  if (response.kind !== 'sigma') throw new Error(response.kind === 'error' ? response.message : 'unexpected response');
  return response.outcomes;
}

/** Discards the worker and its events, e.g. after loading a saved investigation. */
export function resetWorker(): void {
  for (const [id, resolve] of pending) resolve({ id, kind: 'error', message: 'reset' });
  pending.clear();
  worker?.terminate();
  worker = null;
}
