// Runs analyses in a dedicated worker; falls back to the main thread when
// workers are unavailable (the work is the same, only responsiveness differs).

import { analyzeInputs, type AnalysisResult } from './lib/analysis';
import { MAX_FILE_BYTES, type LogEvent, type LogFormat, type TimeSettings } from './lib/model';
import { evaluateSigma, type SigmaOutcome } from './lib/sigma';
import type { SocRequest, SocResponse } from './workers/soc.worker';

let worker: Worker | null = null;
let fallbackEvents: LogEvent[] = [];

function request(message: SocRequest): Promise<SocResponse> {
  if (!worker) worker = new Worker(new URL('./workers/soc.worker.ts', import.meta.url), { type: 'module' });
  const active = worker;
  return new Promise((resolve) => {
    active.onmessage = (event: MessageEvent<SocResponse>) => resolve(event.data);
    active.onerror = () => {
      active.terminate();
      worker = null;
      resolve({ kind: 'error', message: 'worker' });
    };
    active.postMessage(message);
  });
}

export async function analyzeFiles(files: readonly File[], settings: TimeSettings, overrides: Record<number, LogFormat>): Promise<AnalysisResult> {
  if (typeof Worker === 'undefined') {
    const inputs = await Promise.all(
      files.map(async (file) => ({ name: file.name, size: file.size, lastModified: file.lastModified, bytes: file.size > MAX_FILE_BYTES ? null : new Uint8Array(await file.arrayBuffer()) })),
    );
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

/** Replaces the worker's event set, e.g. after loading a saved investigation. */
export function resetWorker(): void {
  worker?.terminate();
  worker = null;
}
