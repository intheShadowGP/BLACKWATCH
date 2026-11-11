import { analyzeInputs, type AnalysisResult } from '../lib/analysis';
import type { LogEvent, LogFormat, TimeSettings } from '../lib/model';
import { evaluateSigma } from '../lib/sigma';

export type SocRequest =
  | { id: number; kind: 'analyze'; files: File[]; settings: TimeSettings; overrides: Record<number, LogFormat> }
  | { id: number; kind: 'sigma'; source: string };

export type SocResponse =
  | { id: number; kind: 'analysis'; result: AnalysisResult }
  | { id: number; kind: 'sigma'; outcomes: Awaited<ReturnType<typeof evaluateSigma>> }
  | { id: number; kind: 'error'; message: string };

// The worker keeps the last events so Sigma rules can run without sending them back.
let lastEvents: LogEvent[] = [];

self.onmessage = async (message: MessageEvent<SocRequest>) => {
  const request = message.data;
  try {
    if (request.kind === 'analyze') {
      // Files are read one at a time, only when reached, and not at all once the event cap is hit.
      const inputs = request.files.map((file) => ({ name: file.name, size: file.size, lastModified: file.lastModified, bytes: async () => new Uint8Array(await file.arrayBuffer()) }));
      const result: AnalysisResult = await analyzeInputs(inputs, request.settings, request.overrides);
      lastEvents = result.events;
      self.postMessage({ id: request.id, kind: 'analysis', result } satisfies SocResponse);
    } else {
      self.postMessage({ id: request.id, kind: 'sigma', outcomes: await evaluateSigma(request.source, lastEvents) } satisfies SocResponse);
    }
  } catch (error) {
    self.postMessage({ id: request.id, kind: 'error', message: error instanceof Error ? error.message : 'Analysis failed' } satisfies SocResponse);
  }
};
