import { analyzeInputs, type AnalysisResult } from '../lib/analysis';
import { MAX_FILE_BYTES, type LogEvent, type LogFormat, type TimeSettings } from '../lib/model';
import { evaluateSigma } from '../lib/sigma';

export type SocRequest =
  | { kind: 'analyze'; files: File[]; settings: TimeSettings; overrides: Record<number, LogFormat> }
  | { kind: 'sigma'; source: string };

export type SocResponse =
  | { kind: 'analysis'; result: AnalysisResult }
  | { kind: 'sigma'; outcomes: Awaited<ReturnType<typeof evaluateSigma>> }
  | { kind: 'error'; message: string };

// The worker keeps the last events so Sigma rules can run without sending them back.
let lastEvents: LogEvent[] = [];

self.onmessage = async (message: MessageEvent<SocRequest>) => {
  const request = message.data;
  try {
    if (request.kind === 'analyze') {
      const inputs = await Promise.all(
        request.files.map(async (file) => ({
          name: file.name,
          size: file.size,
          lastModified: file.lastModified,
          bytes: file.size > MAX_FILE_BYTES ? null : new Uint8Array(await file.arrayBuffer()),
        })),
      );
      const result = await analyzeInputs(inputs, request.settings, request.overrides);
      lastEvents = result.events;
      self.postMessage({ kind: 'analysis', result } satisfies SocResponse);
    } else {
      self.postMessage({ kind: 'sigma', outcomes: await evaluateSigma(request.source, lastEvents) } satisfies SocResponse);
    }
  } catch (error) {
    self.postMessage({ kind: 'error', message: error instanceof Error ? error.message : 'Analysis failed' } satisfies SocResponse);
  }
};
