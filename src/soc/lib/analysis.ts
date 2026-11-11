// End-to-end analysis of imported files: read, identify, parse, number and
// detect. Runs in a worker in the browser; also callable directly (tests).

import { toHex } from '../../toolbox/lib/bytes';
import { runDetections, type DetectionResult } from './detections';
import { MAX_EVENTS, MAX_FILE_BYTES, type LogEvent, type LogFormat, type ParseStats, type TimeSettings } from './model';
import { decodeText, detectBinary, detectFormat, parseText, type BinaryKind } from './parsers';

export interface InputFile {
  name: string;
  size: number;
  lastModified: number;
  /** Bytes, or a loader called only when the file is reached (files are read one at a time). */
  bytes: Uint8Array | null | (() => Promise<Uint8Array>);
}

export type FileStatus = 'parsed' | 'tooLarge' | 'binary' | 'unknownFormat' | 'empty' | 'notReadLimit';

export interface FileReport {
  index: number;
  name: string;
  size: number;
  sha256: string | null;
  status: FileStatus;
  binary: BinaryKind | null;
  detectedFormat: LogFormat | null;
  format: LogFormat | null;
  stats: ParseStats | null;
}

export interface AnalysisResult {
  files: FileReport[];
  events: LogEvent[];
  detections: DetectionResult;
  settings: TimeSettings;
  /** True when the event cap was reached and later events were not read. */
  truncated: boolean;
  analysedAt: string;
}

async function sha256(bytes: Uint8Array): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as BufferSource)));
}

export async function analyzeInputs(inputs: readonly InputFile[], settings: TimeSettings, overrides: Readonly<Record<number, LogFormat>> = {}): Promise<AnalysisResult> {
  const files: FileReport[] = [];
  const events: LogEvent[] = [];
  let truncated = false;
  for (const [index, input] of inputs.entries()) {
    const base = { index, name: input.name.slice(0, 255), size: input.size, sha256: null, binary: null, detectedFormat: null, format: null, stats: null };
    if (events.length >= MAX_EVENTS) {
      files.push({ ...base, status: 'notReadLimit' });
      continue;
    }
    if (input.size > MAX_FILE_BYTES || input.bytes === null) {
      files.push({ ...base, status: 'tooLarge' });
      continue;
    }
    const bytes = typeof input.bytes === 'function' ? await input.bytes() : input.bytes;
    const digest = await sha256(bytes);
    if (bytes.length === 0) {
      files.push({ ...base, sha256: digest, status: 'empty' });
      continue;
    }
    const binary = detectBinary(bytes);
    if (binary) {
      files.push({ ...base, sha256: digest, status: 'binary', binary });
      continue;
    }
    const text = decodeText(bytes);
    const detected = detectFormat(text, input.name);
    const format = overrides[index] ?? detected;
    if (!format) {
      files.push({ ...base, sha256: digest, status: 'unknownFormat' });
      continue;
    }
    const remaining = MAX_EVENTS - events.length;
    const parsed = parseText(text, format, settings);
    if (parsed.events.length > remaining) {
      truncated = true;
      parsed.stats.truncated = true;
    }
    if (parsed.stats.truncated) truncated = true;
    for (let position = 0; position < Math.min(parsed.events.length, remaining); position += 1) {
      events.push({ ...(parsed.events[position] as Omit<LogEvent, 'id' | 'file'>), id: events.length, file: index });
    }
    files.push({ ...base, sha256: digest, status: 'parsed', detectedFormat: detected, format, stats: parsed.stats });
  }
  return { files, events, detections: runDetections(events), settings, truncated, analysedAt: new Date().toISOString() };
}
