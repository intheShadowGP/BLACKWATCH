// Saved investigations. Imported logs are sensitive: they are stored only when
// the analyst saves explicitly, in this browser's IndexedDB, and are validated
// again when read back.

import { z } from 'zod';
import { db as defaultDb, type BlackwatchDb } from '../../lib/db';
import type { AnalysisResult } from './analysis';

export const INVESTIGATION_VERSION = 1;

/**
 * Largest investigation that can be saved. Saving 100,000 events took 0.4 s in
 * Chromium; a 500,000-event save did not complete within 5 minutes, so larger
 * investigations are refused rather than left hanging.
 */
export const MAX_SAVED_EVENTS = 100_000;

const eventSchema = z.object({
  id: z.number().int(),
  file: z.number().int(),
  line: z.number().int(),
  timestamp: z.number().nullable(),
  timeQuality: z.enum(['exact', 'inferred', 'missing']),
  format: z.string(),
  host: z.string().nullable(),
  program: z.string().nullable(),
  message: z.string().max(5000),
  category: z.string(),
  user: z.string().nullable(),
  srcIp: z.string().nullable(),
  count: z.number().int().nonnegative(),
  http: z.unknown().nullable(),
  windows: z.unknown().nullable(),
  fields: z.record(z.string(), z.string()),
});

export const investigationSchema = z.object({
  version: z.literal(INVESTIGATION_VERSION),
  title: z.string().max(200),
  notes: z.string().max(100_000),
  flagged: z.array(z.number().int()).max(100_000),
  result: z.object({
    files: z.array(z.object({ name: z.string(), size: z.number(), sha256: z.string().nullable(), status: z.string() }).passthrough()).max(100),
    events: z.array(eventSchema).max(100_000),
    detections: z.object({ findings: z.array(z.object({ rule: z.string(), eventIds: z.array(z.number()) }).passthrough()), excludedWithoutTime: z.record(z.string(), z.number()) }),
    settings: z.object({ endYear: z.number().int(), offsetMinutes: z.number().int() }),
    truncated: z.boolean(),
    analysedAt: z.string(),
  }),
});

export interface StoredInvestigation {
  version: typeof INVESTIGATION_VERSION;
  title: string;
  notes: string;
  flagged: number[];
  result: AnalysisResult;
}

export interface InvestigationSummary {
  id: string;
  title: string;
  updatedAt: string;
  events: number;
  findings: number;
}

export type SaveResult = { ok: true; id: string } | { ok: false; reason: 'quota' | 'unavailable' | 'tooLarge' };

export async function saveInvestigation(investigation: StoredInvestigation, id: string = crypto.randomUUID(), database: BlackwatchDb = defaultDb): Promise<SaveResult> {
  if (investigation.result.events.length > MAX_SAVED_EVENTS) return { ok: false, reason: 'tooLarge' };
  try {
    await database.investigations.put({ id, title: investigation.title.slice(0, 200), data: investigation, updatedAt: new Date().toISOString() });
    return { ok: true, id };
  } catch (error) {
    const name = (error as { name?: string; inner?: { name?: string } }).inner?.name ?? (error as { name?: string }).name;
    return { ok: false, reason: name === 'QuotaExceededError' ? 'quota' : 'unavailable' };
  }
}

export async function listInvestigations(database: BlackwatchDb = defaultDb): Promise<InvestigationSummary[]> {
  const records = await database.investigations.orderBy('updatedAt').reverse().toArray();
  return records.map((record) => {
    const data = record.data as Partial<StoredInvestigation> | undefined;
    return {
      id: record.id,
      title: record.title,
      updatedAt: record.updatedAt,
      events: Array.isArray(data?.result?.events) ? data.result.events.length : 0,
      findings: Array.isArray(data?.result?.detections?.findings) ? data.result.detections.findings.length : 0,
    };
  });
}

/** Returns null when the record is missing or fails validation (corrupted or from another version). */
export async function loadInvestigation(id: string, database: BlackwatchDb = defaultDb): Promise<StoredInvestigation | null> {
  const record = await database.investigations.get(id);
  if (!record) return null;
  const parsed = investigationSchema.safeParse(record.data);
  return parsed.success ? (parsed.data as unknown as StoredInvestigation) : null;
}

export async function deleteInvestigation(id: string, database: BlackwatchDb = defaultDb): Promise<void> {
  await database.investigations.delete(id);
}
