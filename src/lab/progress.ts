// Lab progress, stored in this browser only. Each attempt records the scenario
// version it was played on; an attempt on older content is shown as such and
// never re-scored against new questions.

import { z } from 'zod';
import { db as defaultDb, type BlackwatchDb } from '../lib/db';

export const progressSchema = z.object({
  scenarioVersion: z.number().int().positive(),
  /** Step id → selected option ids. A step present here is locked (feedback shown). */
  answers: z.record(z.string().max(64), z.array(z.string().max(64)).max(20)),
  startedAt: z.string(),
  completedAt: z.string().nullable(),
  /** Score at completion, frozen with the version it was earned on. */
  score: z.object({ total: z.number().int().nonnegative(), max: z.number().int().positive() }).nullable(),
});

export type Progress = z.infer<typeof progressSchema>;

export function emptyProgress(version: number): Progress {
  return { scenarioVersion: version, answers: {}, startedAt: new Date().toISOString(), completedAt: null, score: null };
}

export async function loadProgress(scenarioId: string, database: BlackwatchDb = defaultDb): Promise<Progress | null> {
  const record = await database.labProgress.get(scenarioId);
  if (!record) return null;
  const parsed = progressSchema.safeParse(record.data);
  return parsed.success ? parsed.data : null;
}

export async function loadAllProgress(database: BlackwatchDb = defaultDb): Promise<Record<string, Progress>> {
  const records = await database.labProgress.toArray();
  const out: Record<string, Progress> = {};
  for (const record of records) {
    const parsed = progressSchema.safeParse(record.data);
    if (parsed.success) out[record.scenarioId] = parsed.data;
  }
  return out;
}

export async function saveProgress(scenarioId: string, progress: Progress, database: BlackwatchDb = defaultDb): Promise<boolean> {
  try {
    await database.labProgress.put({ scenarioId, data: progressSchema.parse(progress), updatedAt: new Date().toISOString() });
    return true;
  } catch {
    return false;
  }
}

export async function clearProgress(scenarioId: string, database: BlackwatchDb = defaultDb): Promise<void> {
  await database.labProgress.delete(scenarioId);
}
