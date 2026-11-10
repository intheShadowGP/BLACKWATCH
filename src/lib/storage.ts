import { db as defaultDb, SCHEMA_VERSION, TABLE_NAMES, type BlackwatchDb, type TableName } from './db';
import { parsePreferences, preferencesSchema, type Preferences } from './preferences';

const PREFERENCES_KEY = 'preferences';

export interface LoadedPreferences {
  preferences: Preferences;
  /** False when IndexedDB could not be read: preferences then live in memory only. */
  persistent: boolean;
}

export async function loadPreferences(
  fallback: Preferences,
  database: BlackwatchDb = defaultDb,
): Promise<LoadedPreferences> {
  try {
    const record = await database.kv.get(PREFERENCES_KEY);
    return { preferences: parsePreferences(record?.value, fallback), persistent: true };
  } catch {
    return { preferences: { ...fallback }, persistent: false };
  }
}

/** Returns false when the write failed (storage disabled, quota exceeded, private mode…). */
export async function savePreferences(
  preferences: Preferences,
  database: BlackwatchDb = defaultDb,
): Promise<boolean> {
  try {
    const value = preferencesSchema.parse(preferences);
    await database.kv.put({ key: PREFERENCES_KEY, value, updatedAt: new Date().toISOString() });
    return true;
  } catch {
    return false;
  }
}

export type RecordCounts = Record<TableName, number>;

export async function countRecords(database: BlackwatchDb = defaultDb): Promise<RecordCounts> {
  const entries = await Promise.all(
    TABLE_NAMES.map(async (name) => [name, await database.table(name).count()] as const),
  );
  return Object.fromEntries(entries) as RecordCounts;
}

export interface ExportBundle {
  application: 'BLACKWATCH';
  applicationVersion: string;
  schemaVersion: number;
  exportedAt: string;
  tables: Record<TableName, unknown[]>;
}

export async function exportAllData(
  applicationVersion: string,
  database: BlackwatchDb = defaultDb,
): Promise<ExportBundle> {
  const entries = await Promise.all(
    TABLE_NAMES.map(async (name) => [name, await database.table(name).toArray()] as const),
  );
  return {
    application: 'BLACKWATCH',
    applicationVersion,
    schemaVersion: SCHEMA_VERSION,
    exportedAt: new Date().toISOString(),
    tables: Object.fromEntries(entries) as Record<TableName, unknown[]>,
  };
}

/** Erases every record of every store in a single transaction. */
export async function deleteAllData(database: BlackwatchDb = defaultDb): Promise<void> {
  const tables = TABLE_NAMES.map((name) => database.table(name));
  await database.transaction('rw', tables, async () => {
    await Promise.all(tables.map((table) => table.clear()));
  });
}

export function exportFileName(date: Date): string {
  const stamp = date.toISOString().replace(/[:.]/g, '-');
  return `blackwatch-export-${stamp}.json`;
}

/** Hands a JSON document to the browser as a local file download. Nothing leaves the device. */
export function downloadJson(fileName: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}
