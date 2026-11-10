import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { BlackwatchDb, SCHEMA_VERSION, TABLE_NAMES } from './db';
import { defaultPreferences } from './preferences';
import {
  countRecords,
  deleteAllData,
  exportAllData,
  exportFileName,
  loadPreferences,
  savePreferences,
} from './storage';

const fallback = defaultPreferences(['en']);
let database: BlackwatchDb;
let sequence = 0;

beforeEach(() => {
  sequence += 1;
  database = new BlackwatchDb(`blackwatch-test-${sequence}`);
});

afterEach(async () => {
  await database.delete();
});

/** A database whose every operation fails, as when IndexedDB is blocked by the browser. */
function brokenDatabase(): BlackwatchDb {
  const broken = new BlackwatchDb(`blackwatch-broken-${sequence}`);
  broken.close();
  broken.open = () => Promise.reject(new Error('IndexedDB is disabled')) as ReturnType<BlackwatchDb['open']>;
  return broken;
}

describe('preferences persistence', () => {
  it('returns defaults from an empty database', async () => {
    expect(await loadPreferences(fallback, database)).toEqual({ preferences: fallback, persistent: true });
  });

  it('round-trips saved preferences', async () => {
    const next = { ...fallback, language: 'fr' as const, theme: 'light' as const };
    expect(await savePreferences(next, database)).toBe(true);
    expect((await loadPreferences(fallback, database)).preferences).toEqual(next);
  });

  it('recovers from a corrupted record', async () => {
    await database.kv.put({ key: 'preferences', value: { theme: '<svg onload=alert(1)>' }, updatedAt: 'x' });
    expect((await loadPreferences(fallback, database)).preferences).toEqual(fallback);
  });

  it('refuses to store invalid preferences', async () => {
    const invalid = { ...fallback, theme: 'neon' } as unknown as typeof fallback;
    expect(await savePreferences(invalid, database)).toBe(false);
    expect(await database.kv.count()).toBe(0);
  });

  it('reports non-persistent defaults when storage fails', async () => {
    const broken = brokenDatabase();
    expect(await loadPreferences(fallback, broken)).toEqual({ preferences: fallback, persistent: false });
    expect(await savePreferences(fallback, broken)).toBe(false);
  });
});

describe('local data control', () => {
  beforeEach(async () => {
    await savePreferences(fallback, database);
    await database.notes.put({ id: 'n1', scope: 'test', body: 'note', updatedAt: '2026-01-01T00:00:00.000Z' });
    await database.favorites.put({ id: 'f1', kind: 'cve', ref: 'x', label: 'x', createdAt: '2026-01-01T00:00:00.000Z' });
  });

  it('counts records per store', async () => {
    const counts = await countRecords(database);
    expect(Object.keys(counts).sort()).toEqual([...TABLE_NAMES].sort());
    expect(counts).toMatchObject({ kv: 1, notes: 1, favorites: 1, investigations: 0, labProgress: 0, cache: 0 });
  });

  it('exports every store with provenance metadata', async () => {
    const bundle = await exportAllData('9.9.9', database);
    expect(bundle.application).toBe('BLACKWATCH');
    expect(bundle.applicationVersion).toBe('9.9.9');
    expect(bundle.schemaVersion).toBe(SCHEMA_VERSION);
    expect(Number.isNaN(Date.parse(bundle.exportedAt))).toBe(false);
    expect(Object.keys(bundle.tables).sort()).toEqual([...TABLE_NAMES].sort());
    expect(bundle.tables.notes).toEqual([
      { id: 'n1', scope: 'test', body: 'note', updatedAt: '2026-01-01T00:00:00.000Z' },
    ]);
    expect(() => JSON.stringify(bundle)).not.toThrow();
  });

  it('deletes every record', async () => {
    await deleteAllData(database);
    const counts = await countRecords(database);
    expect(Object.values(counts).every((count) => count === 0)).toBe(true);
  });

  it('rejects when storage is unavailable', async () => {
    const broken = brokenDatabase();
    await expect(countRecords(broken)).rejects.toThrow();
    await expect(exportAllData('1', broken)).rejects.toThrow();
    await expect(deleteAllData(broken)).rejects.toThrow();
  });
});

describe('exportFileName', () => {
  it('builds a filesystem-safe name', () => {
    const name = exportFileName(new Date('2026-03-04T05:06:07.089Z'));
    expect(name).toBe('blackwatch-export-2026-03-04T05-06-07-089Z.json');
    expect(name).toMatch(/^[\w.-]+$/);
  });
});
