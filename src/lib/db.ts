import Dexie, { type Table } from 'dexie';

/** Version of the local IndexedDB schema. Bump together with a Dexie migration. */
export const SCHEMA_VERSION = 1;

export const TABLE_NAMES = [
  'kv',
  'favorites',
  'notes',
  'investigations',
  'labProgress',
  'cache',
] as const;
export type TableName = (typeof TABLE_NAMES)[number];

export interface KvRecord {
  key: string;
  value: unknown;
  updatedAt: string;
}

export interface FavoriteRecord {
  id: string;
  kind: string;
  ref: string;
  label: string;
  createdAt: string;
}

export interface NoteRecord {
  id: string;
  scope: string;
  body: string;
  updatedAt: string;
}

export interface InvestigationRecord {
  id: string;
  title: string;
  data: unknown;
  updatedAt: string;
}

export interface LabProgressRecord {
  scenarioId: string;
  data: unknown;
  updatedAt: string;
}

export interface CacheRecord {
  key: string;
  value: unknown;
  storedAt: string;
}

export class BlackwatchDb extends Dexie {
  kv!: Table<KvRecord, string>;
  favorites!: Table<FavoriteRecord, string>;
  notes!: Table<NoteRecord, string>;
  investigations!: Table<InvestigationRecord, string>;
  labProgress!: Table<LabProgressRecord, string>;
  cache!: Table<CacheRecord, string>;

  constructor(name = 'blackwatch') {
    super(name);
    this.version(SCHEMA_VERSION).stores({
      kv: 'key',
      favorites: 'id, kind, createdAt',
      notes: 'id, scope, updatedAt',
      investigations: 'id, updatedAt',
      labProgress: 'scenarioId, updatedAt',
      cache: 'key, storedAt',
    });
  }
}

export const db = new BlackwatchDb();
