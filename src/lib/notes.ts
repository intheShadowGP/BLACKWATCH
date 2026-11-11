import { db as defaultDb, type BlackwatchDb, type NoteRecord } from './db';

export const MAX_NOTE_LENGTH = 20_000;

export async function listNotes(scope: string, database: BlackwatchDb = defaultDb): Promise<NoteRecord[]> {
  const notes = await database.notes.where('scope').equals(scope).toArray();
  return notes.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

export async function saveNote(
  scope: string,
  body: string,
  id: string = crypto.randomUUID(),
  database: BlackwatchDb = defaultDb,
): Promise<NoteRecord> {
  const note: NoteRecord = { id, scope, body: body.slice(0, MAX_NOTE_LENGTH), updatedAt: new Date().toISOString() };
  await database.notes.put(note);
  return note;
}

export async function deleteNote(id: string, database: BlackwatchDb = defaultDb): Promise<void> {
  await database.notes.delete(id);
}
