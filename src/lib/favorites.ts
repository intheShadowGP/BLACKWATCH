import { useCallback, useEffect, useState } from 'react';
import { db as defaultDb, type BlackwatchDb, type FavoriteRecord } from './db';

export type FavoriteKind = 'cve' | 'attack';

const key = (kind: FavoriteKind, ref: string) => `${kind}:${ref}`;

export async function listFavorites(kind?: FavoriteKind, database: BlackwatchDb = defaultDb): Promise<FavoriteRecord[]> {
  const records = kind
    ? await database.favorites.where('kind').equals(kind).toArray()
    : await database.favorites.toArray();
  return records.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function addFavorite(
  kind: FavoriteKind,
  ref: string,
  label: string,
  database: BlackwatchDb = defaultDb,
): Promise<void> {
  await database.favorites.put({
    id: key(kind, ref),
    kind,
    ref: ref.slice(0, 200),
    label: label.slice(0, 300),
    createdAt: new Date().toISOString(),
  });
}

export async function removeFavorite(kind: FavoriteKind, ref: string, database: BlackwatchDb = defaultDb): Promise<void> {
  await database.favorites.delete(key(kind, ref));
}

export interface FavoritesState {
  /** References (for example CVE ids) currently saved, most recent first. */
  refs: string[];
  has: (ref: string) => boolean;
  toggle: (ref: string, label: string) => void;
  /** False when local storage cannot be used: the list then only lives in memory. */
  persistent: boolean;
}

export function useFavorites(kind: FavoriteKind): FavoritesState {
  const [refs, setRefs] = useState<string[]>([]);
  const [persistent, setPersistent] = useState(true);

  useEffect(() => {
    let cancelled = false;
    listFavorites(kind)
      .then((records) => {
        if (!cancelled) setRefs(records.map((record) => record.ref));
      })
      .catch(() => {
        if (!cancelled) setPersistent(false);
      });
    return () => {
      cancelled = true;
    };
  }, [kind]);

  const toggle = useCallback(
    (ref: string, label: string) => {
      const saved = refs.includes(ref);
      setRefs(saved ? refs.filter((value) => value !== ref) : [ref, ...refs]);
      const operation = saved ? removeFavorite(kind, ref) : addFavorite(kind, ref, label);
      operation.catch(() => setPersistent(false));
    },
    [kind, refs],
  );

  const has = useCallback((ref: string) => refs.includes(ref), [refs]);
  return { refs, has, toggle, persistent };
}
