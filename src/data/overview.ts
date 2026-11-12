// Overview figures: the single implementation used by the data pipeline (to
// publish overview.json) and by the application (when the summary is absent or
// does not match the published datasets). Imported directly by Node.js, so it
// keeps to erasable TypeScript syntax and explicit .ts import paths.

import { bestCvss } from '../lib/vulnerabilities.ts';
import type { CveDataset, KevDataset, KevSummary, OverviewSummary, RecentSummary } from './schemas.ts';

const DAY = 86_400_000;
/** Number of rows the Overview lists for KEV additions and critical CVEs. */
export const OVERVIEW_LIST_SIZE = 6;

/**
 * KEV figures. Windows are anchored on the retrieval time of the dataset (or
 * its release date), never on the current time, so they describe the data.
 */
export function summarizeKev(data: KevDataset, retrievedAt: string | null): KevSummary {
  const anchor = Date.parse(retrievedAt ?? data.dateReleased);
  const end = new Date(anchor);
  const months: KevSummary['months'] = [];
  for (let offset = 11; offset >= 0; offset -= 1) {
    const month = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() - offset, 1)).toISOString().slice(0, 7);
    months.push({ label: month, value: data.items.filter((item) => item.dateAdded.startsWith(month)).length });
  }
  return {
    total: data.items.length,
    added30: data.items.filter((item) => anchor - Date.parse(item.dateAdded) <= 30 * DAY).length,
    ransomware: data.items.filter((item) => item.ransomware === 'Known').length,
    months,
    latest: data.items.slice(0, OVERVIEW_LIST_SIZE).map(({ cve, dateAdded, name }) => ({ cve, dateAdded, name })),
  };
}

/** Severity distribution of recent CVEs (highest published base score), and the highest-scored ones. */
export function summarizeRecent(data: CveDataset, kevIds: ReadonlySet<string>): RecentSummary {
  const buckets: RecentSummary['buckets'] = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0, UNSCORED: 0 };
  const scored = data.items.map((item) => ({ item, cvss: bestCvss(item) }));
  for (const { cvss } of scored) {
    if (!cvss) buckets.UNSCORED += 1;
    else buckets[cvss.severity] += 1;
  }
  const critical: RecentSummary['critical'] = [];
  for (const { item, cvss } of scored
    .filter((entry) => entry.cvss !== null && entry.cvss.score >= 9)
    .sort((a, b) => (b.cvss?.score ?? 0) - (a.cvss?.score ?? 0) || b.item.published.localeCompare(a.item.published))
    .slice(0, OVERVIEW_LIST_SIZE)) {
    if (cvss) critical.push({ id: item.id, published: item.published, description: item.description, cvss });
  }
  return {
    total: scored.length,
    inKev: scored.filter((entry) => kevIds.has(entry.item.id)).length,
    buckets,
    critical,
  };
}

export interface OverviewInput {
  kev: { data: KevDataset; retrievedAt: string | null; sha256: string } | null;
  recent: { data: CveDataset; sha256: string } | null;
}

/** The complete summary as published in overview.json. */
export function buildOverviewSummary(input: OverviewInput, generatedAt: string, schemaVersion: OverviewSummary['schemaVersion']): OverviewSummary {
  const kevIds = new Set(input.kev ? input.kev.data.items.map((item) => item.cve) : []);
  return {
    schemaVersion,
    generatedAt,
    sources: { kev: input.kev?.sha256 ?? null, 'nvd-recent': input.recent?.sha256 ?? null },
    kev: input.kev ? summarizeKev(input.kev.data, input.kev.retrievedAt) : null,
    recent: input.recent ? summarizeRecent(input.recent.data, kevIds) : null,
  };
}
