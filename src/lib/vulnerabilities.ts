import type { CveItem, Cvss, KevItem } from '../data/schemas';
import type { Severity } from './cvss';

/** One vulnerability as shown in lists: an NVD record, a KEV entry, or both joined on the CVE id. */
export interface VulnRow {
  id: string;
  /** NVD publication date, or the KEV "date added" when no NVD record is loaded. */
  date: string;
  summary: string;
  cve: CveItem | null;
  kev: KevItem | null;
  /** Score used for sorting and prioritisation: the highest base score published for the CVE. */
  cvss: Cvss | null;
  priority: Priority;
}

export type PriorityLevel = 1 | 2 | 3 | 4 | 5;

export type PriorityFactor =
  | 'kev'
  | 'ransomware'
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'unscored'
  | 'patchReference';

export interface Priority {
  level: PriorityLevel;
  /** Facts that produced the level, in order of importance. Every factor comes from published data. */
  factors: PriorityFactor[];
}

/** Highest published base score. CVSS 4.0 and 3.x are different scales; the choice is shown to the user. */
export function bestCvss(cve: CveItem | null): Cvss | null {
  if (!cve) return null;
  const candidates = [cve.cvss4, cve.cvss3].filter((entry): entry is Cvss => entry !== null);
  if (candidates.length === 0) return null;
  return candidates.reduce((best, entry) => (entry.score > best.score ? entry : best));
}

/**
 * Transparent prioritisation.
 *
 *   P1  listed in the CISA KEV catalog (exploitation observed in the wild)
 *   P2  highest base score 9.0 – 10.0
 *   P3  highest base score 7.0 – 8.9
 *   P4  highest base score 4.0 – 6.9
 *   P5  lower score, or no score published yet
 *
 * Not considered, because the application has no data about it: whether the
 * affected product is deployed or exposed in the analyst's environment.
 */
export function prioritize(cve: CveItem | null, kev: KevItem | null): Priority {
  const factors: PriorityFactor[] = [];
  const cvss = bestCvss(cve);
  let level: PriorityLevel;

  if (kev) {
    level = 1;
    factors.push('kev');
    if (kev.ransomware === 'Known') factors.push('ransomware');
  } else if (!cvss) {
    level = 5;
  } else if (cvss.score >= 9) {
    level = 2;
  } else if (cvss.score >= 7) {
    level = 3;
  } else if (cvss.score >= 4) {
    level = 4;
  } else {
    level = 5;
  }

  if (!cvss) factors.push('unscored');
  else if (cvss.score >= 9) factors.push('critical');
  else if (cvss.score >= 7) factors.push('high');
  else if (cvss.score >= 4) factors.push('medium');
  else factors.push('low');

  if (cve?.references.some((reference) => reference.tags.includes('Patch'))) {
    factors.push('patchReference');
  }
  return { level, factors };
}

export function toRow(cve: CveItem | null, kev: KevItem | null): VulnRow | null {
  const id = cve?.id ?? kev?.cve;
  if (!id) return null;
  return {
    id,
    date: cve?.published ?? (kev as KevItem).dateAdded,
    summary: cve?.description || kev?.description || '',
    cve,
    kev,
    cvss: bestCvss(cve),
    priority: prioritize(cve, kev),
  };
}

export type SeverityFilter = 'all' | Severity | 'UNSCORED';
export type SortKey = 'date' | 'score' | 'priority';

export interface VulnQuery {
  text: string;
  severity: SeverityFilter;
  sort: SortKey;
}

export function filterRows(rows: readonly VulnRow[], query: VulnQuery): VulnRow[] {
  const needles = query.text.toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8);
  const filtered = rows.filter((row) => {
    if (query.severity === 'UNSCORED' ? row.cvss !== null : query.severity !== 'all' && row.cvss?.severity !== query.severity) {
      return false;
    }
    if (needles.length === 0) return true;
    const haystack = [
      row.id,
      row.summary,
      row.kev?.vendor,
      row.kev?.product,
      row.kev?.name,
      row.cve?.products.join(' '),
      row.cve?.cwes.join(' '),
      row.kev?.cwes.join(' '),
    ]
      .join(' ')
      .toLowerCase();
    return needles.every((needle) => haystack.includes(needle));
  });

  const byDate = (a: VulnRow, b: VulnRow) => b.date.localeCompare(a.date) || a.id.localeCompare(b.id);
  if (query.sort === 'score') {
    filtered.sort((a, b) => (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) || byDate(a, b));
  } else if (query.sort === 'priority') {
    filtered.sort(
      (a, b) => a.priority.level - b.priority.level || (b.cvss?.score ?? -1) - (a.cvss?.score ?? -1) || byDate(a, b),
    );
  } else {
    filtered.sort(byDate);
  }
  return filtered;
}

export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/;
