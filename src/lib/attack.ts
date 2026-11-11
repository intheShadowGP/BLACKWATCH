import type { AttackDataset } from '../data/schemas';

export type AttackKind = 'tactic' | 'technique' | 'group' | 'software' | 'campaign' | 'mitigation' | 'detection';

export interface AttackObject {
  id: string;
  kind: AttackKind;
  name: string;
  description: string;
}

export function kindOfAttackId(id: string): AttackKind | null {
  if (/^TA\d{4}$/.test(id)) return 'tactic';
  if (/^DET\d{4}$/.test(id)) return 'detection';
  if (/^T\d{4}(\.\d{3})?$/.test(id)) return 'technique';
  if (/^G\d{4}$/.test(id)) return 'group';
  if (/^S\d{4}$/.test(id)) return 'software';
  if (/^C\d{4}$/.test(id)) return 'campaign';
  if (/^M\d{4}$/.test(id)) return 'mitigation';
  return null;
}

const URL_SEGMENTS: Record<AttackKind, string> = {
  tactic: 'tactics',
  technique: 'techniques',
  group: 'groups',
  software: 'software',
  campaign: 'campaigns',
  mitigation: 'mitigations',
  detection: 'detectionstrategies',
};

/** Canonical page of an object on attack.mitre.org, for the full, untruncated text. */
export function attackUrl(id: string): string | null {
  const kind = kindOfAttackId(id);
  if (!kind) return null;
  return `https://attack.mitre.org/${URL_SEGMENTS[kind]}/${id.replace('.', '/')}/`;
}

type RelationName = keyof AttackDataset['relations'];

export interface AttackIndex {
  data: AttackDataset;
  get: (id: string) => AttackObject | null;
  /** Targets of a relation for a source id, e.g. related('groupTechnique', 'G0016'). */
  related: (relation: RelationName, sourceId: string) => string[];
  /** Sources of a relation for a target id, e.g. relatedTo('groupTechnique', 'T1059'). */
  relatedTo: (relation: RelationName, targetId: string) => string[];
  subTechniques: (techniqueId: string) => AttackDataset['techniques'];
  techniquesOfTactic: (shortname: string) => AttackDataset['techniques'];
}

export function buildAttackIndex(data: AttackDataset): AttackIndex {
  const objects = new Map<string, AttackObject>();
  const put = (kind: AttackKind, list: readonly { id: string; name: string; description?: string }[]) => {
    for (const item of list) {
      objects.set(item.id, { id: item.id, kind, name: item.name, description: item.description ?? '' });
    }
  };
  put('tactic', data.tactics);
  put('technique', data.techniques);
  put('group', data.groups);
  put('software', data.software);
  put('campaign', data.campaigns);
  put('mitigation', data.mitigations);
  put('detection', data.detections);

  const forward = new Map<string, string[]>();
  const backward = new Map<string, string[]>();
  const push = (map: Map<string, string[]>, key: string, value: string) => {
    const list = map.get(key);
    if (list) list.push(value);
    else map.set(key, [value]);
  };
  for (const [relation, pairs] of Object.entries(data.relations)) {
    for (const [source, target] of pairs) {
      // Pairs that reference an object absent from the dataset are ignored.
      if (!objects.has(source) || !objects.has(target)) continue;
      push(forward, `${relation}|${source}`, target);
      push(backward, `${relation}|${target}`, source);
    }
  }

  const children = new Map<string, AttackDataset['techniques']>();
  const byTactic = new Map<string, AttackDataset['techniques']>();
  for (const technique of data.techniques) {
    if (technique.parent) {
      const list = children.get(technique.parent);
      if (list) list.push(technique);
      else children.set(technique.parent, [technique]);
    } else {
      for (const tactic of technique.tactics) {
        const list = byTactic.get(tactic);
        if (list) list.push(technique);
        else byTactic.set(tactic, [technique]);
      }
    }
  }
  for (const list of byTactic.values()) list.sort((a, b) => a.name.localeCompare(b.name));

  return {
    data,
    get: (id) => objects.get(id) ?? null,
    related: (relation, sourceId) => forward.get(`${relation}|${sourceId}`) ?? [],
    relatedTo: (relation, targetId) => backward.get(`${relation}|${targetId}`) ?? [],
    subTechniques: (techniqueId) => children.get(techniqueId) ?? [],
    techniquesOfTactic: (shortname) => byTactic.get(shortname) ?? [],
  };
}

/** Case-insensitive match on id, name and (optionally) aliases; every word must match. */
export function matchesQuery(query: string, ...fields: (string | readonly string[] | undefined)[]): boolean {
  const needles = query.toLowerCase().split(/\s+/).filter(Boolean).slice(0, 8);
  if (needles.length === 0) return true;
  const haystack = fields.flat().join(' ').toLowerCase();
  return needles.every((needle) => haystack.includes(needle));
}
