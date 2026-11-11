// CVSS vector decoding (3.0, 3.1, 4.0) and CVSS 3.x base score computation.
//
// Limits, stated in the interface as well:
// - 3.x: base metrics only; temporal and environmental metrics are ignored.
// - 4.0: the vector is decoded but the score is NOT recomputed (the official
//   algorithm relies on a lookup table of macro-vectors that is not embedded).

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface DecodedMetric {
  /** Metric abbreviation as written in the vector, e.g. "AV". */
  metric: string;
  /** Value abbreviation as written in the vector, e.g. "N". */
  value: string;
  metricName: string;
  valueName: string;
}

const V3_METRICS: Record<string, { name: string; values: Record<string, string> }> = {
  AV: { name: 'Attack Vector', values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
  AC: { name: 'Attack Complexity', values: { L: 'Low', H: 'High' } },
  PR: { name: 'Privileges Required', values: { N: 'None', L: 'Low', H: 'High' } },
  UI: { name: 'User Interaction', values: { N: 'None', R: 'Required' } },
  S: { name: 'Scope', values: { U: 'Unchanged', C: 'Changed' } },
  C: { name: 'Confidentiality', values: { H: 'High', L: 'Low', N: 'None' } },
  I: { name: 'Integrity', values: { H: 'High', L: 'Low', N: 'None' } },
  A: { name: 'Availability', values: { H: 'High', L: 'Low', N: 'None' } },
};

const HLN = { H: 'High', L: 'Low', N: 'None' };
const V4_METRICS: Record<string, { name: string; values: Record<string, string> }> = {
  AV: { name: 'Attack Vector', values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' } },
  AC: { name: 'Attack Complexity', values: { L: 'Low', H: 'High' } },
  AT: { name: 'Attack Requirements', values: { N: 'None', P: 'Present' } },
  PR: { name: 'Privileges Required', values: { N: 'None', L: 'Low', H: 'High' } },
  UI: { name: 'User Interaction', values: { N: 'None', P: 'Passive', A: 'Active' } },
  VC: { name: 'Vulnerable System Confidentiality', values: HLN },
  VI: { name: 'Vulnerable System Integrity', values: HLN },
  VA: { name: 'Vulnerable System Availability', values: HLN },
  SC: { name: 'Subsequent System Confidentiality', values: HLN },
  SI: { name: 'Subsequent System Integrity', values: { ...HLN, S: 'Safety' } },
  SA: { name: 'Subsequent System Availability', values: { ...HLN, S: 'Safety' } },
};

const V3_REQUIRED = Object.keys(V3_METRICS);
const V4_REQUIRED = Object.keys(V4_METRICS);

export interface DecodedVector {
  version: '3.0' | '3.1' | '4.0';
  /** Base metrics, in specification order. */
  base: DecodedMetric[];
  /** Number of additional (non-base) metrics present with a defined value. */
  extraMetrics: number;
}

function splitVector(vector: string): { version: string; pairs: Map<string, string> } | null {
  if (typeof vector !== 'string' || vector.length > 400) return null;
  const [prefix, ...parts] = vector.trim().split('/');
  const version = /^CVSS:(\d\.\d)$/.exec(prefix ?? '')?.[1];
  if (!version) return null;
  const pairs = new Map<string, string>();
  for (const part of parts) {
    const match = /^([A-Za-z]{1,3}):([A-Za-z]{1,8})$/.exec(part);
    if (!match || pairs.has(match[1] as string)) return null;
    pairs.set(match[1] as string, match[2] as string);
  }
  return { version, pairs };
}

/** Decodes a CVSS vector into named base metrics. Returns null for an invalid or unsupported vector. */
export function decodeVector(vector: string): DecodedVector | null {
  const parsed = splitVector(vector);
  if (!parsed) return null;
  const { version, pairs } = parsed;
  const isV3 = version === '3.0' || version === '3.1';
  if (!isV3 && version !== '4.0') return null;
  const table = isV3 ? V3_METRICS : V4_METRICS;
  const required = isV3 ? V3_REQUIRED : V4_REQUIRED;

  const base: DecodedMetric[] = [];
  for (const metric of required) {
    const value = pairs.get(metric);
    const definition = table[metric];
    const valueName = value && definition ? definition.values[value] : undefined;
    if (!value || !definition || !valueName) return null;
    base.push({ metric, value, metricName: definition.name, valueName });
  }
  let extraMetrics = 0;
  for (const [metric, value] of pairs) {
    if (!required.includes(metric) && value !== 'X') extraMetrics += 1;
  }
  return { version: version as DecodedVector['version'], base, extraMetrics };
}

/** Rounding function defined by the CVSS 3.1 specification (Appendix A). */
function roundUp(value: number): number {
  const scaled = Math.round(value * 100000);
  return scaled % 10000 === 0 ? scaled / 100000 : (Math.floor(scaled / 10000) + 1) / 10;
}

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
} as const;

/** Computes the CVSS 3.0 / 3.1 base score from a vector. Returns null if the vector is not a valid 3.x vector. */
export function computeCvss3BaseScore(vector: string): number | null {
  const decoded = decodeVector(vector);
  if (!decoded || decoded.version === '4.0') return null;
  const get = (metric: string) => decoded.base.find((entry) => entry.metric === metric)?.value as string;

  const scope = get('S') as 'U' | 'C';
  const av = WEIGHTS.AV[get('AV') as keyof typeof WEIGHTS.AV];
  const ac = WEIGHTS.AC[get('AC') as keyof typeof WEIGHTS.AC];
  const ui = WEIGHTS.UI[get('UI') as keyof typeof WEIGHTS.UI];
  const pr = WEIGHTS.PR[scope][get('PR') as 'N' | 'L' | 'H'];
  const cia = (metric: string) => WEIGHTS.CIA[get(metric) as keyof typeof WEIGHTS.CIA];

  const iss = 1 - (1 - cia('C')) * (1 - cia('I')) * (1 - cia('A'));
  const impact = scope === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return scope === 'U'
    ? roundUp(Math.min(impact + exploitability, 10))
    : roundUp(Math.min(1.08 * (impact + exploitability), 10));
}

/** Qualitative severity rating scale shared by CVSS 3.x and 4.0. */
export function severityFromScore(score: number): Severity {
  if (score <= 0) return 'NONE';
  if (score < 4) return 'LOW';
  if (score < 7) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}
