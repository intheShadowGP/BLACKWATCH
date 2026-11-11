// Evaluation of a documented subset of Sigma against imported events.
//
// Supported:
//   - detection selections as a map (all fields must match) or a list of maps
//     (any map), with a value or a list of values per field (any value; all
//     values with the "all" modifier);
//   - keyword lists (any keyword contained in the event message);
//   - value modifiers: contains, startswith, endswith, all; matching is
//     case-insensitive, with * and ? wildcards in plain values;
//   - null values (field absent or empty);
//   - conditions with and, or, not, parentheses, "1 of x*", "all of x*",
//     "1 of them" and "all of them".
// Anything else (regular expressions, cidr, base64 and other modifiers,
// aggregations, timeframes, correlations) makes the rule unsupported: it is
// rejected with the reason and never evaluated partially.
//
// Matching only compares strings with the operations above. Nothing in a rule
// is compiled to code or to a regular expression.

import type { LogEvent } from './model';

export type SigmaOutcome =
  | { status: 'matched'; title: string; level: string | null; eventIds: number[]; candidates: number; missingFields: string[] }
  | { status: 'noMatch'; title: string; level: string | null; candidates: number; missingFields: string[] }
  | { status: 'notApplicable'; title: string; reason: 'noLogsource' | 'noFields'; detail: string }
  | { status: 'unsupported'; title: string; reason: string }
  | { status: 'invalid'; reason: string };

type Matcher = (event: LogEvent) => boolean;
type FieldValue = string | number | boolean | null;

const SUPPORTED_MODIFIERS = new Set(['contains', 'startswith', 'endswith', 'all']);

/** Field names understood in addition to source fields, per Sigma taxonomy where one exists. */
export const FIELD_ALIASES: Readonly<Record<string, (event: LogEvent) => string | null>> = {
  EventID: (event) => (event.windows ? String(event.windows.eventId) : null),
  Provider_Name: (event) => event.windows?.provider ?? null,
  Channel: (event) => event.windows?.channel ?? null,
  Computer: (event) => event.host,
  User: (event) => event.user,
  message: (event) => event.message,
  Message: (event) => event.message,
  SourceIp: (event) => event.srcIp,
  Image: (event) => event.windows?.data.NewProcessName ?? event.fields.Image ?? null,
  ParentImage: (event) => event.windows?.data.ParentProcessName ?? event.fields.ParentImage ?? null,
  'c-ip': (event) => (event.http ? event.srcIp : null),
  'cs-method': (event) => event.http?.method ?? null,
  'cs-uri-stem': (event) => event.http?.path?.split('?')[0] ?? null,
  'cs-uri-query': (event) => (event.http?.path?.includes('?') ? (event.http.path.split('?').slice(1).join('?') ?? null) : null),
  'cs-uri': (event) => event.http?.path ?? null,
  'sc-status': (event) => (event.http?.status === null || event.http?.status === undefined ? null : String(event.http.status)),
  'cs-user-agent': (event) => event.http?.userAgent ?? null,
  'cs-referer': (event) => event.http?.referrer ?? null,
};

export function fieldValue(event: LogEvent, field: string): string | null {
  const alias = FIELD_ALIASES[field];
  if (alias) {
    const value = alias(event);
    if (value !== null) return value;
  }
  return event.windows?.data[field] ?? event.fields[field] ?? null;
}

/** Case-insensitive glob with * and ?; escape with backslash. */
export function globMatch(pattern: string, value: string): boolean {
  const p = pattern.toLowerCase();
  const v = value.toLowerCase();
  // Iterative wildcard matching (no regular expression, linear backtracking bound).
  let pi = 0;
  let vi = 0;
  let star = -1;
  let mark = 0;
  while (vi < v.length) {
    let char = p[pi];
    let escaped = false;
    if (char === '\\' && (p[pi + 1] === '*' || p[pi + 1] === '?' || p[pi + 1] === '\\')) {
      char = p[pi + 1];
      escaped = true;
    }
    if (char !== undefined && ((!escaped && char === '?') || char === v[vi]) && !(char === '*' && !escaped)) {
      pi += escaped ? 2 : 1;
      vi += 1;
    } else if (char === '*' && !escaped) {
      star = pi;
      mark = vi;
      pi += 1;
    } else if (star >= 0) {
      pi = star + 1;
      mark += 1;
      vi = mark;
    } else return false;
  }
  while (p[pi] === '*') pi += 1;
  return pi === p.length;
}

class Unsupported extends Error {}

function valueMatcher(field: string, modifiers: string[], raw: FieldValue): (actual: string | null) => boolean {
  if (raw === null) return (actual) => actual === null || actual === '';
  const expected = String(raw);
  const lower = expected.toLowerCase();
  if (modifiers.includes('contains')) return (actual) => actual !== null && actual.toLowerCase().includes(lower);
  if (modifiers.includes('startswith')) return (actual) => actual !== null && actual.toLowerCase().startsWith(lower);
  if (modifiers.includes('endswith')) return (actual) => actual !== null && actual.toLowerCase().endsWith(lower);
  void field;
  return (actual) => actual !== null && globMatch(expected, actual);
}

function selectionMatcher(name: string, body: unknown, fieldsUsed: Set<string>): Matcher {
  if (Array.isArray(body)) {
    if (body.every((item) => typeof item === 'string' || typeof item === 'number')) {
      const keywords = body.map((item) => String(item).toLowerCase());
      return (event) => keywords.some((keyword) => (keyword.includes('*') || keyword.includes('?') ? globMatch(`*${keyword}*`, event.message) : event.message.toLowerCase().includes(keyword)));
    }
    if (body.every((item) => typeof item === 'object' && item !== null && !Array.isArray(item))) {
      const matchers = body.map((item, index) => selectionMatcher(`${name}[${index}]`, item, fieldsUsed));
      return (event) => matchers.some((matcher) => matcher(event));
    }
    throw new Unsupported(`selection ${name} mixes keywords and field maps`);
  }
  if (typeof body !== 'object' || body === null) throw new Unsupported(`selection ${name} is neither a map nor a list`);
  const clauses: Matcher[] = Object.entries(body as Record<string, unknown>).map(([key, value]) => {
    const [field, ...modifiers] = key.split('|');
    if (!field) throw new Unsupported(`selection ${name} uses keyword modifiers without a field`);
    for (const modifier of modifiers) if (!SUPPORTED_MODIFIERS.has(modifier)) throw new Unsupported(`modifier "${modifier}" (${key})`);
    fieldsUsed.add(field);
    const values = Array.isArray(value) ? value : [value];
    if (values.some((item) => typeof item === 'object' && item !== null)) throw new Unsupported(`nested value in ${key}`);
    const matchers = values.map((item) => valueMatcher(field, modifiers, item as FieldValue));
    const all = modifiers.includes('all');
    return (event: LogEvent) => {
      const actual = fieldValue(event, field);
      return all ? matchers.every((matcher) => matcher(actual)) : matchers.some((matcher) => matcher(actual));
    };
  });
  return (event) => clauses.every((clause) => clause(event));
}

/** Recursive-descent parser for the supported condition grammar. */
function conditionMatcher(condition: string, selections: Record<string, Matcher>): Matcher {
  if (condition.includes('|')) throw new Unsupported('aggregation in condition');
  const tokens = condition.match(/\(|\)|[^\s()]+/g) ?? [];
  let position = 0;
  const peek = () => tokens[position]?.toLowerCase();
  const names = Object.keys(selections);
  const resolve = (pattern: string): Matcher[] => {
    const matched = pattern === 'them' ? names : names.filter((name) => globMatch(pattern, name));
    if (matched.length === 0) throw new Unsupported(`no selection matches "${pattern}"`);
    return matched.map((name) => selections[name] as Matcher);
  };
  const primary = (): Matcher => {
    const token = tokens[position];
    if (token === undefined) throw new Unsupported('incomplete condition');
    if (token === '(') {
      position += 1;
      const inner = expression();
      if (tokens[position] !== ')') throw new Unsupported('unbalanced parentheses');
      position += 1;
      return inner;
    }
    if (/^(1|all|any)$/i.test(token) && tokens[position + 1]?.toLowerCase() === 'of') {
      const target = tokens[position + 2];
      if (!target) throw new Unsupported('incomplete "of" expression');
      position += 3;
      const matchers = resolve(target);
      return token.toLowerCase() === 'all' ? (event) => matchers.every((matcher) => matcher(event)) : (event) => matchers.some((matcher) => matcher(event));
    }
    if (/^\d+$/.test(token)) throw new Unsupported(`"${token} of" quantifier`);
    position += 1;
    const selection = selections[token];
    if (!selection) throw new Unsupported(`unknown selection "${token}"`);
    return selection;
  };
  const unary = (): Matcher => {
    if (peek() === 'not') {
      position += 1;
      const inner = unary();
      return (event) => !inner(event);
    }
    return primary();
  };
  const conjunction = (): Matcher => {
    let left = unary();
    while (peek() === 'and') {
      position += 1;
      const right = unary();
      const previous = left;
      left = (event) => previous(event) && right(event);
    }
    return left;
  };
  const expression = (): Matcher => {
    let left = conjunction();
    while (peek() === 'or') {
      position += 1;
      const right = conjunction();
      const previous = left;
      left = (event) => previous(event) || right(event);
    }
    return left;
  };
  const result = expression();
  if (position < tokens.length) throw new Unsupported(`unexpected "${tokens[position]}" in condition`);
  return result;
}

/** Events a rule can apply to, according to its logsource; null when the logsource is unknown. */
function candidatesFor(logsource: Record<string, unknown>, events: readonly LogEvent[]): { events: LogEvent[]; known: boolean } {
  const product = typeof logsource.product === 'string' ? logsource.product.toLowerCase() : null;
  const category = typeof logsource.category === 'string' ? logsource.category.toLowerCase() : null;
  const service = typeof logsource.service === 'string' ? logsource.service.toLowerCase() : null;
  let list: LogEvent[] = [...events];
  let known = false;
  if (product === 'windows') {
    list = list.filter((event) => event.windows !== null);
    known = true;
    if (service) list = list.filter((event) => (event.windows?.channel ?? '').toLowerCase().includes(service) || service === 'security' && event.windows?.channel === 'Security');
    if (category === 'process_creation') list = list.filter((event) => event.windows?.eventId === 4688);
  } else if (product === 'linux') {
    list = list.filter((event) => event.format === 'syslog' || (event.format === 'json' && event.program !== null));
    known = true;
    if (service === 'auth' || service === 'sshd') list = list.filter((event) => event.category !== 'other' && event.category !== 'httpRequest');
  }
  if (category === 'webserver') {
    list = list.filter((event) => event.http !== null);
    known = true;
  }
  return { events: list, known: known || (product === null && category === null && service === null) };
}

export async function evaluateSigma(source: string, events: readonly LogEvent[]): Promise<SigmaOutcome[]> {
  const { parseAllDocuments } = await import('yaml');
  const documents = parseAllDocuments(source.slice(0, 1_000_000), { uniqueKeys: true });
  const list = Array.isArray(documents) ? documents : [documents];
  const outcomes: SigmaOutcome[] = [];
  for (const document of list) {
    if (document.errors[0]) {
      outcomes.push({ status: 'invalid', reason: document.errors[0].message.split('\n')[0] ?? 'YAML error' });
      continue;
    }
    let data: unknown;
    try {
      data = document.toJS({ maxAliasCount: 100 });
    } catch (error) {
      outcomes.push({ status: 'invalid', reason: (error as Error).message });
      continue;
    }
    if (data === null || data === undefined) continue;
    const rule = data as Record<string, unknown>;
    const title = typeof rule.title === 'string' ? rule.title : '(untitled)';
    const level = typeof rule.level === 'string' ? rule.level : null;
    const detection = rule.detection;
    if (typeof detection !== 'object' || detection === null || Array.isArray(detection)) {
      outcomes.push({ status: 'invalid', reason: `${title}: no detection mapping` });
      continue;
    }
    try {
      const { condition, timeframe, ...named } = detection as Record<string, unknown>;
      if (timeframe !== undefined) throw new Unsupported('timeframe');
      if (rule.correlation !== undefined) throw new Unsupported('correlation rule');
      const fieldsUsed = new Set<string>();
      const selections = Object.fromEntries(Object.entries(named).map(([name, body]) => [name, selectionMatcher(name, body, fieldsUsed)]));
      const conditions = Array.isArray(condition) ? condition : [condition];
      if (conditions.some((item) => typeof item !== 'string' || item.trim() === '')) throw new Unsupported('missing or non-text condition');
      const matcher = conditions.map((item) => conditionMatcher(item as string, selections)).reduce((acc, next) => (event: LogEvent) => acc(event) || next(event));
      const logsource = typeof rule.logsource === 'object' && rule.logsource !== null ? (rule.logsource as Record<string, unknown>) : {};
      const { events: candidates, known } = candidatesFor(logsource, events);
      if (!known || candidates.length === 0) {
        outcomes.push({ status: 'notApplicable', title, reason: 'noLogsource', detail: JSON.stringify(logsource) });
        continue;
      }
      const missing = [...fieldsUsed].filter((field) => !candidates.some((event) => fieldValue(event, field) !== null));
      if (fieldsUsed.size > 0 && missing.length === fieldsUsed.size) {
        outcomes.push({ status: 'notApplicable', title, reason: 'noFields', detail: missing.join(', ') });
        continue;
      }
      const matched = candidates.filter(matcher).map((event) => event.id);
      outcomes.push(matched.length > 0 ? { status: 'matched', title, level, eventIds: matched, candidates: candidates.length, missingFields: missing } : { status: 'noMatch', title, level, candidates: candidates.length, missingFields: missing });
    } catch (error) {
      if (error instanceof Unsupported) outcomes.push({ status: 'unsupported', title, reason: error.message });
      else throw error;
    }
  }
  return outcomes;
}
