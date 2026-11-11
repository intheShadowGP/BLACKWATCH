// Structural viewers for YARA and Sigma rules. Rules are parsed for display
// only: nothing is compiled, evaluated or executed.

export const MAX_RULE_CHARS = 1_000_000;

// ── YARA ────────────────────────────────────────────────────────────────────

export interface YaraString {
  identifier: string;
  kind: 'text' | 'hex' | 'regex';
  value: string;
  modifiers: string[];
}

export interface YaraRule {
  name: string;
  modifiers: string[];
  tags: string[];
  meta: { key: string; value: string }[];
  strings: YaraString[];
  condition: string;
  /** 1-based line of the rule keyword. */
  line: number;
}

export type YaraParseResult = { ok: true; imports: string[]; includes: string[]; rules: YaraRule[] } | { ok: false; message: string; line: number };

type Token = { type: 'word' | 'string' | 'regex' | 'hex' | 'punct' | 'number'; value: string; line: number; start?: number; end?: number };

/**
 * Tokenises YARA source: comments, quoted strings, regular expressions and hex
 * blocks are read as single tokens before braces are matched, so a brace or a
 * "//" inside a string can never confuse the structure.
 */
function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let line = 1;
  let index = 0;
  const fail = (message: string): never => {
    throw Object.assign(new Error(message), { line });
  };
  const previousAllowsRegex = () => {
    const previous = tokens[tokens.length - 1];
    return previous !== undefined && (previous.value === '=' || previous.value === 'matches');
  };
  while (index < source.length) {
    const start = index;
    const count = tokens.length;
    const char = source[index] as string;
    if (char === '\n') {
      line += 1;
      index += 1;
    } else if (/\s/.test(char)) {
      index += 1;
    } else if (source.startsWith('//', index)) {
      while (index < source.length && source[index] !== '\n') index += 1;
    } else if (source.startsWith('/*', index)) {
      const end = source.indexOf('*/', index + 2);
      if (end < 0) fail('Unterminated comment');
      for (let cursor = index; cursor < end; cursor += 1) if (source[cursor] === '\n') line += 1;
      index = end + 2;
    } else if (char === '"') {
      let cursor = index + 1;
      while (cursor < source.length && source[cursor] !== '"') {
        if (source[cursor] === '\\') cursor += 1;
        if (source[cursor] === '\n') fail('Line break inside a string');
        cursor += 1;
      }
      if (cursor >= source.length) fail('Unterminated string');
      tokens.push({ type: 'string', value: source.slice(index, cursor + 1), line });
      index = cursor + 1;
    } else if (char === '/' && previousAllowsRegex()) {
      let cursor = index + 1;
      while (cursor < source.length && source[cursor] !== '/') {
        if (source[cursor] === '\\') cursor += 1;
        if (source[cursor] === '\n') fail('Line break inside a regular expression');
        cursor += 1;
      }
      if (cursor >= source.length) fail('Unterminated regular expression');
      cursor += 1;
      while (cursor < source.length && /[is]/.test(source[cursor] as string)) cursor += 1;
      tokens.push({ type: 'regex', value: source.slice(index, cursor), line });
      index = cursor;
    } else if (char === '{' && tokens[tokens.length - 1]?.value === '=') {
      const end = source.indexOf('}', index);
      if (end < 0) fail('Unterminated hex string');
      const body = source.slice(index, end + 1);
      tokens.push({ type: 'hex', value: body.replace(/\s+/g, ' '), line });
      for (const c of body) if (c === '\n') line += 1;
      index = end + 1;
    } else if (/[A-Za-z_$#@!]/.test(char)) {
      const match = /^[A-Za-z_$#@!][A-Za-z0-9_*]*/.exec(source.slice(index, index + 256)) as RegExpExecArray;
      tokens.push({ type: 'word', value: match[0], line });
      index += match[0].length;
    } else if (/\d/.test(char)) {
      const match = /^(0x[0-9a-fA-F]+|\d+(KB|MB)?)/.exec(source.slice(index, index + 64)) as RegExpExecArray;
      tokens.push({ type: 'number', value: match[0], line });
      index += match[0].length;
    } else {
      const two = source.slice(index, index + 2);
      const value = ['==', '!=', '<=', '>=', '<<', '>>', '..'].includes(two) ? two : char;
      tokens.push({ type: 'punct', value, line });
      index += value.length;
    }
    if (tokens.length > count) Object.assign(tokens[tokens.length - 1] as Token, { start, end: index });
  }
  return tokens;
}

const STRING_MODIFIERS = new Set(['nocase', 'wide', 'ascii', 'fullword', 'private', 'xor', 'base64', 'base64wide']);

export function parseYara(source: string): YaraParseResult {
  if (source.length > MAX_RULE_CHARS) return { ok: false, message: `Input longer than ${MAX_RULE_CHARS} characters`, line: 1 };
  let tokens: Token[];
  try {
    tokens = tokenize(source);
  } catch (error) {
    return { ok: false, message: (error as Error).message, line: (error as { line?: number }).line ?? 1 };
  }
  const imports: string[] = [];
  const includes: string[] = [];
  const rules: YaraRule[] = [];
  let index = 0;
  const peek = () => tokens[index];
  const fail = (message: string): YaraParseResult => ({ ok: false, message, line: peek()?.line ?? tokens[tokens.length - 1]?.line ?? 1 });

  while (index < tokens.length) {
    const token = peek() as Token;
    if (token.value === 'import' || token.value === 'include') {
      const target = tokens[index + 1];
      if (target?.type !== 'string') return fail(`Expected a quoted name after ${token.value}`);
      (token.value === 'import' ? imports : includes).push(target.value.slice(1, -1));
      index += 2;
      continue;
    }
    const modifiers: string[] = [];
    while (peek()?.value === 'private' || peek()?.value === 'global') {
      modifiers.push((peek() as Token).value);
      index += 1;
    }
    if (peek()?.value !== 'rule') return fail("Expected 'rule'");
    const line = (peek() as Token).line;
    index += 1;
    const name = peek();
    if (name?.type !== 'word' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name.value)) return fail('Expected a rule name');
    index += 1;
    const tags: string[] = [];
    if (peek()?.value === ':') {
      index += 1;
      while (peek()?.type === 'word' && peek()?.value !== '{') {
        tags.push((peek() as Token).value);
        index += 1;
      }
    }
    if (peek()?.value !== '{') return fail("Expected '{' after the rule name");
    index += 1;
    const rule: YaraRule = { name: name.value, modifiers, tags, meta: [], strings: [], condition: '', line };
    let section: 'meta' | 'strings' | 'condition' | null = null;
    const conditionParts: Token[] = [];
    let depth = 0;
    for (;;) {
      const current = peek();
      if (!current) return fail(`Rule ${rule.name} is not closed`);
      if (current.value === '}' && depth === 0) {
        index += 1;
        break;
      }
      if (current.type === 'word' && ['meta', 'strings', 'condition'].includes(current.value) && tokens[index + 1]?.value === ':' && depth === 0) {
        section = current.value as 'meta' | 'strings' | 'condition';
        index += 2;
        continue;
      }
      if (section === 'meta') {
        const value = tokens[index + 2];
        if (current.type !== 'word' || tokens[index + 1]?.value !== '=' || !value) return fail('Invalid meta entry');
        let text = value.value;
        let consumed = 3;
        if (value.value === '-' && tokens[index + 3]?.type === 'number') {
          text = `-${(tokens[index + 3] as Token).value}`;
          consumed = 4;
        }
        rule.meta.push({ key: current.value, value: value.type === 'string' ? text.slice(1, -1) : text });
        index += consumed;
      } else if (section === 'strings') {
        if (current.type !== 'word' || !current.value.startsWith('$') || tokens[index + 1]?.value !== '=') return fail('Invalid string definition');
        const value = tokens[index + 2];
        if (!value || !['string', 'hex', 'regex'].includes(value.type)) return fail(`Invalid value for ${current.value}`);
        index += 3;
        const stringModifiers: string[] = [];
        while (peek()?.type === 'word' && STRING_MODIFIERS.has((peek() as Token).value)) {
          let modifier = (peek() as Token).value;
          index += 1;
          if (peek()?.value === '(') {
            const close = tokens.findIndex((candidate, position) => position > index && candidate.value === ')');
            if (close < 0) return fail('Unclosed modifier arguments');
            modifier += `(${tokens.slice(index + 1, close).map((part) => part.value).join('')})`;
            index = close + 1;
          }
          stringModifiers.push(modifier);
        }
        rule.strings.push({ identifier: current.value, kind: value.type === 'string' ? 'text' : (value.type as 'hex' | 'regex'), value: value.value, modifiers: stringModifiers });
      } else if (section === 'condition') {
        if (current.value === '{' || current.value === '(') depth += current.value === '{' ? 1 : 0;
        if (current.value === '}') depth -= 1;
        conditionParts.push(current);
        index += 1;
      } else {
        return fail("Expected 'meta:', 'strings:' or 'condition:'");
      }
    }
    if (conditionParts.length === 0) return fail(`Rule ${rule.name} has no condition`);
    // The condition is shown as written, with whitespace normalised.
    const first = conditionParts[0] as Token;
    const last = conditionParts[conditionParts.length - 1] as Token;
    rule.condition = source.slice(first.start, last.end).replace(/\s+/g, ' ').trim();
    rules.push(rule);
  }
  return { ok: true, imports, includes, rules };
}

// ── Sigma ───────────────────────────────────────────────────────────────────

export interface SigmaRule {
  title: string;
  id: string | null;
  status: string | null;
  level: string | null;
  description: string | null;
  author: string | null;
  date: string | null;
  references: string[];
  tags: string[];
  /** ATT&CK technique ids derived from tags such as attack.t1059.001. */
  techniques: string[];
  logsource: Record<string, string>;
  /** Named selections, each shown as formatted YAML. */
  detection: { name: string; body: string }[];
  condition: string[];
  falsepositives: string[];
  fields: string[];
}

export type SigmaParseResult = { ok: true; rules: SigmaRule[] } | { ok: false; message: string; line: number | null };

const asText = (value: unknown): string | null => (typeof value === 'string' || typeof value === 'number' ? String(value) : value instanceof Date ? value.toISOString().slice(0, 10) : null);
const asList = (value: unknown): string[] => (Array.isArray(value) ? value.map(asText).filter((item): item is string => item !== null) : asText(value) !== null ? [asText(value) as string] : []);

/** Parses one or more Sigma rules (YAML documents) for display. */
export async function parseSigma(source: string): Promise<SigmaParseResult> {
  if (source.length > MAX_RULE_CHARS) return { ok: false, message: `Input longer than ${MAX_RULE_CHARS} characters`, line: null };
  const { parseAllDocuments, stringify } = await import('yaml');
  // maxAliasCount bounds alias expansion ("billion laughs"); custom tags are not resolved.
  const documents = parseAllDocuments(source, { prettyErrors: true, uniqueKeys: true });
  const list = Array.isArray(documents) ? documents : [documents];
  const rules: SigmaRule[] = [];
  for (const document of list) {
    const error = document.errors[0];
    if (error) return { ok: false, message: error.message.split('\n')[0] ?? error.message, line: error.linePos?.[0]?.line ?? null };
    let data: unknown;
    try {
      data = document.toJS({ maxAliasCount: 100 });
    } catch (caught) {
      return { ok: false, message: (caught as Error).message, line: null };
    }
    if (data === null || data === undefined) continue;
    if (typeof data !== 'object' || Array.isArray(data)) return { ok: false, message: 'A Sigma rule must be a YAML mapping', line: null };
    const rule = data as Record<string, unknown>;
    const detection = rule.detection;
    if (typeof rule.title !== 'string' || typeof detection !== 'object' || detection === null || Array.isArray(detection)) {
      return { ok: false, message: "A Sigma rule needs a 'title' and a 'detection' mapping", line: null };
    }
    const detectionEntries = Object.entries(detection as Record<string, unknown>);
    const tags = asList(rule.tags);
    const logsource = typeof rule.logsource === 'object' && rule.logsource !== null ? Object.fromEntries(Object.entries(rule.logsource as Record<string, unknown>).map(([key, value]) => [key, asText(value) ?? JSON.stringify(value)])) : {};
    rules.push({
      title: rule.title,
      id: asText(rule.id),
      status: asText(rule.status),
      level: asText(rule.level),
      description: asText(rule.description),
      author: asText(rule.author),
      date: asText(rule.date),
      references: asList(rule.references),
      tags,
      techniques: [...new Set(tags.map((tag) => /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(tag)?.[1]?.toUpperCase()).filter((id): id is string => Boolean(id)))],
      logsource,
      detection: detectionEntries.filter(([name]) => name !== 'condition' && name !== 'timeframe').map(([name, body]) => ({ name, body: stringify(body).trimEnd() })),
      condition: asList((detection as Record<string, unknown>).condition),
      falsepositives: asList(rule.falsepositives),
      fields: asList(rule.fields),
    });
  }
  if (rules.length === 0) return { ok: false, message: 'No rule found', line: null };
  return { ok: true, rules };
}
