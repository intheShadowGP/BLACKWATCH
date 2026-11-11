// Built-in detection rules. Each rule states its parameters; each finding
// lists the events that produced it, so every result can be checked by hand.
// Events without a readable timestamp are excluded from time-window rules and
// counted, so a quiet result never hides unusable data.

import type { EventCategory, LogEvent } from './model';

export type Severity = 'high' | 'medium' | 'low';

export type RuleId =
  | 'remoteBruteForce'
  | 'passwordSpraying'
  | 'userFailures'
  | 'successAfterFailures'
  | 'rootLogin'
  | 'privilegeEscalation'
  | 'accountChanges'
  | 'logCleared'
  | 'encodedPowerShell'
  | 'suspiciousWebRequest'
  | 'webScanning'
  | 'requestBurst';

export interface RuleDefinition {
  id: RuleId;
  severity: Severity;
  /** MITRE ATT&CK technique identifiers (Enterprise). */
  techniques: readonly string[];
  params: Readonly<Record<string, number>>;
  /** True when the rule counts events inside a time window. */
  windowed: boolean;
}

const MINUTE = 60_000;

export const RULES: readonly RuleDefinition[] = [
  { id: 'remoteBruteForce', severity: 'high', techniques: ['T1110.001'], params: { threshold: 10, windowMinutes: 5 }, windowed: true },
  { id: 'passwordSpraying', severity: 'high', techniques: ['T1110.003'], params: { distinctUsers: 5, windowMinutes: 30 }, windowed: true },
  { id: 'userFailures', severity: 'medium', techniques: ['T1110'], params: { threshold: 5, windowMinutes: 10 }, windowed: true },
  { id: 'successAfterFailures', severity: 'high', techniques: ['T1110', 'T1078'], params: { failures: 5, windowMinutes: 30 }, windowed: true },
  { id: 'rootLogin', severity: 'medium', techniques: ['T1078.003'], params: {}, windowed: false },
  { id: 'privilegeEscalation', severity: 'medium', techniques: ['T1548.003'], params: {}, windowed: false },
  { id: 'accountChanges', severity: 'medium', techniques: ['T1136', 'T1098'], params: {}, windowed: false },
  { id: 'logCleared', severity: 'high', techniques: ['T1685.005'], params: {}, windowed: false },
  { id: 'encodedPowerShell', severity: 'high', techniques: ['T1059.001'], params: {}, windowed: false },
  { id: 'suspiciousWebRequest', severity: 'medium', techniques: ['T1190'], params: {}, windowed: false },
  { id: 'webScanning', severity: 'medium', techniques: ['T1595.002', 'T1595.003'], params: { clientErrors: 20, windowMinutes: 5 }, windowed: true },
  { id: 'requestBurst', severity: 'low', techniques: [], params: { requests: 300, windowMinutes: 1 }, windowed: true },
];

export interface Finding {
  key: string;
  rule: RuleId;
  severity: Severity;
  entity: { kind: 'ip' | 'user' | 'host' | 'event'; value: string };
  /** Contributing event ids, in time order. */
  eventIds: number[];
  /** Occurrences represented (sum of event counts). */
  count: number;
  first: number | null;
  last: number | null;
  /** Rule-specific facts, keyed for translation. */
  detail: Record<string, string | number>;
}

export interface DetectionResult {
  findings: Finding[];
  /** Per rule: events of the relevant kind excluded because they had no usable timestamp. */
  excludedWithoutTime: Partial<Record<RuleId, number>>;
}

const FAILURES: ReadonlySet<EventCategory> = new Set(['authFailure']);

/**
 * Marks the events that lie in at least one window of `windowMs` whose weight
 * reaches `threshold`, then groups marked events separated by less than a
 * window into bursts.
 */
export function windowBursts(events: readonly LogEvent[], windowMs: number, threshold: number, weight: (event: LogEvent) => number = (event) => event.count): LogEvent[][] {
  const sorted = [...events].sort((a, b) => (a.timestamp as number) - (b.timestamp as number) || a.id - b.id);
  const marked = new Array<boolean>(sorted.length).fill(false);
  let start = 0;
  let sum = 0;
  for (let end = 0; end < sorted.length; end += 1) {
    sum += weight(sorted[end] as LogEvent);
    while ((sorted[end] as LogEvent).timestamp as number - ((sorted[start] as LogEvent).timestamp as number) > windowMs) {
      sum -= weight(sorted[start] as LogEvent);
      start += 1;
    }
    if (sum >= threshold) for (let index = start; index <= end; index += 1) marked[index] = true;
  }
  const bursts: LogEvent[][] = [];
  let current: LogEvent[] = [];
  sorted.forEach((event, index) => {
    if (!marked[index]) return;
    const previous = current[current.length - 1];
    if (previous && (event.timestamp as number) - (previous.timestamp as number) > windowMs) {
      bursts.push(current);
      current = [];
    }
    current.push(event);
  });
  if (current.length > 0) bursts.push(current);
  return bursts;
}

function groupBy(events: readonly LogEvent[], key: (event: LogEvent) => string | null): Map<string, LogEvent[]> {
  const groups = new Map<string, LogEvent[]>();
  for (const event of events) {
    const value = key(event);
    if (value === null) continue;
    const list = groups.get(value);
    if (list) list.push(event);
    else groups.set(value, [event]);
  }
  return groups;
}

const sumCounts = (events: readonly LogEvent[]) => events.reduce((total, event) => total + event.count, 0);

function finding(rule: RuleDefinition, entity: Finding['entity'], events: readonly LogEvent[], detail: Record<string, string | number> = {}): Finding {
  const times = events.map((event) => event.timestamp).filter((time): time is number => time !== null);
  return {
    key: `${rule.id}|${entity.kind}|${entity.value}|${events[0]?.id ?? 0}`,
    rule: rule.id,
    severity: rule.severity,
    entity,
    eventIds: events.map((event) => event.id),
    count: sumCounts(events),
    first: times.length > 0 ? Math.min(...times) : null,
    last: times.length > 0 ? Math.max(...times) : null,
    detail,
  };
}

// ── Web request patterns ────────────────────────────────────────────────────

export const WEB_PATTERNS: readonly { id: string; pattern: RegExp }[] = [
  { id: 'traversal', pattern: /(?:\.\.[/\\])|(?:[/\\]\.\.(?:$|[?#]))/ },
  { id: 'sqlInjection', pattern: /\bunion\b[\s\S]{0,40}\bselect\b|\bselect\b[\s\S]{1,60}\bfrom\b|'\s*or\s*'?\d+'?\s*=\s*'?\d|\bsleep\(\s*\d|\bbenchmark\(|information_schema|\bwaitfor\s+delay\b|;\s*drop\s+table/i },
  { id: 'xss', pattern: /<\s*script|javascript:|\bon(?:error|load|mouseover|focus)\s*=|<\s*(?:svg|img|iframe)\b[^>]*\bon\w+\s*=/i },
  { id: 'commandInjection', pattern: /[;|`]\s*(?:cat|id|whoami|uname|wget|curl|nc|bash|sh|powershell|ping)\b|\$\(|\/bin\/(?:ba)?sh\b|\bcmd\.exe\b/i },
  { id: 'jndi', pattern: /\$\{\s*jndi\s*:/i },
  { id: 'sensitiveFile', pattern: /\/(?:\.env\b|\.git\/|\.svn\/|\.htaccess|\.htpasswd|wp-config\.php|etc\/passwd|etc\/shadow|id_rsa|\.aws\/credentials|web\.config|phpinfo\.php)/i },
  { id: 'webShell', pattern: /\/(?:shell|cmd|c99|r57|wso|webshell|b374k)\.(?:php|aspx?|jsp)\b/i },
];

export const SCANNER_AGENTS = /sqlmap|nikto|nmap|masscan|zgrab|nuclei|gobuster|dirbuster|wpscan|acunetix|nessus|openvas|ffuf|feroxbuster|wfuzz|whatweb|httpx|jaeles/i;

/** Decodes percent-encoding up to twice (double encoding is a common evasion). */
export function decodeTwice(value: string): string {
  let current = value;
  for (let round = 0; round < 2; round += 1) {
    try {
      const next = decodeURIComponent(current.replace(/\+/g, ' '));
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

export function matchWebPatterns(event: LogEvent): string[] {
  if (!event.http) return [];
  const targets = [decodeTwice(event.http.path ?? ''), event.http.userAgent ?? '', event.http.referrer ?? ''];
  return WEB_PATTERNS.filter(({ pattern }) => targets.some((target) => pattern.test(target))).map(({ id }) => id);
}

const SENSITIVE_COMMAND = /(?:^|\/)(?:ba|z|da|k|c|tc)?sh(?:\s|$)|\/etc\/(?:sudoers|passwd|shadow)|visudo|\bchmod\s+[0-7]*[4-7][0-7]{3}\b|\bsu\s+-?\s*$/;

// ── Rules ───────────────────────────────────────────────────────────────────

export function runDetections(events: readonly LogEvent[]): DetectionResult {
  const findings: Finding[] = [];
  const excluded: Partial<Record<RuleId, number>> = {};
  const rule = (id: RuleId) => RULES.find((candidate) => candidate.id === id) as RuleDefinition;
  const timed = (list: readonly LogEvent[], id: RuleId) => {
    const missing = list.filter((event) => event.timestamp === null).length;
    if (missing > 0) excluded[id] = (excluded[id] ?? 0) + missing;
    return list.filter((event) => event.timestamp !== null);
  };

  const failures = events.filter((event) => FAILURES.has(event.category));
  const successes = events.filter((event) => event.category === 'authSuccess');

  // Remote brute force: failures from one source address.
  {
    const definition = rule('remoteBruteForce');
    const window = (definition.params.windowMinutes as number) * MINUTE;
    for (const [ip, list] of groupBy(timed(failures.filter((event) => event.srcIp), definition.id), (event) => event.srcIp)) {
      for (const burst of windowBursts(list, window, definition.params.threshold as number)) {
        findings.push(finding(definition, { kind: 'ip', value: ip }, burst, { users: new Set(burst.map((event) => event.user ?? '?')).size }));
      }
    }
  }

  // Password spraying: one source failing for many distinct accounts.
  {
    const definition = rule('passwordSpraying');
    const window = (definition.params.windowMinutes as number) * MINUTE;
    const minimum = definition.params.distinctUsers as number;
    for (const [ip, list] of groupBy(timed(failures.filter((event) => event.srcIp && event.user), definition.id), (event) => event.srcIp)) {
      const sorted = [...list].sort((a, b) => (a.timestamp as number) - (b.timestamp as number));
      const contributing = new Set<LogEvent>();
      let start = 0;
      for (let end = 0; end < sorted.length; end += 1) {
        while ((sorted[end] as LogEvent).timestamp as number - ((sorted[start] as LogEvent).timestamp as number) > window) start += 1;
        const slice = sorted.slice(start, end + 1);
        if (new Set(slice.map((event) => event.user)).size >= minimum) slice.forEach((event) => contributing.add(event));
      }
      if (contributing.size > 0) {
        const burst = sorted.filter((event) => contributing.has(event));
        findings.push(finding(definition, { kind: 'ip', value: ip }, burst, { users: new Set(burst.map((event) => event.user)).size }));
      }
    }
  }

  // Repeated failures against one account, from any source.
  {
    const definition = rule('userFailures');
    const window = (definition.params.windowMinutes as number) * MINUTE;
    for (const [user, list] of groupBy(timed(failures.filter((event) => event.user), definition.id), (event) => (event.user as string).toLowerCase())) {
      for (const burst of windowBursts(list, window, definition.params.threshold as number)) {
        findings.push(finding(definition, { kind: 'user', value: user }, burst, { sources: new Set(burst.map((event) => event.srcIp ?? '?')).size }));
      }
    }
  }

  // Success after failures from the same source or for the same account.
  {
    const definition = rule('successAfterFailures');
    const window = (definition.params.windowMinutes as number) * MINUTE;
    const minimum = definition.params.failures as number;
    const timedFailures = timed(failures, definition.id);
    for (const success of timed(successes, definition.id)) {
      const time = success.timestamp as number;
      const prior = timedFailures.filter(
        (event) =>
          (event.timestamp as number) <= time &&
          time - (event.timestamp as number) <= window &&
          ((success.srcIp !== null && event.srcIp === success.srcIp) || (success.user !== null && event.user?.toLowerCase() === success.user.toLowerCase())),
      );
      if (sumCounts(prior) >= minimum) {
        findings.push(finding(definition, success.srcIp ? { kind: 'ip', value: success.srcIp } : { kind: 'user', value: success.user as string }, [...prior, success], { user: success.user ?? '?', failures: sumCounts(prior) }));
      }
    }
  }

  // Direct root logins over SSH.
  {
    const definition = rule('rootLogin');
    for (const event of successes) {
      if (event.user === 'root' && event.fields.service === 'ssh') findings.push(finding(definition, { kind: 'ip', value: event.srcIp ?? '?' }, [event], { method: event.fields.method ?? '?' }));
    }
  }

  // Privilege escalation indicators.
  {
    const definition = rule('privilegeEscalation');
    for (const event of events) {
      let reason: string | null = null;
      if (event.category === 'sudoNotAllowed') reason = 'notInSudoers';
      else if (event.category === 'sudoFailure') reason = 'sudoFailure';
      else if (event.category === 'suFailure') reason = 'suFailure';
      else if (event.category === 'sudoCommand' && event.fields.targetUser === 'root' && SENSITIVE_COMMAND.test(event.fields.command ?? '')) reason = 'rootShell';
      if (reason) findings.push(finding(definition, { kind: 'user', value: event.user ?? '?' }, [event], { reason, command: event.fields.command ?? '' }));
    }
  }

  // Account creation and group membership changes.
  {
    const definition = rule('accountChanges');
    for (const event of events) {
      if (event.category === 'accountCreated') findings.push(finding(definition, { kind: 'user', value: event.user ?? '?' }, [event], { reason: 'created' }));
      if (event.category === 'groupMemberAdded') findings.push(finding(definition, { kind: 'user', value: event.user ?? '?' }, [event], { reason: 'groupAdded', group: event.fields.group ?? event.windows?.data.TargetUserName ?? '?' }));
    }
  }

  // Cleared Windows event logs.
  {
    const definition = rule('logCleared');
    for (const event of events) if (event.category === 'logCleared') findings.push(finding(definition, { kind: 'host', value: event.host ?? '?' }, [event], { user: event.user ?? '?' }));
  }

  // Encoded PowerShell command lines (Windows process creation or any log message).
  {
    const definition = rule('encodedPowerShell');
    const encoded = /(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s[-/]e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{16,}/i;
    for (const event of events) {
      const commandLine = event.windows?.data.CommandLine ?? event.fields.CommandLine ?? event.message;
      if (encoded.test(commandLine)) findings.push(finding(definition, { kind: 'host', value: event.host ?? '?' }, [event], { user: event.user ?? '?' }));
    }
  }

  const requests = events.filter((event) => event.category === 'httpRequest' && event.http);

  // Suspicious web requests, grouped by source address.
  {
    const definition = rule('suspiciousWebRequest');
    const matched = new Map<string, { events: LogEvent[]; kinds: Set<string> }>();
    for (const event of requests) {
      const kinds = matchWebPatterns(event);
      if (kinds.length === 0) continue;
      const key = event.srcIp ?? '?';
      const entry = matched.get(key) ?? { events: [], kinds: new Set<string>() };
      entry.events.push(event);
      kinds.forEach((kind) => entry.kinds.add(kind));
      matched.set(key, entry);
    }
    for (const [ip, entry] of matched) findings.push(finding(definition, { kind: 'ip', value: ip }, entry.events, { kinds: [...entry.kinds].sort().join(', ') }));
  }

  // Scanning: bursts of client errors, or a known scanner user agent.
  {
    const definition = rule('webScanning');
    const window = (definition.params.windowMinutes as number) * MINUTE;
    const errors = timed(requests.filter((event) => (event.http?.status ?? 0) >= 400 && (event.http?.status ?? 0) < 500), definition.id);
    const flagged = new Set<string>();
    for (const [ip, list] of groupBy(errors, (event) => event.srcIp)) {
      for (const burst of windowBursts(list, window, definition.params.clientErrors as number)) {
        findings.push(finding(definition, { kind: 'ip', value: ip }, burst, { reason: 'clientErrors' }));
        flagged.add(ip);
      }
    }
    for (const [ip, list] of groupBy(requests.filter((event) => SCANNER_AGENTS.test(event.http?.userAgent ?? '')), (event) => event.srcIp)) {
      if (flagged.has(ip)) continue;
      findings.push(finding(definition, { kind: 'ip', value: ip }, list, { reason: 'scannerAgent', agent: (SCANNER_AGENTS.exec(list[0]?.http?.userAgent ?? '')?.[0] ?? '').toLowerCase() }));
    }
  }

  // Request bursts from one address.
  {
    const definition = rule('requestBurst');
    const window = (definition.params.windowMinutes as number) * MINUTE;
    for (const [ip, list] of groupBy(timed(requests, definition.id), (event) => event.srcIp)) {
      for (const burst of windowBursts(list, window, definition.params.requests as number)) findings.push(finding(definition, { kind: 'ip', value: ip }, burst));
    }
  }

  const order: Record<Severity, number> = { high: 0, medium: 1, low: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity] || (a.first ?? 0) - (b.first ?? 0));
  return { findings, excludedWithoutTime: excluded };
}
