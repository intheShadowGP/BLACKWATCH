// Regular expression testing. Patterns run in a dedicated worker that is
// terminated after a time limit, so a catastrophic pattern cannot freeze the page.

export const REGEX_TIMEOUT_MS = 2000;
export const MAX_REGEX_TEXT = 1_000_000;
export const MAX_REGEX_PATTERN = 2000;
export const MAX_REGEX_MATCHES = 1000;
export const REGEX_FLAGS = ['g', 'i', 'm', 's', 'u', 'y'] as const;

export interface RegexMatch {
  index: number;
  value: string;
  groups: (string | null)[];
  named: Record<string, string | null>;
}

export type RegexRequest = { pattern: string; flags: string; text: string };

export type RegexResult =
  | { status: 'ok'; matches: RegexMatch[]; truncated: boolean; elapsedMs: number }
  | { status: 'invalid'; message: string }
  | { status: 'timeout' }
  | { status: 'unavailable' };

/** Executes the search. Runs inside the worker; exported for tests. */
export function executeRegex({ pattern, flags, text }: RegexRequest): RegexResult {
  if (pattern.length > MAX_REGEX_PATTERN) return { status: 'invalid', message: `Pattern longer than ${MAX_REGEX_PATTERN} characters` };
  const cleanFlags = [...new Set(flags.split('').filter((flag) => (REGEX_FLAGS as readonly string[]).includes(flag)))].join('');
  let regex: RegExp;
  try {
    regex = new RegExp(pattern, cleanFlags.includes('g') ? cleanFlags : `${cleanFlags}g`);
  } catch (error) {
    return { status: 'invalid', message: (error as Error).message };
  }
  const started = performance.now();
  const matches: RegexMatch[] = [];
  let truncated = false;
  const input = text.slice(0, MAX_REGEX_TEXT);
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    if (matches.length >= MAX_REGEX_MATCHES) {
      truncated = true;
      break;
    }
    matches.push({
      index: match.index,
      value: match[0].slice(0, 1000),
      groups: match.slice(1).map((group) => (group === undefined ? null : group.slice(0, 1000))),
      named: Object.fromEntries(Object.entries(match.groups ?? {}).map(([name, value]) => [name, value === undefined ? null : value.slice(0, 1000)])),
    });
    if (match[0] === '') regex.lastIndex += 1;
    if (!cleanFlags.includes('g')) break;
  }
  return { status: 'ok', matches, truncated: truncated || text.length > MAX_REGEX_TEXT, elapsedMs: performance.now() - started };
}

/** Runs the search in a fresh worker, terminated after REGEX_TIMEOUT_MS. */
export function runRegex(request: RegexRequest, timeoutMs = REGEX_TIMEOUT_MS): Promise<RegexResult> {
  if (typeof Worker === 'undefined') return Promise.resolve({ status: 'unavailable' });
  return new Promise((resolve) => {
    const worker = new Worker(new URL('../workers/regex.worker.ts', import.meta.url), { type: 'module' });
    const timer = window.setTimeout(() => {
      worker.terminate();
      resolve({ status: 'timeout' });
    }, timeoutMs);
    worker.onmessage = (event: MessageEvent<RegexResult>) => {
      window.clearTimeout(timer);
      worker.terminate();
      resolve(event.data);
    };
    worker.onerror = () => {
      window.clearTimeout(timer);
      worker.terminate();
      resolve({ status: 'unavailable' });
    };
    worker.postMessage(request);
  });
}
