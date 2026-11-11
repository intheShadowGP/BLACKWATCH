// Normalised event model of the SOC Workbench. Every parser produces LogEvent
// objects; detections and views only read this model.

export const LOG_FORMATS = ['json', 'csv', 'syslog', 'webAccess', 'apacheError', 'nginxError', 'windowsXml'] as const;
export type LogFormat = (typeof LOG_FORMATS)[number];

/**
 * - exact: the source carries a full date with a time zone.
 * - inferred: year and/or time zone come from the analyst's settings (classic syslog, local times).
 * - missing: no readable timestamp; the event is kept but excluded from time-window rules.
 */
export type TimeQuality = 'exact' | 'inferred' | 'missing';

export type EventCategory =
  | 'authFailure'
  | 'authSuccess'
  | 'authInvalidUser'
  | 'authInfo'
  | 'sudoCommand'
  | 'sudoFailure'
  | 'sudoNotAllowed'
  | 'suSuccess'
  | 'suFailure'
  | 'accountCreated'
  | 'groupMemberAdded'
  | 'accountLockout'
  | 'logCleared'
  | 'processCreated'
  | 'httpRequest'
  | 'webError'
  | 'other';

export interface HttpInfo {
  method: string | null;
  path: string | null;
  protocol: string | null;
  status: number | null;
  bytes: number | null;
  referrer: string | null;
  userAgent: string | null;
  /** True when the request line could not be split into method, path and protocol (typical of scanners). */
  malformed: boolean;
}

export interface WindowsInfo {
  eventId: number;
  provider: string | null;
  channel: string | null;
  computer: string | null;
  data: Record<string, string>;
}

export interface LogEvent {
  /** Index in the analysis, stable for the lifetime of an import. */
  id: number;
  /** Index of the source file. */
  file: number;
  /** 1-based line (or record) number in the source file. */
  line: number;
  timestamp: number | null;
  timeQuality: TimeQuality;
  format: LogFormat;
  host: string | null;
  program: string | null;
  message: string;
  category: EventCategory;
  user: string | null;
  srcIp: string | null;
  /** Number of occurrences this line stands for ("message repeated N times" counts N). */
  count: number;
  http: HttpInfo | null;
  windows: WindowsInfo | null;
  /** Source fields for structured formats (JSON, CSV, Windows EventData), flattened. */
  fields: Record<string, string>;
}

export interface TimeSettings {
  /** Year assumed for the LAST line of a file whose timestamps carry no year. */
  endYear: number;
  /** Offset from UTC, in minutes, of timestamps that carry no time zone. */
  offsetMinutes: number;
}

export interface ParseStats {
  format: LogFormat;
  /** Lines or records read. */
  read: number;
  parsed: number;
  unparsed: number;
  /** First unparsed lines, for display (truncated). */
  unparsedSamples: { line: number; text: string }[];
  timestamps: Record<TimeQuality, number>;
  /** Number of year changes inferred while reading classic syslog (December to January). */
  yearRollovers: number;
  truncated: boolean;
}

export const MAX_FILE_BYTES = 100 * 1024 * 1024;
export const MAX_EVENTS = 500_000;
export const MAX_MESSAGE_CHARS = 4000;
export const MAX_FIELDS = 64;
