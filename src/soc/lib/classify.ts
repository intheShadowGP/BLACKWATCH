// Classification of Linux authentication messages (sshd, sudo, su, PAM).
//
// Counting rule for SSH: one authentication attempt is one sshd line
// "Failed <method> for [invalid user] <user> from <ip>". PAM lines describing
// the same attempt ("pam_unix(sshd:auth): authentication failure") and the
// "PAM n more authentication failures" summaries are informational, so an
// attempt is never counted twice. "message repeated N times: [ ... ]" stands
// for N identical lines and counts N.

import type { EventCategory } from './model';

export interface Classification {
  category: EventCategory;
  user: string | null;
  srcIp: string | null;
  count: number;
  /** Message with the "message repeated" wrapper removed. */
  message: string;
  detail: Record<string, string>;
}

const IP = '([0-9a-fA-F:.]+)';

export function classifyAuthMessage(program: string | null, rawMessage: string): Classification {
  let message = rawMessage;
  let count = 1;
  const repeated = /^message repeated (\d+) times: \[\s*(.*?)\s*\]$/.exec(message);
  if (repeated) {
    count = Math.min(Number(repeated[1]), 100_000);
    message = repeated[2] as string;
  }
  const base = (category: EventCategory, user: string | null = null, srcIp: string | null = null, detail: Record<string, string> = {}): Classification => ({ category, user, srcIp, count, message, detail });
  const name = (program ?? '').toLowerCase();
  let match: RegExpExecArray | null;

  if (name === 'sshd' || name.startsWith('sshd')) {
    if ((match = new RegExp(`^Failed (\\S+) for (invalid user )?(.*?) from ${IP} port \\d+`).exec(message))) {
      return base('authFailure', match[3] as string, match[4] as string, { method: match[1] as string, invalidUser: match[2] ? 'true' : 'false', service: 'ssh' });
    }
    if ((match = new RegExp(`^Accepted (\\S+) for (.*?) from ${IP} port \\d+`).exec(message))) {
      return base('authSuccess', match[2] as string, match[3] as string, { method: match[1] as string, service: 'ssh' });
    }
    if ((match = new RegExp(`^Invalid user (.*?) from ${IP}(?: port \\d+)?`).exec(message))) {
      return base('authInvalidUser', match[1] as string, match[2] as string, { service: 'ssh' });
    }
    if ((match = new RegExp(`rhost=${IP}(?:\\s+user=(\\S+))?`).exec(message))) {
      return base('authInfo', match[2] ?? null, match[1] as string, { service: 'ssh' });
    }
    if ((match = new RegExp(`from ${IP}`).exec(message))) return base('authInfo', null, match[1] as string, { service: 'ssh' });
    return base('authInfo', null, null, { service: 'ssh' });
  }

  if (name === 'sudo') {
    if ((match = /^\s*(\S+) : user NOT in sudoers ; .*?USER=(\S+) ; COMMAND=(.*)$/.exec(message))) {
      return base('sudoNotAllowed', match[1] as string, null, { targetUser: match[2] as string, command: match[3] as string });
    }
    if ((match = /^\s*(\S+) : (\d+) incorrect password attempts? ; .*?USER=(\S+) ; COMMAND=(.*)$/.exec(message))) {
      return { ...base('sudoFailure', match[1] as string, null, { targetUser: match[3] as string, command: match[4] as string }), count: count * Number(match[2]) };
    }
    if ((match = /^\s*(\S+) : .*?USER=(\S+) ; COMMAND=(.*)$/.exec(message))) {
      return base('sudoCommand', match[1] as string, null, { targetUser: match[2] as string, command: match[3] as string });
    }
    if ((match = /pam_unix\(sudo:auth\): authentication failure;.*?ruser=(\S*)/.exec(message))) {
      return base('authInfo', match[1] || null, null, { service: 'sudo' });
    }
    return base('authInfo', null, null, { service: 'sudo' });
  }

  if (name === 'su') {
    if ((match = /^FAILED (?:SU|su) \(to (\S+)\) (\S+) on/.exec(message)) || (match = /^FAILED SU \(to (\S+)\) (\S+)/.exec(message))) {
      return base('suFailure', match[2] as string, null, { targetUser: match[1] as string });
    }
    if ((match = /^\(to (\S+)\) (\S+) on/.exec(message)) || (match = /^Successful su for (\S+) by (\S+)/.exec(message))) {
      return base('suSuccess', match[2] as string, null, { targetUser: match[1] as string });
    }
    if ((match = /pam_unix\(su(?:-l)?:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S*?)(?:\(uid=\d+\))?$/.exec(message))) {
      return base('suSuccess', match[2] || null, null, { targetUser: match[1] as string });
    }
    if ((match = /pam_unix\(su(?:-l)?:auth\): authentication failure;.*?ruser=(\S*).*?user=(\S+)/.exec(message))) {
      return base('suFailure', match[1] || null, null, { targetUser: match[2] as string });
    }
    return base('authInfo', null, null, { service: 'su' });
  }

  if ((match = /^new user: name=([^,]+),/.exec(message)) && /useradd|adduser/.test(name)) {
    return base('accountCreated', match[1] as string, null, {});
  }
  if ((match = /^add '([^']+)' to (?:shadow )?group '([^']+)'/.exec(message)) && /usermod|gpasswd/.test(name)) {
    return base('groupMemberAdded', match[1] as string, null, { group: match[2] as string });
  }
  return base('other');
}

// ── Windows ─────────────────────────────────────────────────────────────────

/**
 * Security event identifiers used by the detections. Each is documented by
 * Microsoft in "Audit events" (learn.microsoft.com, Windows security auditing).
 */
export const WINDOWS_EVENTS: Readonly<Record<number, EventCategory>> = {
  4624: 'authSuccess',
  4625: 'authFailure',
  4720: 'accountCreated',
  4728: 'groupMemberAdded',
  4732: 'groupMemberAdded',
  4756: 'groupMemberAdded',
  4740: 'accountLockout',
  1102: 'logCleared',
  4688: 'processCreated',
};

export function classifyWindows(eventId: number, provider: string | null, data: Record<string, string>): Pick<Classification, 'category' | 'user' | 'srcIp'> {
  const category = (provider === null || provider === 'Microsoft-Windows-Security-Auditing' || provider === 'Microsoft-Windows-Eventlog') ? WINDOWS_EVENTS[eventId] ?? 'other' : 'other';
  const ip = data.IpAddress && data.IpAddress !== '-' && data.IpAddress !== '::1' && data.IpAddress !== '127.0.0.1' ? data.IpAddress : null;
  const user = data.TargetUserName && data.TargetUserName !== '-' ? data.TargetUserName : data.SubjectUserName && data.SubjectUserName !== '-' ? data.SubjectUserName : null;
  if (category === 'groupMemberAdded') return { category, user: data.MemberName && data.MemberName !== '-' ? data.MemberName : user, srcIp: null };
  return { category, user, srcIp: ip };
}
