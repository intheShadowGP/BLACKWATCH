// Synthetic log samples for tests and for the "load a sample" action. All
// addresses are in documentation ranges (RFC 5737, RFC 3849); host and user
// names are invented. Nothing here comes from a real system.

const pad = (value: number) => String(value).padStart(2, '0');

/** Classic syslog line (RFC 3164 style, as written by rsyslog to auth.log). */
export function authLine(month: string, day: number, seconds: number, program: string, message: string, pid = 1200): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${month} ${String(day).padStart(2, ' ')} ${pad(h)}:${pad(m)}:${pad(s)} bastion ${program}[${pid}]: ${message}`;
}

/** auth.log with an SSH brute force followed by a success, sudo activity and noise. */
export function sampleAuthLog(): string {
  const lines: string[] = [];
  let t = 8 * 3600;
  lines.push(authLine('Jan', 10, t, 'sshd', 'Accepted publickey for alice from 198.51.100.10 port 50122 ssh2: ED25519 SHA256:synthetic'));
  for (let attempt = 0; attempt < 12; attempt += 1) {
    t += 7;
    lines.push(authLine('Jan', 10, t, 'sshd', `Invalid user user${attempt} from 203.0.113.50 port ${40000 + attempt}`));
    lines.push(authLine('Jan', 10, t, 'sshd', `pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.50`));
    lines.push(authLine('Jan', 10, t + 1, 'sshd', `Failed password for invalid user user${attempt} from 203.0.113.50 port ${40000 + attempt} ssh2`));
  }
  t += 5;
  lines.push(authLine('Jan', 10, t, 'sshd', 'message repeated 3 times: [ Failed password for root from 203.0.113.50 port 40100 ssh2]'));
  t += 20;
  lines.push(authLine('Jan', 10, t, 'sshd', 'Accepted password for root from 203.0.113.50 port 40101 ssh2'));
  t += 60;
  lines.push(authLine('Jan', 10, t, 'sudo', '   bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/bash'));
  lines.push(authLine('Jan', 10, t + 30, 'sudo', 'alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update'));
  lines.push(authLine('Jan', 10, t + 40, 'sudo', 'alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash'));
  lines.push(authLine('Jan', 10, t + 50, 'su', 'FAILED SU (to root) bob on pts/1'));
  lines.push(authLine('Jan', 10, t + 70, 'useradd', 'new user: name=svc-backup, UID=1005, GID=1005, home=/home/svc-backup, shell=/bin/bash'));
  lines.push(authLine('Jan', 10, t + 80, 'usermod', "add 'svc-backup' to group 'sudo'"));
  lines.push(authLine('Jan', 10, t + 90, 'CRON', 'pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)'));
  lines.push('this line is not syslog');
  return `${lines.join('\n')}\n`;
}

const accessLine = (ip: string, time: string, request: string, status: number, bytes: number, agent: string) =>
  `${ip} - - [${time}] "${request}" ${status} ${bytes} "-" "${agent}"`;

/** Combined-format access log with a scan, attacks and normal traffic. */
export function sampleAccessLog(): string {
  const lines: string[] = [];
  const time = (seconds: number) => `10/Jan/2026:09:${pad(Math.floor(seconds / 60))}:${pad(seconds % 60)} +0000`;
  lines.push(accessLine('198.51.100.20', time(0), 'GET / HTTP/1.1', 200, 5120, 'Mozilla/5.0 (X11; Linux x86_64)'));
  lines.push(accessLine('198.51.100.20', time(2), 'GET /assets/app.css HTTP/1.1', 200, 2048, 'Mozilla/5.0 (X11; Linux x86_64)'));
  const paths = ['/admin', '/wp-login.php', '/.env', '/.git/config', '/phpmyadmin/', '/backup.zip', '/config.php', '/server-status', '/login.jsp', '/api/v1/users', '/console', '/shell.php', '/test', '/old', '/db.sql', '/robots.txt', '/cgi-bin/test.cgi', '/actuator', '/debug', '/xmlrpc.php', '/vendor/phpunit/', '/.htaccess'];
  paths.forEach((path, index) => lines.push(accessLine('203.0.113.77', time(60 + index), `GET ${path} HTTP/1.1`, path === '/robots.txt' ? 200 : 404, 162, 'Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)')));
  lines.push(accessLine('203.0.113.78', time(200), 'GET /index.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--%20 HTTP/1.1', 500, 0, 'sqlmap/1.8'));
  lines.push(accessLine('203.0.113.78', time(205), 'GET /download?file=../../../../etc/passwd HTTP/1.1', 403, 0, 'curl/8.5.0'));
  lines.push(accessLine('203.0.113.78', time(210), 'GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1', 200, 900, 'curl/8.5.0'));
  lines.push(accessLine('203.0.113.78', time(215), 'GET /ping?host=127.0.0.1;cat%20/etc/shadow HTTP/1.1', 400, 0, 'curl/8.5.0'));
  lines.push(`203.0.113.79 - - [${time(220)}] "\\x16\\x03\\x01\\x00\\xa5\\x01\\x00\\x00" 400 157 "-" "-"`);
  lines.push(accessLine('198.51.100.20', time(230), 'POST /login HTTP/1.1', 302, 0, 'Mozilla/5.0 (X11; Linux x86_64)'));
  return `${lines.join('\n')}\n`;
}

const windowsEvent = (id: number, time: string, data: Record<string, string>, provider = 'Microsoft-Windows-Security-Auditing', channel = 'Security') =>
  `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='${provider}' Guid='{00000000-0000-0000-0000-000000000000}'/><EventID>${id}</EventID><Version>0</Version><Level>0</Level><TimeCreated SystemTime='${time}'/><EventRecordID>${id}</EventRecordID><Channel>${channel}</Channel><Computer>WS01.corp.example</Computer></System><EventData>${Object.entries(data).map(([key, value]) => `<Data Name='${key}'>${value}</Data>`).join('')}</EventData></Event>`;

/** Windows Security events: failed logons, a success, group change, log clearing. */
export function sampleWindowsXml(): string {
  const events: string[] = [];
  for (let index = 0; index < 8; index += 1) {
    events.push(windowsEvent(4625, `2026-01-10T10:00:${pad(index * 5)}.1234567Z`, { TargetUserName: 'administrator', TargetDomainName: 'CORP', LogonType: '3', IpAddress: '192.0.2.44', IpPort: '50000' }));
  }
  events.push(windowsEvent(4624, '2026-01-10T10:01:00.0000000Z', { TargetUserName: 'administrator', TargetDomainName: 'CORP', LogonType: '3', IpAddress: '192.0.2.44', IpPort: '50010' }));
  events.push(windowsEvent(4732, '2026-01-10T10:02:00.0000000Z', { MemberName: 'CN=helpdesk,OU=Users,DC=corp,DC=example', TargetUserName: 'Administrators', SubjectUserName: 'administrator' }));
  events.push(windowsEvent(1102, '2026-01-10T10:03:00.0000000Z', { SubjectUserName: 'administrator' }, 'Microsoft-Windows-Eventlog'));
  return `<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n${events.join('\n')}\n</Events>\n`;
}
