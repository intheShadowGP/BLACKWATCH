// Captures the README screenshots from a running production build with the
// published datasets. Usage:
//   npm run data:build && npm run build && npm run preview -- --port 4173
//   node scripts/docs-screenshots.mjs http://127.0.0.1:4173/
//
// Every capture's visible text is checked against the repository identity
// terms (see scripts/check-identity.mjs) before it is written, because the
// datasets are third-party text that may name any product. The SOC capture uses
// a synthetic log built below (documentation addresses only).

import { mkdir } from 'node:fs/promises';
import { chromium } from '@playwright/test';

const base = process.argv[2] ?? 'http://127.0.0.1:4173/';
const output = new URL('../docs/screenshots/', import.meta.url);
const fromCodes = (...codes) => String.fromCharCode(...codes);
const TERMS = [fromCodes(99, 108, 97, 117, 100, 101), fromCodes(97, 110, 116, 104, 114, 111, 112, 105, 99)];

function syntheticAuthLog() {
  const lines = [];
  const stamp = (seconds) => {
    const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
    const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
    const s = String(seconds % 60).padStart(2, '0');
    return `Mar 14 ${h}:${m}:${s}`;
  };
  let t = 2 * 3600;
  lines.push(`${stamp(t)} ledger-db sshd[811]: Accepted publickey for ops from 198.51.100.10 port 50122 ssh2`);
  for (let attempt = 0; attempt < 40; attempt += 1) {
    t += 3;
    const user = ['admin', 'oracle', 'postgres', 'test', 'ubuntu'][attempt % 5];
    lines.push(`${stamp(t)} ledger-db sshd[${900 + attempt}]: Failed password for invalid user ${user} from 203.0.113.77 port ${41000 + attempt} ssh2`);
  }
  t += 40;
  lines.push(`${stamp(t)} ledger-db sshd[990]: Accepted password for postgres from 203.0.113.77 port 41090 ssh2`);
  lines.push(`${stamp(t + 60)} ledger-db sudo:   postgres : user NOT in sudoers ; TTY=pts/1 ; PWD=/var/lib/postgresql ; USER=root ; COMMAND=/bin/bash`);
  lines.push(`${stamp(t + 120)} ledger-db useradd[1201]: new user: name=svc-sync, UID=1005, GID=1005, home=/home/svc-sync, shell=/bin/bash`);
  lines.push(`${stamp(t + 130)} ledger-db usermod[1202]: add 'svc-sync' to group 'sudo'`);
  return `${lines.join('\n')}\n`;
}

const SHOTS = [
  { file: 'overview.png', route: '/', ready: (page) => page.getByText('CISA KEV').first().waitFor() },
  { file: 'vulnerabilities.png', route: '/vulnerabilities', ready: (page) => page.getByRole('table').first().waitFor() },
  { file: 'attack.png', route: '/attack', ready: (page) => page.getByText(/ATT&CK v\d/).first().waitFor() },
  {
    file: 'soc.png',
    route: '/soc',
    ready: async (page) => {
      await page.locator('input[type=file][multiple]').setInputFiles({ name: 'auth.log', mimeType: 'text/plain', buffer: Buffer.from(syntheticAuthLog()) });
      await page.getByRole('tab', { name: /Findings/ }).waitFor();
      // Show the findings rather than the import panel.
      await page.getByRole('tab', { name: /Findings/ }).evaluate((tab) => window.scrollTo(0, tab.getBoundingClientRect().top + window.scrollY - 24));
    },
  },
  { file: 'toolbox.png', route: '/toolbox/cidr', ready: async (page) => {
    await page.getByRole('textbox').first().fill('192.0.2.0/26');
  } },
  { file: 'lab.png', route: '/lab/ssh-bruteforce', ready: (page) => page.getByRole('heading', { level: 1 }).waitFor() },
];

await mkdir(output, { recursive: true });
const browser = await chromium.launch();
const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, locale: 'en-US', colorScheme: 'dark', serviceWorkers: 'block' });
const page = await context.newPage();
for (const shot of SHOTS) {
  await page.goto(`${base}#${shot.route}`);
  await page.getByRole('heading', { level: 1 }).waitFor();
  await shot.ready(page);
  await page.waitForLoadState('networkidle');
  // Only the first screen is captured; check exactly what it shows.
  const visible = await page.evaluate(() => {
    const parts = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const range = document.createRange();
      range.selectNodeContents(node);
      const rect = range.getBoundingClientRect();
      if (rect.width > 0 && rect.bottom > 0 && rect.top < window.innerHeight) parts.push(node.textContent);
    }
    return parts.join(' ').toLowerCase();
  });
  const found = TERMS.filter((term) => visible.includes(term));
  if (found.length > 0) throw new Error(`${shot.file}: visible text contains a restricted term; choose another view`);
  await page.screenshot({ path: new URL(shot.file, output).pathname.replace(/^\/([A-Za-z]:)/, '$1') });
  console.log(`${shot.file} written`);
}
await browser.close();
