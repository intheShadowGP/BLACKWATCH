import { readFileSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';
import { sampleAccessLog, sampleAuthLog, sampleWindowsXml } from '../src/soc/fixtures';
import { attachResourceTimingOnFailure } from './diagnostics';

test.use({ locale: 'en-US' });
attachResourceTimingOnFailure();

async function importSamples(page: Page) {
  await page.locator('input[type=file][multiple]').setInputFiles([
    { name: 'auth.log', mimeType: 'text/plain', buffer: Buffer.from(sampleAuthLog()) },
    { name: 'access.log', mimeType: 'text/plain', buffer: Buffer.from(sampleAccessLog()) },
    { name: 'security.xml', mimeType: 'application/xml', buffer: Buffer.from(sampleWindowsXml()) },
    { name: 'archive.gz', mimeType: 'application/gzip', buffer: Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0x00]) },
  ]);
  await expect(page.getByRole('tab', { name: /Findings/ })).toBeVisible();
}

test('analyses imported logs locally, without any network request', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  await page.goto('/#/soc');
  await expect(page.getByRole('heading', { level: 1, name: 'SOC Workbench' })).toBeVisible();
  const requests: string[] = [];
  page.on('request', (request) => requests.push(request.url()));
  await importSamples(page);

  // Only the application's own worker script may be requested; no log content leaves the page.
  expect(requests.filter((url) => !/\/assets\/soc\.worker-[\w-]+\.js$/.test(url) && !/\/assets\/[\w-]+\.js$/.test(url))).toEqual([]);
  expect(requests.every((url) => url.startsWith('http://127.0.0.1:4173/'))).toBe(true);

  await expect(page.getByText('Remote authentication brute force').first()).toBeVisible();
  await expect(page.getByText('Event log cleared').first()).toBeVisible();
  await expect(page.getByText('Web scanning').first()).toBeVisible();
  await expect(page.getByText(/gzip-compressed file/)).toBeVisible();
  await expect(page.getByText('this line is not syslog', { exact: false })).toBeAttached();
  expect(errors).toEqual([]);
});

test('drills from a finding to its events and keeps the import across navigation', async ({ page, isMobile }) => {
  const openNavigation = async () => {
    if (isMobile) await page.getByRole('button', { name: 'Open navigation' }).click();
  };
  await page.goto('/#/soc');
  await importSamples(page);
  await page.getByRole('button', { name: 'Show the 13 events' }).first().click();
  await expect(page.getByText('Showing the events of a finding')).toBeVisible();
  await expect(page.getByText(/^13 of \d+ shown$/)).toBeVisible();

  await openNavigation();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'MITRE ATT&CK' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'MITRE ATT&CK' })).toBeVisible();
  await openNavigation();
  await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: 'SOC Workbench' }).click();
  await expect(page.getByRole('tab', { name: /Findings/ })).toBeVisible();
});

test('changing the assumed time zone re-dates inferred timestamps', async ({ page }) => {
  await page.goto('/#/soc');
  await importSamples(page);
  await page.getByRole('tab', { name: /Events/ }).click();
  await page.getByLabel('Search events').fill('Accepted publickey for alice');
  await expect(page.getByRole('cell', { name: /2026-01-10 08:00:00Z/ })).toBeVisible();
  await page.getByLabel('Time zone of timestamps without one').selectOption({ label: 'UTC+02:00' });
  await expect(page.getByRole('tab', { name: /Events/ })).toBeVisible();
  await page.getByRole('tab', { name: /Events/ }).click();
  await page.getByLabel('Search events').fill('Accepted publickey for alice');
  await expect(page.getByRole('cell', { name: /2026-01-10 06:00:00Z/ })).toBeVisible();
});

test('evaluates a supported Sigma rule and rejects an unsupported one', async ({ page }) => {
  await page.goto('/#/soc');
  await importSamples(page);
  await page.getByRole('tab', { name: /Sigma rules/ }).click();
  await page.getByLabel('Rule source').fill(
    "title: Sudo refused\nlogsource:\n  product: linux\ndetection:\n  keywords:\n    - 'NOT in sudoers'\n  condition: keywords\n---\ntitle: Regex rule\nlogsource:\n  product: linux\ndetection:\n  sel:\n    message|re: 'a.*'\n  condition: sel",
  );
  await page.getByRole('button', { name: 'Evaluate' }).click();
  await expect(page.getByText(/Matched 1 of \d+ candidate events/)).toBeVisible();
  await expect(page.getByText(/Not evaluated: unsupported construct \(modifier "re"/)).toBeVisible();
});

test('exports a Markdown report with fenced excerpts and saves the investigation', async ({ page }) => {
  await page.goto('/#/soc');
  await importSamples(page);
  await page.getByRole('tab', { name: /Investigation/ }).click();
  await page.getByLabel('Investigation title').fill('Sample <b>case</b>');
  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download the report (Markdown)' }).click()]);
  expect(download.suggestedFilename()).toMatch(/\.md$/);
  const report = readFileSync(await download.path(), 'utf8');
  expect(report).toContain('# Sample \\<b\\>case\\</b\\>');
  expect(report).toContain('read as UTC+00:00');
  expect(report).toMatch(/```text\n/);
  expect(report).not.toMatch(/<b>/);

  await page.getByRole('button', { name: 'Save investigation in this browser' }).click();
  await expect(page.getByText('Investigation saved in this browser.')).toBeVisible();
  await page.reload();
  await page.getByRole('button', { name: 'Open', exact: true }).click();
  await expect(page.getByText(/Loaded from a saved investigation/)).toBeVisible();
  await expect(page.getByRole('tab', { name: /Findings/ })).toBeVisible();
});
