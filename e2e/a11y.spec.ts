import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';
import { DATA_FILES } from '../src/test/fixtures';
import { sampleAuthLog } from '../src/soc/fixtures';
import { attachResourceTimingOnFailure } from './diagnostics';

test.use({ locale: 'en-US' });
attachResourceTimingOnFailure();

test.beforeEach(async ({ page }) => {
  await page.route('**/data/*.json', async (route) => {
    const name = new URL(route.request().url()).pathname.split('/').pop() ?? '';
    const body = DATA_FILES[name];
    await (body === undefined ? route.fulfill({ status: 404, body: 'Not found' }) : route.fulfill({ json: body }));
  });
});

const ROUTES = [
  '/',
  '/threat-intel',
  '/threat-intel?tab=ioc',
  '/vulnerabilities',
  '/vulnerabilities/CVE-2025-20001',
  '/attack',
  '/attack/T1566',
  '/toolbox',
  '/toolbox/jwt',
  '/toolbox/cidr',
  '/toolbox/tls',
  '/soc',
  '/lab',
  '/lab/ssh-bruteforce',
  '/settings',
];

async function audit(page: Page) {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
  return results.violations.map((violation) => `${violation.id} (${violation.impact}): ${violation.nodes.slice(0, 3).map((node) => node.target.join(' ')).join(' | ')}`);
}

for (const theme of ['dark', 'light'] as const) {
  test(`has no WCAG A/AA violations in the ${theme} theme`, async ({ page, browserName }) => {
    // In CI, Firefox's page process crashed inside the axe analysis on both themes, while every other
    // Firefox spec visiting the same routes passed. The rules evaluate the DOM and computed styles:
    // they run on Chromium and WebKit.
    test.skip(browserName === 'firefox', 'Firefox page crashed during the axe analysis in CI');
    test.setTimeout(120_000);
    await page.emulateMedia({ colorScheme: theme });
    await page.goto('/#/settings');
    await page.getByText(theme === 'dark' ? 'Dark' : 'Light', { exact: true }).click();
    const found: string[] = [];
    for (const route of ROUTES) {
      await page.goto(`/#${route}`);
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
      await page.waitForLoadState('networkidle');
      for (const violation of await audit(page)) found.push(`${route}: ${violation}`);
    }
    // The SOC Workbench with data, which renders tables, tabs and findings.
    await page.goto('/#/soc');
    await page.locator('input[type=file][multiple]').setInputFiles({ name: 'auth.log', mimeType: 'text/plain', buffer: Buffer.from(sampleAuthLog()) });
    await expect(page.getByRole('tab', { name: /Findings/ })).toBeVisible();
    for (const violation of await audit(page)) found.push(`/soc (loaded): ${violation}`);
    expect(found).toEqual([]);
  });
}

test('keeps keyboard focus on the page after actions that replace the focused control', async ({ page }) => {
  await page.goto('/#/lab/ssh-bruteforce');
  const step = page.getByRole('region', { name: 'Which statements are established by the evidence?' });
  await step.getByRole('checkbox').first().check();
  await step.getByRole('button', { name: 'Submit answer' }).focus();
  await page.keyboard.press('Enter');
  await expect(step.getByText(/points$/).first()).toBeVisible();
  const lab = await page.evaluate(() => document.activeElement?.tagName ?? 'none');
  expect(lab).not.toBe('BODY');

  await page.goto('/#/soc');
  await page.locator('input[type=file][multiple]').setInputFiles({ name: 'auth.log', mimeType: 'text/plain', buffer: Buffer.from(sampleAuthLog()) });
  const show = page.getByRole('button', { name: /^Show the \d+ events$/ }).first();
  await show.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByText('Showing the events of a finding')).toBeVisible();
  const soc = await page.evaluate(() => document.activeElement?.tagName ?? 'none');
  expect(soc).not.toBe('BODY');
});
