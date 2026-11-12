import { expect, test, type Page } from '@playwright/test';
import { attachResourceTimingOnFailure } from './diagnostics';
import { DATA_FILES } from '../src/test/fixtures';

/** Serves the synthetic fixture datasets: tests never depend on live intelligence. */
async function serveFixtures(page: Page) {
  await page.route('**/data/*.json', async (route) => {
    const name = new URL(route.request().url()).pathname.split('/').pop() ?? '';
    const body = DATA_FILES[name];
    await (body === undefined ? route.fulfill({ status: 404, body: 'Not found' }) : route.fulfill({ json: body }));
  });
}

/** Collects console errors and failed or third-party requests for the lifetime of a page. */
function watch(page: Page) {
  const consoleErrors: string[] = [];
  const foreignRequests: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => consoleErrors.push(error.message));
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (!['127.0.0.1', 'localhost'].includes(url.hostname) && !['data:', 'blob:'].includes(url.protocol)) {
      foreignRequests.push(request.url());
    }
  });
  return { consoleErrors, foreignRequests };
}

async function openNavigation(page: Page, isMobile: boolean) {
  if (isMobile) await page.getByRole('button', { name: /open navigation|ouvrir la navigation/i }).click();
}

test.use({ locale: 'en-US' });
attachResourceTimingOnFailure();

test.beforeEach(async ({ page }) => {
  await serveFixtures(page);
});

test('loads without console errors or third-party requests', async ({ page }) => {
  const observed = watch(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Overview' })).toBeVisible();
  await expect(page.locator('meta[http-equiv="Content-Security-Policy"]')).toHaveCount(1);
  expect(observed.consoleErrors).toEqual([]);
  expect(observed.foreignRequests).toEqual([]);
});

test('navigates between modules and to settings', async ({ page, isMobile }) => {
  const observed = watch(page);
  await page.goto('/');
  for (const name of ['Security Toolbox', 'SOC Workbench', 'Settings & Privacy']) {
    await openNavigation(page, isMobile);
    await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name }).click();
    await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
  }
  await expect(page).toHaveURL(/#\/settings$/);
  expect(observed.consoleErrors).toEqual([]);
});

test('language choice applies immediately and survives a reload', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button', { name: /French/ }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Vue d’ensemble' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'fr');
  await page.reload();
  await expect(page.getByRole('heading', { level: 1, name: 'Vue d’ensemble' })).toBeVisible();
});

test('theme preference survives a reload and local data can be deleted', async ({ page }) => {
  await page.goto('/#/settings');
  await page.getByText('Light', { exact: true }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');

  await page.getByRole('button', { name: 'Delete local data' }).click();
  const dialog = page.getByRole('alertdialog');
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Delete everything' }).click();
  await expect(page.getByText(/Local data deleted/)).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
});

test('exports local data as a JSON file', async ({ page }) => {
  await page.goto('/#/settings');
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.getByRole('button', { name: 'Export local data' }).click(),
  ]);
  expect(download.suggestedFilename()).toMatch(/^blackwatch-export-[\w-]+\.json$/);
});

for (const path of ['/', '/settings', '/vulnerabilities', '/vulnerabilities/CVE-2025-20001', '/attack', '/attack/G9001', '/threat-intel', '/threat-intel?tab=ioc']) {
  test(`has no horizontal page overflow on ${path}`, async ({ page }) => {
    await page.goto(`/#${path}`);
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible();
    await page.waitForLoadState('networkidle');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  });
}

test('shows dataset figures with provenance', async ({ page }) => {
  const observed = watch(page);
  await page.goto('/');
  await expect(page.getByText('Known exploited vulnerabilities').locator('xpath=following-sibling::p[1]')).toHaveText('2');
  await expect(page.getByText('Publisher of kev')).toBeVisible();
  await page.goto('/#/vulnerabilities/CVE-2025-20001');
  await expect(page.getByText('In CISA KEV')).toBeVisible();
  await page.goto('/#/attack');
  await expect(page.getByText(/ATT&CK v99\.0/)).toBeVisible();
  expect(observed.consoleErrors).toEqual([]);
  expect(observed.foreignRequests).toEqual([]);
});

test('states that no dataset is published when the data files are absent', async ({ page }) => {
  await page.unroute('**/data/*.json');
  await page.route('**/data/*.json', (route) => route.fulfill({ status: 404, body: 'Not found' }));
  await page.goto('/');
  await expect(page.getByText(/No intelligence dataset is published/).first()).toBeVisible();
  await page.goto('/#/vulnerabilities');
  await expect(page.getByText(/This dataset is not published/).first()).toBeVisible();
});

test('unknown routes render as text', async ({ page }) => {
  const observed = watch(page);
  await page.goto('/#/%3Cimg%20src=x%20onerror=alert(1)%3E');
  await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
  await expect(page.locator('main img')).toHaveCount(0);
  expect(observed.consoleErrors).toEqual([]);
});
