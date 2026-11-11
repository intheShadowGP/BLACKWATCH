import { createHash } from 'node:crypto';
import { expect, test, type Page } from '@playwright/test';
import { attachResourceTimingOnFailure } from './diagnostics';

test.use({ locale: 'en-US' });
attachResourceTimingOnFailure();

function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on('console', (message) => {
    if (message.type() === 'error') errors.push(message.text());
  });
  page.on('pageerror', (error) => errors.push(error.message));
  return errors;
}

test('stops a catastrophic regular expression and keeps the page usable', async ({ page }) => {
  const errors = collectErrors(page);
  await page.goto('/#/toolbox/regex');
  await page.getByLabel('Pattern').fill('^(a+)+$');
  await page.getByLabel('Text', { exact: true }).fill(`${'a'.repeat(40)}!`);
  await page.getByRole('button', { name: 'Test' }).click();
  await expect(page.getByText(/Stopped after 2 seconds/)).toBeVisible({ timeout: 8000 });

  // The interface still responds and a normal pattern runs in a fresh worker.
  await page.getByLabel('Pattern').fill('(?<word>a{3})');
  await page.getByRole('button', { name: 'Test' }).click();
  await expect(page.getByText(/^13 matches in/)).toBeVisible();
  expect(errors).toEqual([]);
});

test('hashes a file in a background worker under the production CSP', async ({ page }) => {
  const errors = collectErrors(page);
  const content = Buffer.from('BLACKWATCH file hashing test\n'.repeat(1000));
  await page.goto('/#/toolbox/hash-file');
  await page.getByLabel('Choose a file').setInputFiles({ name: 'sample.bin', mimeType: 'application/octet-stream', buffer: content });
  await expect(page.getByText(createHash('sha256').update(content).digest('hex'))).toBeVisible();
  await expect(page.getByText(createHash('md5').update(content).digest('hex'))).toBeVisible();
  await expect(page.getByText(createHash('sha512').update(content).digest('hex'))).toBeVisible();
  expect(errors).toEqual([]);
});

test('identifies a file type from its magic bytes', async ({ page }) => {
  await page.goto('/#/toolbox/file-meta');
  await page.getByLabel('Choose a file').setInputFiles({ name: 'report.pdf', mimeType: 'application/pdf', buffer: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00]) });
  await expect(page.getByText('ELF executable or object').first()).toBeVisible();
  await expect(page.getByText('The file extension does not match the detected type.')).toBeVisible();
});

test('searches the IANA port registry shipped with the site', async ({ page }) => {
  await page.goto('/#/toolbox/ports');
  await page.getByLabel('Port number or service name').fill('3389');
  await expect(page.getByRole('cell', { name: 'ms-wbt-server' }).first()).toBeVisible();
  await expect(page.getByText(/IANA Service Name and Transport Protocol Port Number Registry/)).toBeVisible();
});

test('parses a Sigma rule with the lazily loaded YAML parser', async ({ page }) => {
  const errors = collectErrors(page);
  await page.goto('/#/toolbox/sigma');
  await page.getByLabel('Rule source').fill('title: Test rule\nlogsource:\n  product: linux\ndetection:\n  keywords:\n    - sudo\n  condition: keywords\ntags:\n  - attack.t1548.003\nlevel: medium');
  await page.getByRole('button', { name: 'Parse' }).click();
  await expect(page.getByRole('heading', { name: 'Test rule' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'T1548.003' })).toBeVisible();
  expect(errors).toEqual([]);
});

test('lists every tool and opens each one without errors or overflow', async ({ page }) => {
  const errors = collectErrors(page);
  await page.goto('/#/toolbox');
  const links = page.getByRole('main').getByRole('link');
  await expect(links.first()).toBeVisible();
  const hrefs = await links.evaluateAll((elements) => elements.map((element) => element.getAttribute('href') ?? ''));
  expect(hrefs.length).toBe(20);
  for (const href of hrefs) {
    await page.goto(`/${href}`);
    await expect(page.getByRole('complementary', { name: 'Limits' })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, href).toBeLessThanOrEqual(0);
  }
  expect(errors).toEqual([]);
});
