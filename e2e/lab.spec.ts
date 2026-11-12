import { readFileSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';
import { CATALOG, loadScenario } from '../src/lab/catalog';
import { bestAnswer, scenarioMax } from '../src/lab/engine';
import type { Scenario } from '../src/lab/model';
import { attachResourceTimingOnFailure, reportCspViolations } from './diagnostics';

test.use({ locale: 'en-US' });
attachResourceTimingOnFailure();
reportCspViolations();

async function answer(page: Page, scenario: Scenario, stepIndex: number) {
  const step = scenario.steps[stepIndex];
  if (!step) throw new Error('no step');
  const section = page.getByRole('region', { name: step.prompt.en });
  for (const id of bestAnswer(step)) {
    const option = step.options.find((candidate) => candidate.id === id);
    await section.getByLabel(option?.text.en as string, { exact: true }).check();
  }
  await section.getByRole('button', { name: 'Submit answer' }).click();
  await expect(section.getByText(`${step.points} / ${step.points} points`)).toBeVisible();
}

test('lists every scenario', async ({ page }) => {
  await page.goto('/#/lab');
  for (const entry of CATALOG) await expect(page.getByRole('link', { name: new RegExp(entry.title.en) })).toBeVisible();
});

test('plays a scenario with the best answers, resumes after reload and reproduces the report', async ({ page }) => {
  const scenario = (await loadScenario('ssh-bruteforce')) as Scenario;
  await page.goto('/#/lab/ssh-bruteforce');
  await expect(page.getByRole('heading', { level: 1, name: scenario.title.en })).toBeVisible();
  await answer(page, scenario, 0);
  await answer(page, scenario, 1);

  // Progress survives a reload and answered steps stay locked. Saving is asynchronous: reload once
  // both answers are stored, as a person would not reload within the same few milliseconds.
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          new Promise<number>((resolve) => {
            const request = indexedDB.open('blackwatch');
            request.onsuccess = () => {
              const read = request.result.transaction('labProgress').objectStore('labProgress').get('ssh-bruteforce');
              read.onsuccess = () => {
                resolve(Object.keys(read.result?.data?.answers ?? {}).length);
                request.result.close();
              };
              read.onerror = () => resolve(-1);
            };
            request.onerror = () => resolve(-1);
          }),
      ),
    )
    .toBe(2);
  await page.reload();
  const first = page.getByRole('region', { name: scenario.steps[0]?.prompt.en as string });
  await expect(first.getByText('Answer recorded')).toBeVisible();
  await expect(first.getByRole('button', { name: 'Submit answer' })).toHaveCount(0);

  for (let index = 2; index < scenario.steps.length; index += 1) await answer(page, scenario, index);
  await expect(page.getByText(`Score: ${scenarioMax(scenario)} / ${scenarioMax(scenario)}`)).toBeVisible();

  const reports: string[] = [];
  for (let round = 0; round < 2; round += 1) {
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download the report (Markdown)' }).click()]);
    reports.push(readFileSync(await download.path(), 'utf8'));
  }
  expect(reports[0]).toBe(reports[1]);
  expect(reports[0]).toContain(`Score: ${scenarioMax(scenario)} / ${scenarioMax(scenario)}`);

  await page.getByRole('button', { name: 'Restart the exercise' }).click();
  await page.getByRole('alertdialog').getByRole('button', { name: 'Restart the exercise' }).click();
  await expect(page.getByRole('region', { name: scenario.steps[0]?.prompt.en as string }).getByRole('button', { name: 'Submit answer' })).toBeVisible();
  await page.goto('/#/lab');
  await expect(page.getByText('Not started').first()).toBeVisible();
});

test('scenario pages have no horizontal overflow', async ({ page }) => {
  for (const entry of CATALOG) {
    await page.goto(`/#/lab/${entry.id}`);
    await expect(page.getByRole('heading', { level: 1, name: entry.title.en })).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow, entry.id).toBeLessThanOrEqual(0);
  }
});
