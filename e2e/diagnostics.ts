import { writeFileSync } from 'node:fs';
import { test } from '@playwright/test';

/**
 * On failure, attaches the browser's resource timing entries. If the route
 * chunks appear with a response end, the bytes reached the page and a stall
 * lies in the application; if they are absent, the requests never completed.
 */
export function attachResourceTimingOnFailure(): void {
  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status === testInfo.expectedStatus) return;
    const entries = await page
      .evaluate(() =>
        performance.getEntriesByType('resource').map((entry) => {
          const resource = entry as PerformanceResourceTiming;
          return { name: resource.name, start: Math.round(resource.startTime), responseEnd: Math.round(resource.responseEnd), size: resource.transferSize };
        }),
      )
      .catch(() => 'page unavailable');
    const file = testInfo.outputPath('resource-timing.json');
    writeFileSync(file, JSON.stringify(entries, null, 2));
    await testInfo.attach('resource-timing.json', { path: file, contentType: 'application/json' });
  });
}

/**
 * Turns Content Security Policy violations into console errors, which the specs already collect.
 * Some engines report a blocked operation only as a `securitypolicyviolation` event, not on the
 * console (Chromium did so for a caught `new Function` probe that Firefox logs as an error).
 */
export function reportCspViolations(): void {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      document.addEventListener('securitypolicyviolation', (event) => {
        console.error(`CSP violation: ${event.violatedDirective} ${event.blockedURI || '(inline)'}`);
      });
    });
  });
}
