import { defineConfig, devices } from '@playwright/test';

const PORT = 4173;
const ALL_BROWSERS = Boolean(process.env.CI) || process.env.E2E_ALL_BROWSERS === '1';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  // Each worker launches a browser: a small pool keeps slower machines and CI runners reliable.
  workers: 2,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
    // Specs observe and stub network requests, which a service worker would answer instead.
    // e2e/pwa.spec.ts allows it and serves the build itself.
    serviceWorkers: 'block',
  },
  // Cold start of several browsers at once can exceed the default 5 s on slower machines.
  expect: {
    timeout: 10_000,
  },
  // End-to-end tests run against the production build, Content Security Policy included.
  webServer: {
    command: `npm run build && npm run preview -- --host 127.0.0.1 --port ${PORT} --strictPort`,
    url: `http://127.0.0.1:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
    // Gecko and WebKit: opt-in locally (E2E_ALL_BROWSERS=1), always on in CI.
    ...(ALL_BROWSERS
      ? [
          { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
          { name: 'webkit', use: { ...devices['Desktop Safari'] } },
        ]
      : []),
  ],
});
