import { defineConfig } from '@playwright/test';
import path from 'path';

/**
 * Playwright configuration for BitNet browser-extension E2E tests.
 *
 * Prerequisites:
 *   npm install -g @playwright/test
 *   npx playwright install chromium
 *
 * Running:
 *   npx playwright test
 */

const extensionPath = path.resolve(__dirname, '..', '..', 'browser-extension');

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  workers: 1,
  // 5 minutes total budget per test; some extension launchers are slow on
  // first run. The default 30s was too aggressive for the cold-start case
  // where Chromium has to spin up a new profile and load the extension.
  timeout: 60_000,
  reporter: [['line'], ['html', { open: 'never' }]],
  projects: [
    {
      name: 'chromium-extension',
      use: {
        browserName: 'chromium',
        viewport: { width: 1280, height: 720 },
        launchOptions: {
          // Run headless by default; pass PLAYWRIGHT_HEADED=1 to see the
          // browser UI. This makes the tests usable from both a CI runner
          // and a developer workstation without editing the config file.
          headless: process.env.PLAYWRIGHT_HEADED !== '1',
          args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`,
            '--no-first-run',
            '--no-default-browser-check',
          ],
        },
      },
    },
  ],
});
