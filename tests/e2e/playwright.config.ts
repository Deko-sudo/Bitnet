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
  reporter: [['line'], ['html', { open: 'never' }]],
  projects: [
    {
      name: 'chromium-extension',
      use: {
        browserName: 'chromium',
        viewport: { width: 1280, height: 720 },
        launchOptions: {
          args: [
            `--disable-extensions-except=${extensionPath}`,
            `--load-extension=${extensionPath}`,
            '--no-first-run',
            '--no-default-browser-check',
          ],
          headless: false,
        },
      },
    },
  ],
});
