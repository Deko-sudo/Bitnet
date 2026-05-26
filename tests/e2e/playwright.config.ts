import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: 'list',
  use: {
    trace: 'on-first-retry',
    headless: false,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Launch Chrome with the BitNet extension loaded
        launchOptions: {
          args: [
            `--disable-extensions-except=${__dirname}/../../browser-extension`,
            `--load-extension=${__dirname}/../../browser-extension`,
          ],
        },
      },
    },
  ],
});