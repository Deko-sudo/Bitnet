import { test, expect } from '@playwright/test';
import { resolve as resolvePath } from 'path';

test('popup screenshot', async ({ page }) => {
  const popupUrl = 'file:///' + resolvePath(__dirname, '..', '..', 'browser-extension', 'popup.html').split(String.fromCharCode(92)).join('/');
  await page.goto(popupUrl);
  await page.waitForTimeout(500);
  await page.screenshot({ path: 'C:/Users/anror/popup-screenshot.png', fullPage: true });
  const text = await page.locator('#status').textContent();
  console.log('Status text after load:', text);
  const refreshExists = await page.locator('#refresh').count();
  console.log('Refresh button count:', refreshExists);
  const entriesExists = await page.locator('#entries').count();
  console.log('Entries div count:', entriesExists);
});
