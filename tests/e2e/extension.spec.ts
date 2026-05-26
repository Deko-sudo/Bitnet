import { test, expect } from '@playwright/test';
import path from 'path';

const EXTENSION_PATH = path.resolve(__dirname, '../../browser-extension');

test.describe('BitNet Browser Extension', () => {
  test('popup loads and shows vault status', async ({ page, context }) => {
    // Open the extension popup via service worker
    const background = context.backgroundPages()[0] || await context.waitForEvent('backgroundpage');
    expect(background).toBeTruthy();

    // Navigate to the popup HTML directly
    await page.goto(`file:///${EXTENSION_PATH.replace(/\\/g, '/')}/popup.html`);
    
    // Wait for popup to render
    await page.waitForSelector('#status');
    const status = await page.locator('#status').textContent();
    
    // Should show "Vault locked" or similar since native host is not running
    expect(status).toMatch(/Vault locked|unlock|Error/);
  });

  test('content script overlay appears on password field focus', async ({ page }) => {
    // Create a simple login page
    await page.setContent(`
      <html>
        <body>
          <form>
            <input type="text" id="username" placeholder="Username" />
            <input type="password" id="password" placeholder="Password" />
            <button type="submit">Login</button>
          </form>
        </body>
      </html>
    `);

    // Focus the password field
    await page.locator('#password').focus();

    // Wait for overlay to appear (up to 2 seconds)
    const overlay = page.locator('#bitnet-overlay');
    await expect(overlay).toBeVisible({ timeout: 2000 });

    // Verify overlay contains expected text
    const text = await overlay.textContent();
    expect(text).toMatch(/BitNet|unlock|entries/);

    // Blur should remove overlay
    await page.locator('#username').focus();
    await expect(overlay).toBeHidden({ timeout: 1000 });
  });

  test('native messaging host responds to is_unlocked', async () => {
    // This test requires bitnet-native-host.exe to be built and registered.
    // It verifies the native messaging protocol by spawning the host directly.
    const { spawn } = require('child_process');
    const hostPath = path.resolve(__dirname, '../../target/release/bitnet-native-host.exe');
    
    // Skip if host not built
    const fs = require('fs');
    if (!fs.existsSync(hostPath)) {
      test.skip(true, 'bitnet-native-host.exe not found. Build with: cargo build --release --workspace');
      return;
    }

    const proc = spawn(hostPath, [], { stdio: ['pipe', 'pipe', 'ignore'] });
    
    return new Promise<void>((resolve, reject) => {
      const msg = Buffer.from(JSON.stringify({ action: 'is_unlocked' }));
      const lenBuf = Buffer.alloc(4);
      lenBuf.writeUInt32LE(msg.length, 0);
      
      proc.stdout?.once('data', (data: Buffer) => {
        // First 4 bytes = response length
        const respLen = data.readUInt32LE(0);
        const respBody = data.slice(4, 4 + respLen).toString();
        const resp = JSON.parse(respBody);
        expect(resp).toHaveProperty('success');
        proc.kill();
        resolve();
      });

      proc.stdin?.write(lenBuf);
      proc.stdin?.write(msg);
      proc.stdin?.end();

      setTimeout(() => {
        proc.kill();
        reject(new Error('Native host timeout'));
      }, 5000);
    });
  });
});