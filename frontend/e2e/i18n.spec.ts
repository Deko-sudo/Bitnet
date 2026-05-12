import { test, expect } from '@playwright/test'
import http from 'http'

const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:5173'
const API_URL = 'http://127.0.0.1:8000'
const TEST_PASSWORD = 'E2eT3st!Pass2024'

const testUser = `i18n_${Date.now()}`

async function registerAndLogin(): Promise<void> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ username: testUser, email: `${testUser}@test.com`, password: TEST_PASSWORD })
    const req = http.request(
      `${API_URL}/api/v1/auth/register`,
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let body = ''
        res.on('data', (chunk) => (body += chunk))
        res.on('end', () => { res.statusCode === 201 || res.statusCode === 409 ? resolve() : reject() })
      }
    )
    req.on('error', reject)
    req.write(data)
    req.end()
  })
}

async function loginAsPage(page: import('@playwright/test').Page) {
  await page.goto(`${BASE_URL}/login`)
  await page.locator('[data-testid="login-username"]').fill(testUser)
  await page.locator('[data-testid="login-password"]').fill(TEST_PASSWORD)
  await page.locator('[data-testid="login-submit"]').click()
  await page.waitForURL(/\/(vault|$)/, { timeout: 15000 })
  await page.waitForTimeout(500)
}

test.describe('i18n Language Switching', () => {
  test.beforeAll(async () => { await registerAndLogin() })

  test.beforeEach(async ({ page }) => {
    await loginAsPage(page)
  })

  test('switch to Russian and verify UI text', async ({ page }) => {
    await page.locator('[data-testid="nav-settings"]').click()
    await page.waitForURL(/\/settings/, { timeout: 10000 })

    await page.locator('[data-testid="lang-ru"]').click()
    await page.waitForTimeout(500)

    const vaultNav = page.locator('[data-testid="nav-vault"]')
    const vaultTitle = await vaultNav.getAttribute('title')
    expect(vaultTitle).toContain('Хранилище')
  })

  test('switch to English and verify UI text', async ({ page }) => {
    await page.locator('[data-testid="nav-settings"]').click()
    await page.waitForURL(/\/settings/, { timeout: 10000 })

    await page.locator('[data-testid="lang-en"]').click()
    await page.waitForTimeout(500)

    const vaultNav = page.locator('[data-testid="nav-vault"]')
    const vaultTitle = await vaultNav.getAttribute('title')
    expect(vaultTitle).toContain('Vault')
  })
})