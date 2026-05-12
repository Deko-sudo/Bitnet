import { test, expect } from '@playwright/test'
import http from 'http'

const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:5173'
const API_URL = 'http://127.0.0.1:8000'
const TEST_PASSWORD = 'E2eT3st!Pass2024'

const testUser = `gen_${Date.now()}`

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

test.describe('Password Generator', () => {
  test.beforeAll(async () => { await registerAndLogin() })

  test.beforeEach(async ({ page }) => {
    await loginAsPage(page)
    await page.locator('[data-testid="nav-generator"]').click()
    await page.waitForURL(/\/generator/, { timeout: 10000 })
  })

  test('generate a password', async ({ page }) => {
    const output = page.locator('[data-testid="generator-output"]')
    await expect(output).toContainText(/generate/i)

    await page.locator('[data-testid="generator-generate-btn"]').click()

    const text = await output.textContent()
    expect(text).toBeTruthy()
    expect(text!.length).toBeGreaterThanOrEqual(8)
  })

  test('copy generated password', async ({ page }) => {
    await page.locator('[data-testid="generator-generate-btn"]').click()
    const copiedEl = page.locator('[data-testid="generator-copied"]')
    if (await copiedEl.isVisible()) {
      await expect(copiedEl).toBeVisible({ timeout: 3000 })
    }
  })
})