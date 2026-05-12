import { test, expect } from '@playwright/test'
import http from 'http'

const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:5173'
const API_URL = 'http://127.0.0.1:8000'
const TEST_PASSWORD = 'E2eT3st!Pass2024'

const testUser = `lock_${Date.now()}`

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

test.describe('Lock Screen', () => {
  test.beforeAll(async () => { await registerAndLogin() })

  test.beforeEach(async ({ page }) => {
    await loginAsPage(page)
  })

  test('lock and unlock the vault', async ({ page }) => {
    await page.evaluate(() => {
      const raw = sessionStorage.getItem('bitnet-auth')
      if (raw) {
        const data = JSON.parse(raw)
        if (data?.state) {
          data.state.isLocked = true
          sessionStorage.setItem('bitnet-auth', JSON.stringify(data))
        }
      }
    })
    await page.reload()
    await expect(page.locator('[data-testid="lock-screen"]')).toBeVisible({ timeout: 15000 })

    await page.locator('[data-testid="lock-password"]').fill(TEST_PASSWORD)
    await page.locator('[data-testid="lock-submit"]').click()
    await expect(page.locator('[data-testid="lock-screen"]')).toBeHidden({ timeout: 10000 })
  })

  test('lock screen shows error on wrong password', async ({ page }) => {
    await page.evaluate(() => {
      const raw = sessionStorage.getItem('bitnet-auth')
      if (raw) {
        const data = JSON.parse(raw)
        if (data?.state) {
          data.state.isLocked = true
          sessionStorage.setItem('bitnet-auth', JSON.stringify(data))
        }
      }
    })
    await page.reload()
    await expect(page.locator('[data-testid="lock-screen"]')).toBeVisible({ timeout: 15_000 })

    await page.locator('[data-testid="lock-password"]').fill('wrong_password_12345')
    await page.locator('[data-testid="lock-submit"]').click()

    await expect(page.locator('[data-testid="lock-screen"]')).toBeVisible({ timeout: 5_000 })
  })
})