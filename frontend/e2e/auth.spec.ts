import { test, expect } from '@playwright/test'

const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:5173'

test.describe('Authentication', () => {
  test('login with valid credentials', async ({ page }) => {
    const user = `login_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
    const { status } = await registerViaApi(user, `${user}@test.com`, 'E2eT3st!Pass2024')
    expect([201, 409]).toContain(status)

    await page.goto(`${BASE_URL}/login`)
    await page.locator('[data-testid="login-username"]').fill(user)
    await page.locator('[data-testid="login-password"]').fill('E2eT3st!Pass2024')
    await page.locator('[data-testid="login-submit"]').click()
    await page.waitForURL(/\/(vault|$)/, { timeout: 15000 })
    expect(page.url()).toMatch(/\/(vault|$)/)
  })

  test('login with invalid credentials shows error', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`)
    const uniqueUser = `wrong_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
    await page.locator('[data-testid="login-username"]').fill(uniqueUser)
    await page.locator('[data-testid="login-password"]').fill('definitely_wrong_pass_12345')
    await page.locator('[data-testid="login-submit"]').click()
    await expect(page.locator('[data-testid="login-error"]')).toBeVisible({ timeout: 10000 })
  })

  test('navigate from login to register and back', async ({ page }) => {
    await page.goto(`${BASE_URL}/login`)
    await page.locator('[data-testid="login-register-link"]').click()
    await expect(page).toHaveURL(/\/register/, { timeout: 10000 })
  })
})

async function registerViaApi(username: string, email: string, password: string): Promise<{ status: number; body: string }> {
  const http = await import('http')
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ username, email, password })
    const req = http.request(
      'http://127.0.0.1:8000/api/v1/auth/register',
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let body = ''
        res.on('data', (chunk) => (body += chunk))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
      }
    )
    req.on('error', reject)
    req.write(data)
    req.end()
  })
}