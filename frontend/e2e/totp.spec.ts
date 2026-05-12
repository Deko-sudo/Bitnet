import { test, expect } from '@playwright/test'
import http from 'http'
import crypto from 'crypto'

const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:5173'
const API_URL = 'http://127.0.0.1:8000'
const TEST_PASSWORD = 'E2eT3st!Pass2024'
const KNOWN_SECRET = 'JBSWY3DPEHPK3PXP'

function makeRequest(method: string, path: string, data?: object, token?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const bodyData = data ? JSON.stringify(data) : undefined
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) headers['Authorization'] = `Bearer ${token}`
    if (bodyData) headers['Content-Length'] = String(Buffer.byteLength(bodyData))
    const options: http.RequestOptions = {
      method,
      hostname: '127.0.0.1',
      port: 8000,
      path: `/api/v1${path}`,
      headers,
    }
    const req = http.request(options, (res) => {
      let body = ''
      res.on('data', (chunk) => (body += chunk))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body }))
    })
    req.on('error', reject)
    if (bodyData) req.write(bodyData)
    req.end()
  })
}

function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const clean = input.replace(/=+$/, '').toUpperCase()
  let bits = ''
  for (const ch of clean) {
    const val = alphabet.indexOf(ch)
    if (val === -1) throw new Error(`Invalid base32 char: ${ch}`)
    bits += val.toString(2).padStart(5, '0')
  }
  const bytes: number[] = []
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2))
  }
  return Buffer.from(bytes)
}

function computeTotp(secret: string, digits = 6, period = 30): string {
  const key = base32Decode(secret)
  const counter = Math.floor(Date.now() / 1000 / period)
  const counterBuf = Buffer.alloc(8)
  counterBuf.writeUInt32BE(counter, 4)
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest()
  const offset = hmac[hmac.length - 1] & 0x0f
  const code = ((hmac[offset] & 0x7f) << 24 | (hmac[offset + 1] & 0xff) << 16 | (hmac[offset + 2] & 0xff) << 8 | (hmac[offset + 3] & 0xff)) % (10 ** digits)
  return code.toString().padStart(digits, '0')
}

let testUser = ''
let registered = false

async function registerUser(): Promise<void> {
  if (registered) return
  testUser = `totp_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
  const regResult = await makeRequest('POST', '/auth/register', {
    username: testUser,
    email: `${testUser}@test.com`,
    password: TEST_PASSWORD,
  })
  if (regResult.status !== 201 && regResult.status !== 409) {
    throw new Error(`Registration failed: ${regResult.status} ${regResult.body}`)
  }
  registered = true
}

async function loginViaApi(): Promise<string> {
  const loginResult = await makeRequest('POST', '/auth/login', {
    username: testUser,
    password: TEST_PASSWORD,
  })
  if (loginResult.status !== 200) {
    throw new Error(`Login failed: ${loginResult.status} ${loginResult.body}`)
  }
  return JSON.parse(loginResult.body).access_token
}

async function loginAsPage(page: import('@playwright/test').Page) {
  await page.goto(`${BASE_URL}/login`)
  await page.locator('[data-testid="login-username"]').fill(testUser)
  await page.locator('[data-testid="login-password"]').fill(TEST_PASSWORD)
  await page.locator('[data-testid="login-submit"]').click()
  await page.waitForURL(/\/(vault|$)/, { timeout: 15000 })
  await page.waitForTimeout(500)
}

test.describe('TOTP Authenticator', () => {
  test.beforeAll(async () => {
    await registerUser()
  })

  test('set up TOTP via paste and verify it appears', async ({ page }) => {
    const token = await loginViaApi()

    const setupResult = await makeRequest('POST', '/totp/setup', {
      secret: KNOWN_SECRET,
      issuer: 'E2E Test Issuer',
      account_name: 'e2e@test.com',
      digits: 6,
      period: 30,
    }, token)
    expect([200, 201]).toContain(setupResult.status)

    const setupData = JSON.parse(setupResult.body)
    const totpId = setupData.id
    expect(totpId).toBeDefined()

    const code = computeTotp(KNOWN_SECRET)
    const verifyResult = await makeRequest('POST', `/totp/${totpId}/verify`, {
      code,
    }, token)
    expect(verifyResult.status).toBe(200)
    expect(JSON.parse(verifyResult.body).verified).toBe(true)

    await loginAsPage(page)

    await page.goto(`${BASE_URL}/authenticator`)
    await page.waitForTimeout(1500)

    const card = page.locator(`[data-testid="totp-card-${totpId}"]`)
    await expect(card).toBeVisible({ timeout: 10000 })
    await expect(card).toContainText('E2E Test Issuer')
  })

  test('delete a TOTP key', async ({ page }) => {
    const token = await loginViaApi()

    const setupResult = await makeRequest('POST', '/totp/setup', {
      secret: KNOWN_SECRET,
      issuer: 'Delete Test',
      account_name: 'delete@test.com',
      digits: 6,
      period: 30,
    }, token)
    expect([200, 201]).toContain(setupResult.status)

    const totpId = JSON.parse(setupResult.body).id

    const code = computeTotp(KNOWN_SECRET)
    const verifyResult = await makeRequest('POST', `/totp/${totpId}/verify`, {
      code,
    }, token)
    expect(verifyResult.status).toBe(200)

    await loginAsPage(page)

    await page.goto(`${BASE_URL}/authenticator`)
    await page.waitForTimeout(1500)

    const card = page.locator(`[data-testid="totp-card-${totpId}"]`)
    await expect(card).toBeVisible({ timeout: 10000 })

    const deleteBtn = card.locator('button').first()
    await deleteBtn.click()
    await page.waitForTimeout(500)

    const confirmBtn = page.locator('button:has-text("Delete")').last()
    await expect(confirmBtn).toBeVisible({ timeout: 5000 })
    await confirmBtn.click()
    await page.waitForTimeout(1000)

    await expect(card).not.toBeVisible({ timeout: 10000 })
  })

  test('authenticator page shows empty state when no keys', async ({ page }) => {
    const uniqueUser = `totp_empty_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
    const regResult = await makeRequest('POST', '/auth/register', {
      username: uniqueUser,
      email: `${uniqueUser}@test.com`,
      password: TEST_PASSWORD,
    })
    expect([201, 409]).toContain(regResult.status)

    await page.goto(`${BASE_URL}/login`)
    await page.locator('[data-testid="login-username"]').fill(uniqueUser)
    await page.locator('[data-testid="login-password"]').fill(TEST_PASSWORD)
    await page.locator('[data-testid="login-submit"]').click()
    await page.waitForURL(/\/(vault|$)/, { timeout: 15000 })
    await page.waitForTimeout(500)

    await page.goto(`${BASE_URL}/authenticator`)
    await page.waitForTimeout(1000)

    await expect(page.locator('text=No authenticator keys yet')).toBeVisible({ timeout: 10000 })
  })
})