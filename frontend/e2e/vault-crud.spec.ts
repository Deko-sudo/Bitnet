import { test, expect } from '@playwright/test'
import http from 'http'

const BASE_URL = process.env.E2E_BASE_URL || 'http://127.0.0.1:5173'
const API_URL = 'http://127.0.0.1:8000'
const TEST_PASSWORD = 'E2eT3st!Pass2024'

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

let testUser = ''
let registered = false

async function registerUser(): Promise<void> {
  if (registered) return
  testUser = `vault_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`
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

test.describe('Vault CRUD', () => {
  test.beforeAll(async () => {
    await registerUser()
  })

  test('create a new entry', async ({ page }) => {
    await loginAsPage(page)
    const token = await loginViaApi()

    const createResult = await makeRequest('POST', '/entries/', {
      title: 'E2E Test Entry',
      username: 'testuser@example.com',
      password: 'SuperSecret123!',
    }, token)
    expect([200, 201]).toContain(createResult.status)
  })

  test('edit an existing entry via API', async ({ page }) => {
    await loginAsPage(page)
    const token = await loginViaApi()

    const createResult = await makeRequest('POST', '/entries/', {
      title: 'Original Title',
      username: 'user',
      password: 'Pass123!',
    }, token)
    expect([200, 201]).toContain(createResult.status)

    const entryId = JSON.parse(createResult.body).id
    const patchResult = await makeRequest('PATCH', `/entries/${entryId}`, {
      title: 'Updated Title',
      username: 'user',
      password: 'Pass123!',
    }, token)
    expect(patchResult.status).toBe(200)
  })

  test('delete an entry via API', async ({ page }) => {
    await loginAsPage(page)
    const token = await loginViaApi()

    const createResult = await makeRequest('POST', '/entries/', {
      title: 'Delete Me',
      username: 'user',
      password: 'Pass123!',
    }, token)
    expect([200, 201]).toContain(createResult.status)

    const entryId = JSON.parse(createResult.body).id
    const deleteResult = await makeRequest('DELETE', `/entries/${entryId}`, undefined, token)
    expect([200, 204]).toContain(deleteResult.status)
  })
})