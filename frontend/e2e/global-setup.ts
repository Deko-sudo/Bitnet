import { randomBytes } from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import http from 'http'

const BACKEND_PORT = 8000
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`

function waitForServer(url: string, timeout = 30000): Promise<void> {
  return new Promise((resolve, reject) => {
    const start = Date.now()
    const check = () => {
      http
        .get(`${url}/health`, (res) => {
          let data = ''
          res.on('data', (chunk) => (data += chunk))
          res.on('end', () => {
            try {
              const json = JSON.parse(data)
              if (json.status === 'ok' || json.status === 'degraded') {
                resolve()
              } else {
                retry(new Error(`Unexpected health status: ${data}`))
              }
            } catch {
              retry(new Error(`Invalid JSON: ${data}`))
            }
          })
        })
        .on('error', (err) => retry(err))
    }
    const retry = (err: Error) => {
      if (Date.now() - start > timeout) {
        reject(new Error(`Server not ready after ${timeout}ms: ${err.message}`))
      } else {
        setTimeout(check, 500)
      }
    }
    check()
  })
}

function registerUser(url: string, username: string, email: string, password: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ username, email, password })
    const req = http.request(
      `${url}/api/v1/auth/register`,
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let body = ''
        res.on('data', (chunk) => (body += chunk))
        res.on('end', () => {
          if (res.statusCode === 201 || res.statusCode === 409) {
            resolve()
          } else {
            reject(new Error(`Registration failed: ${res.statusCode} ${body}`))
          }
        })
      }
    )
    req.on('error', reject)
    req.write(data)
    req.end()
  })
}

function loginUser(url: string, username: string, password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({ username, password })
    const req = http.request(
      `${url}/api/v1/auth/login`,
      { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } },
      (res) => {
        let body = ''
        res.on('data', (chunk) => (body += chunk))
        res.on('end', () => {
          if (res.statusCode === 200) {
            const json = JSON.parse(body)
            resolve(json.access_token)
          } else {
            reject(new Error(`Login failed: ${res.statusCode} ${body}`))
          }
        })
      }
    )
    req.on('error', reject)
    req.write(data)
    req.end()
  })
}

export default async function globalSetup() {
  const tmpDir = os.tmpdir()
  const keyFile = path.join(tmpDir, 'bitnet_e2e_server_key.bin')
  const dbFile = path.join(tmpDir, 'bitnet_e2e_test.db')

  fs.writeFileSync(keyFile, randomBytes(32))
  if (fs.existsSync(dbFile)) {
    try { fs.unlinkSync(dbFile) } catch {}
  }

  process.env.BITNET_SERVER_WRAP_KEY_FILE = keyFile
  process.env.SQLALCHEMY_DATABASE_URL = `sqlite:///${dbFile.replace(/\\/g, '/')}`
  process.env.E2E_KEY_FILE = keyFile
  process.env.E2E_DB_FILE = dbFile

  await waitForServer(BACKEND_URL, 30000)

  const testUsername = `e2euser_${Date.now()}`
  const testEmail = `${testUsername}@test.com`
  const testPassword = 'E2eT3st!Pass2024'

  await registerUser(BACKEND_URL, testUsername, testEmail, testPassword)
  const token = await loginUser(BACKEND_URL, testUsername, testPassword)

  process.env.E2E_USERNAME = testUsername
  process.env.E2E_EMAIL = testEmail
  process.env.E2E_PASSWORD = testPassword
  process.env.E2E_TOKEN = token
}