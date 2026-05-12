import fs from 'fs'
import os from 'os'
import path from 'path'

export default async function globalTeardown() {
  const pid = process.env.E2E_UVICORN_PID
  if (pid) {
    try {
      process.kill(Number(pid), 'SIGTERM')
    } catch {
      // Process may have already exited
    }
  }

  const keyFile = process.env.E2E_KEY_FILE
  if (keyFile && fs.existsSync(keyFile)) {
    fs.unlinkSync(keyFile)
  }

  const dbFile = process.env.E2E_DB_FILE
  if (dbFile && fs.existsSync(dbFile)) {
    try {
      fs.unlinkSync(dbFile)
    } catch {
      // DB file may be locked on Windows
    }
  }
}