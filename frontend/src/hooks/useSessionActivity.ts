import { useEffect, useRef } from 'react'
import { useAuthStore } from '@/store/authStore'

const EVENTS = ['mousedown', 'keydown', 'touchstart', 'scroll']

export function useSessionActivity() {
  const token = useAuthStore((s) => s.token)
  const isLocked = useAuthStore((s) => s.isLocked)
  const lockTimeoutMinutes = useAuthStore((s) => s.lockTimeoutMinutes)
  const lock = useAuthStore((s) => s.lock)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  useEffect(() => {
    if (!token || isLocked) return
    if (lockTimeoutMinutes === 0) {
      if (timerRef.current) {
        clearInterval(timerRef.current)
        timerRef.current = null
      }
      return
    }

    const checkTimeout = () => {
      const { lastActivity } = useAuthStore.getState()
      const elapsed = Date.now() - lastActivity
      const timeout = lockTimeoutMinutes * 60 * 1000
      if (elapsed > timeout) {
        lock()
      }
    }

    timerRef.current = setInterval(checkTimeout, 5000)

    const handler = () => {
      useAuthStore.getState().touch()
    }

    EVENTS.forEach((e) => document.addEventListener(e, handler, { passive: true }))

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
      EVENTS.forEach((e) => document.removeEventListener(e, handler))
    }
  }, [token, isLocked, lockTimeoutMinutes, lock])
}