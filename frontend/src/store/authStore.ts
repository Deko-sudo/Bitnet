import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware'
import { api } from '@/api/client'

interface AuthState {
  token: string | null
  user: { id: number; username: string; email: string } | null
  isLocked: boolean
  isLoading: boolean
  lockTimeoutMinutes: number
  lastActivity: number
  setToken: (token: string, user: { id: number; username: string; email: string }) => void
  logout: () => void
  initAuth: () => void
  lock: () => void
  unlock: () => void
  setLockTimeout: (minutes: number) => void
  touch: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      token: null,
      user: null,
      isLocked: false,
      isLoading: true,
      lockTimeoutMinutes: 5,
      lastActivity: Date.now(),
      setToken: (token, user) => set({ token, user, isLocked: false, lastActivity: Date.now() }),
      logout: () => {
        const token = get().token
        set({ token: null, user: null, isLocked: false })
        sessionStorage.removeItem('bitnet-auth')
        if (token) {
          api.post('/auth/logout').catch(() => {})
        }
        window.location.replace('/login')
      },
      lock: () => set({ isLocked: true }),
      unlock: () => set({ isLocked: false, lastActivity: Date.now() }),
      setLockTimeout: (minutes) => set({ lockTimeoutMinutes: minutes }),
      touch: () => set({ lastActivity: Date.now() }),
      initAuth: () => {
        const state = get()
        if (state.isLocked) {
          set({ isLoading: false })
          return
        }
        if (state.token && state.lastActivity && state.lockTimeoutMinutes > 0) {
          const elapsed = Date.now() - state.lastActivity
          const timeout = state.lockTimeoutMinutes * 60 * 1000
          if (elapsed > timeout) {
            set({ isLocked: true, isLoading: false })
          } else {
            set({ isLocked: false, isLoading: false })
          }
        } else {
          set({ isLoading: false })
        }
      },
    }),
    {
      name: 'bitnet-auth',
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        token: state.token,
        user: state.user,
        isLocked: state.isLocked,
        lockTimeoutMinutes: state.lockTimeoutMinutes,
        lastActivity: state.lastActivity,
      }),
    }
  )
)