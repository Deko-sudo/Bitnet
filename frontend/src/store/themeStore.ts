import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { themes } from '@/themes'

export interface ThemeState {
  currentTheme: string
  crtEnabled: boolean
  themes: typeof themes
  setTheme: (key: string) => void
  setCrtEnabled: (enabled: boolean) => void
  applyTheme: () => void
}

export const useThemeStore = create<ThemeState>()(
  persist(
    (set, get) => ({
      currentTheme: 'midnight',
      crtEnabled: true,
      themes,
      setTheme: (key) => {
        set({ currentTheme: key })
        get().applyTheme()
      },
      setCrtEnabled: (enabled) => {
        set({ crtEnabled: enabled })
        get().applyTheme()
      },
      applyTheme: () => {
        const { currentTheme, crtEnabled } = get()
        const root = document.documentElement
        const def = themes[currentTheme]
        const vars = def?.vars ?? themes.midnight.vars

        Object.entries(vars).forEach(([k, v]) => {
          root.style.setProperty(k, v)
        })

        const body = document.body
        const existingOverlay = document.getElementById('pixel-overlay')

        if (currentTheme === 'pixel' && crtEnabled) {
          body.classList.add('font-pixel')
          if (!existingOverlay) {
            const overlay = document.createElement('div')
            overlay.id = 'pixel-overlay'
            overlay.className = 'pointer-events-none fixed inset-0 z-50 pixel-scanlines pixel-crt-flicker'
            document.body.appendChild(overlay)
          }
        } else {
          body.classList.remove('font-pixel')
          if (existingOverlay) {
            existingOverlay.remove()
          }
        }
      },
    }),
    {
      name: 'bitnet-theme',
    }
  )
)

export { themes }