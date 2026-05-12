import { useAuthStore } from '@/store/authStore'
import { useThemeStore, themes } from '@/store/themeStore'
import { useEffect, useState } from 'react'
import { Sun, Moon, Monitor } from 'lucide-react'

export default function Header() {
  const user = useAuthStore((s) => s.user)
  const { currentTheme, setTheme } = useThemeStore()
  const isLocked = useAuthStore((s) => s.isLocked)
  const lockTimeoutMinutes = useAuthStore((s) => s.lockTimeoutMinutes)
  const initialTimeLeft = Math.max(0, lockTimeoutMinutes * 60 - Math.floor((Date.now() - useAuthStore.getState().lastActivity) / 1000))
  const [timeLeft, setTimeLeft] = useState(initialTimeLeft)

  useEffect(() => {
    if (!user || isLocked) return
    if (lockTimeoutMinutes <= 0) return
    const interval = setInterval(() => {
      const { lastActivity } = useAuthStore.getState()
      const elapsed = (Date.now() - lastActivity) / 1000
      const remaining = Math.max(0, lockTimeoutMinutes * 60 - elapsed)
      setTimeLeft(Math.round(remaining))
    }, 1000)
    return () => clearInterval(interval)
  }, [user, isLocked, lockTimeoutMinutes])

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return `${m}:${sec.toString().padStart(2, '0')}`
  }

  return (
    <header className="flex h-14 items-center justify-between border-b border-border bg-card px-4">
      <div className="flex items-center gap-2">
        <h1 className="text-lg font-semibold tracking-tight">BitNet</h1>
        <span className="rounded bg-primary px-1.5 py-0.5 text-[10px] font-medium text-primary-foreground">
          Vault
        </span>
      </div>

      <div className="flex items-center gap-3">
        {user && !isLocked && lockTimeoutMinutes > 0 && (
          <span className="text-xs text-muted-foreground tabular-nums">
            Lock in {formatTime(timeLeft)}
          </span>
        )}

        <div className="flex items-center gap-1 rounded-md border border-border bg-background p-1">
          {(['light', 'midnight', 'pixel'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTheme(t)}
              className={[
                'rounded px-2 py-1 text-xs transition-colors',
                currentTheme === t
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
              ].join(' ')}
              title={themes[t]?.name ?? t}
            >
              {t === 'light' && <Sun size={14} />}
              {t === 'midnight' && <Moon size={14} />}
              {t === 'pixel' && <Monitor size={14} />}
            </button>
          ))}
        </div>
      </div>
    </header>
  )
}