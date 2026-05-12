import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { useAuthStore } from '@/store/authStore'
import { useThemeStore } from '@/store/themeStore'
import { api } from '@/api/client'
import { Lock, Eye, EyeOff, Timer } from 'lucide-react'

export default function LockScreen() {
  const { t } = useTranslation()
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [rateLimited, setRateLimited] = useState(false)
  const [retryAfter, setRetryAfter] = useState(0)
  const setToken = useAuthStore((s) => s.setToken)
  const unlock = useAuthStore((s) => s.unlock)
  const user = useAuthStore((s) => s.user)
  const currentTheme = useThemeStore((s) => s.currentTheme)
  const isPixel = currentTheme === 'pixel'
  const retryRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const startRetryCountdown = (seconds: number) => {
    setRetryAfter(seconds)
    setRateLimited(true)
    if (retryRef.current) clearInterval(retryRef.current)
    retryRef.current = setInterval(() => {
      setRetryAfter((prev) => {
        if (prev <= 1) {
          if (retryRef.current) clearInterval(retryRef.current)
          setRateLimited(false)
          return 0
        }
        return prev - 1
      })
    }, 1000)
  }

  useEffect(() => {
    return () => {
      if (retryRef.current) clearInterval(retryRef.current)
      setPassword('')
    }
  }, [])

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (password.length < 1) {
      setError(t('lock.passwordRequired'))
      return
    }
    if (rateLimited) return
    setLoading(true)
    try {
      const res = await api.post('/auth/login', {
        username: user?.username ?? '',
        password,
      })
      const data = res.data
      if (data.access_token && data.user) {
        setToken(data.access_token, { id: data.user_id, username: data.username, email: data.email ?? '' })
      }
      unlock()
      setPassword('')
    } catch (err: any) {
      if (err.response?.status === 429) {
        const retry = err.response.headers?.['retry-after']
        const seconds = retry ? parseInt(retry, 10) : 30
        startRetryCountdown(seconds)
        setError(t('lock.tooManyAttempts', { seconds }))
      } else {
        setError(t('auth.invalidCredentials'))
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div data-testid="lock-screen" className="fixed inset-0 z-[100] flex items-center justify-center bg-background/95 backdrop-blur-sm">
      <div className={[
        'w-full max-w-sm space-y-6 rounded-lg border border-border bg-card p-8 shadow-lg',
        isPixel ? 'border-4 border-primary font-pixel' : '',
      ].join(' ')}>
        <div className="flex flex-col items-center gap-3">
          <div className={[
            'flex h-16 w-16 items-center justify-center rounded-full bg-primary/10',
            isPixel ? 'rounded-none border-2 border-primary' : '',
          ].join(' ')}>
            <Lock size={32} className="text-primary" />
          </div>
          <div className="text-center">
            <h2 className="text-lg font-semibold">{t('lock.vaultLocked')}</h2>
            {user && (
              <p className="text-sm text-muted-foreground">{user.username}</p>
            )}
          </div>
        </div>

        <form onSubmit={handleUnlock} className="space-y-4">
          {error && (
            <div className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive flex items-center gap-2">
              {rateLimited ? <Timer size={16} /> : null}
              {error}
            </div>
          )}

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('lock.masterPassword')}</label>
            <div className="relative">
              <input
                data-testid="lock-password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className={[
                  'w-full rounded-md border border-input bg-background px-3 py-2 pr-10 text-sm outline-none ring-offset-background focus:ring-2 focus:ring-ring',
                  isPixel ? 'rounded-none border-2' : '',
                ].join(' ')}
                placeholder={t('lock.enterPassword')}
                autoFocus
                disabled={rateLimited}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground"
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <button
            data-testid="lock-submit"
            type="submit"
            disabled={loading || rateLimited}
            className={[
              'w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50',
              isPixel ? 'rounded-none border-2 border-primary bg-transparent text-primary hover:bg-primary hover:text-primary-foreground' : '',
            ].join(' ')}
          >
            {rateLimited ? t('lock.retryIn', { seconds: retryAfter }) : loading ? t('lock.unlocking') : t('lock.unlock')}
          </button>
        </form>

        <button
          onClick={() => useAuthStore.getState().logout()}
          className="w-full text-center text-xs text-muted-foreground hover:text-foreground"
        >
          {t('lock.logoutInstead')}
        </button>
      </div>
    </div>
  )
}