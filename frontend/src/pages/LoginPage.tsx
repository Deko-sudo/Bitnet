import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useAuthStore } from '@/store/authStore'
import { api } from '@/api/client'
import { Eye, EyeOff, Shield, Timer } from 'lucide-react'

export default function LoginPage() {
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [rateLimited, setRateLimited] = useState(false)
  const navigate = useNavigate()
  const setToken = useAuthStore((s) => s.setToken)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setRateLimited(false)
    setLoading(true)
    try {
      const res = await api.post('/auth/login', { username, password })
      const data = res.data as { access_token: string; user_id: number; username: string }
      // Fetch full user profile to get email since login only returns id+username
      let email = ''
      try {
        const meRes = await api.get('/auth/me', {
          headers: { Authorization: `Bearer ${data.access_token}` },
        })
        email = meRes.data.email ?? ''
      } catch {
        // Ignore me errors; proceed without email if unavailable
      }
      setToken(data.access_token, {
        id: data.user_id,
        username: data.username,
        email,
      })
      navigate('/vault')
    } catch (err: any) {
      if (err.response?.status === 429) {
        setRateLimited(true)
        setError(t('auth.tooManyAttemptsLogin'))
      } else {
        setError(t('auth.invalidCredentials'))
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-4">
      <div className="w-full max-w-sm space-y-6">
        <div className="flex flex-col items-center gap-2">
          <Shield size={48} className="text-primary" />
          <h1 className="text-2xl font-bold tracking-tight">{t('app.title')}</h1>
          <p className="text-sm text-muted-foreground">{t('auth.loginSubtitle')}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div data-testid="login-error" className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive flex items-center gap-2">
              {rateLimited ? <Timer size={16} /> : null}
              {error}
            </div>
          )}

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('auth.username')}</label>
            <input
              data-testid="login-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none ring-offset-background focus:ring-2 focus:ring-ring"
              required
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('auth.password')}</label>
            <div className="relative">
              <input
                data-testid="login-password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 pr-10 text-sm outline-none ring-offset-background focus:ring-2 focus:ring-ring"
                required
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
            type="submit"
            data-testid="login-submit"
            disabled={loading || rateLimited}
            className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? t('auth.signingIn') : t('auth.login')}
          </button>
        </form>

        <p className="text-center text-sm text-muted-foreground">
          {t('auth.noAccount')}{' '}
          <Link to="/register" data-testid="login-register-link" className="text-primary hover:underline">{t('auth.register')}</Link>
        </p>
      </div>
    </div>
  )
}
