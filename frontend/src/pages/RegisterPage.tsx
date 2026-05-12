import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { api } from '@/api/client'
import { Eye, EyeOff, Shield, Check, X } from 'lucide-react'

export default function RegisterPage() {
  const { t } = useTranslation()
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const hasMinLength = password.length >= 12
  const hasUpper = /[A-Z]/.test(password)
  const hasDigit = /\d/.test(password)
  const hasSpecial = /[^a-zA-Z0-9]/.test(password)
  const strength = [hasMinLength, hasUpper, hasDigit, hasSpecial].filter(Boolean).length

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    if (strength < 3) {
      setError(t('auth.weakPassword'))
      return
    }
    setLoading(true)
    try {
      await api.post('/auth/register', { username, email, password })
      navigate('/login')
    } catch (err: any) {
      setError(err.response?.status === 409 ? t('auth.userExists') : t('register.registrationFailed'))
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
          <p className="text-sm text-muted-foreground">{t('auth.registerSubtitle')}</p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {error && (
            <div data-testid="register-error" className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">
              {error}
            </div>
          )}

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('auth.username')}</label>
            <input
              data-testid="register-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none ring-offset-background focus:ring-2 focus:ring-ring"
              required
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('auth.email')}</label>
            <input
              data-testid="register-email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none ring-offset-background focus:ring-2 focus:ring-ring"
              required
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('auth.password')}</label>
            <div className="relative">
              <input
                data-testid="register-password"
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

          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs">
              <span className={hasMinLength ? 'text-green-500' : 'text-muted-foreground'}>
                {hasMinLength ? <Check size={12} /> : <X size={12} />} {t('register.charMin')}
              </span>
              <span className={hasUpper ? 'text-green-500' : 'text-muted-foreground'}>
                {hasUpper ? <Check size={12} /> : <X size={12} />} {t('register.uppercase')}
              </span>
              <span className={hasDigit ? 'text-green-500' : 'text-muted-foreground'}>
                {hasDigit ? <Check size={12} /> : <X size={12} />} {t('register.digit')}
              </span>
              <span className={hasSpecial ? 'text-green-500' : 'text-muted-foreground'}>
                {hasSpecial ? <Check size={12} /> : <X size={12} />} {t('register.special')}
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full bg-muted">
              <div
                className="h-full rounded-full transition-all"
                style={{
                  width: `${(strength / 4) * 100}%`,
                  backgroundColor:
                    strength <= 1 ? 'hsl(var(--destructive))' : strength === 2 ? 'orange' : strength === 3 ? 'yellow' : 'hsl(120, 60%, 50%)',
                }}
              />
            </div>
          </div>

          <button
            type="submit"
            data-testid="register-submit"
            disabled={loading}
            className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground transition-colors hover:bg-primary/90 disabled:opacity-50"
          >
            {loading ? t('auth.creating') : t('auth.register')}
          </button>
        </form>

        <p className="text-center text-sm text-muted-foreground">
          {t('auth.hasAccount')}{' '}
          <Link to="/login" className="text-primary hover:underline">{t('auth.login')}</Link>
        </p>
      </div>
    </div>
  )
}
