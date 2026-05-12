import { useState, useEffect, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/api/client'
import type { VaultEntry } from '@/types'
import { X, Eye, EyeOff, RefreshCw } from 'lucide-react'
import { useThemeStore } from '@/store/themeStore'
import { secureRandomPassword } from '@/utils/random'

interface EntryEditorProps {
  entry?: VaultEntry | null
  prefillPassword?: string
  onClose: () => void
  onSaved: () => void
}

export default function EntryEditor({ entry, prefillPassword, onClose, onSaved }: EntryEditorProps) {
  const [title, setTitle] = useState(entry?.title ?? '')
  const [username, setUsername] = useState(entry?.username ?? '')
  const [password, setPassword] = useState(entry?.password ?? prefillPassword ?? '')
  const [url, setUrl] = useState(entry?.url ?? '')
  const [notes, setNotes] = useState(entry?.notes ?? '')
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const isPixel = useThemeStore((s) => s.currentTheme) === 'pixel'
  const { t } = useTranslation()

  useEffect(() => {
    return () => {
      setPassword('')
      setUsername('')
      setNotes('')
      setUrl('')
    }
  }, [])

  const isEditing = !!entry
  const prevEntryIdRef = useRef<number | undefined>(entry?.id)

  useEffect(() => {
    if (!entry) return
    if (entry.id !== prevEntryIdRef.current) {
      prevEntryIdRef.current = entry.id
      if ('password' in entry) {
        setTitle(entry.title ?? '')
        setUsername(entry.username ?? '')
        setPassword(entry.password ?? '')
        setUrl(entry.url ?? '')
        setNotes(entry.notes ?? '')
      }
    }
  }, [entry])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const payload: Record<string, string | null> = {
        title,
        username,
        password,
      }
      if (url.trim()) payload.url = url
      if (notes.trim()) payload.notes = notes

      if (isEditing && entry) {
        await api.patch(`/entries/${entry.id}`, payload)
      } else {
        await api.post('/entries/', payload)
      }
      setPassword('')
      setUsername('')
      setNotes('')
      setUrl('')
      onSaved()
      onClose()
    } catch (err: any) {
      setError(err.response?.status === 422 ? t('common.validationFailed') : t('common.saveError'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div data-testid="entry-editor" className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
      <div className={[
        'w-full max-w-lg max-h-[90vh] overflow-y-auto rounded-lg border border-border bg-card p-6 shadow-lg',
        isPixel ? 'border-4 border-primary font-pixel' : '',
      ].join(' ')}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">{isEditing ? t('vault.editEntry') : t('vault.newEntry')}</h2>
          <button data-testid="editor-close" onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-accent">
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="mb-4 rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1">
            <label className="text-sm font-medium">{t('vault.titleLabel')} *</label>
            <input
              data-testid="editor-title"
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className={[
                'w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring',
                isPixel ? 'rounded-none border-2' : '',
              ].join(' ')}
              placeholder={t('vault.titlePlaceholder')}
              required
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('vault.usernameLabel')}</label>
            <input
              data-testid="editor-username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className={[
                'w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring',
                isPixel ? 'rounded-none border-2' : '',
              ].join(' ')}
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('vault.passwordLabel')} *</label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  data-testid="editor-password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={[
                    'w-full rounded-md border border-input bg-background px-3 py-2 pr-16 text-sm outline-none focus:ring-2 focus:ring-ring',
                    isPixel ? 'rounded-none border-2' : '',
                  ].join(' ')}
                  required
                />
                <div className="absolute right-1 top-1/2 -translate-y-1/2 flex gap-1">
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="rounded p-1 text-muted-foreground hover:bg-accent"
                  >
                    {showPassword ? <EyeOff size={14} /> : <Eye size={14} />}
                  </button>
                  <button
                    type="button"
                    data-testid="editor-generate"
                    onClick={() => setPassword(secureRandomPassword())}
                    className="rounded p-1 text-muted-foreground hover:bg-accent"
                    title="Generate"
                  >
                    <RefreshCw size={14} />
                  </button>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('vault.urlLabel')}</label>
            <input
              data-testid="editor-url"
              type="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              className={[
                'w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring',
                isPixel ? 'rounded-none border-2' : '',
              ].join(' ')}
              placeholder="https://..."
            />
          </div>

          <div className="space-y-1">
            <label className="text-sm font-medium">{t('vault.notesLabel')}</label>
            <textarea
              data-testid="editor-notes"
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              className={[
                'w-full rounded-md border border-input bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring',
                isPixel ? 'rounded-none border-2' : '',
              ].join(' ')}
            />
          </div>

          <div className="flex gap-2 pt-2">
            <button
              type="button"
              data-testid="editor-cancel"
              onClick={onClose}
              className="flex-1 rounded-md border border-border bg-background px-4 py-2 text-sm font-medium hover:bg-accent"
            >
              {t('vault.cancel')}
            </button>
            <button
              type="submit"
              data-testid="editor-submit"
              disabled={loading}
              className={[
                'flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50',
                isPixel ? 'rounded-none' : '',
              ].join(' ')}
            >
              {loading ? t('common.saving') : isEditing ? t('vault.update') : t('vault.create')}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}