import { useState, useEffect, useCallback, useRef } from 'react'
import { useTranslation } from 'react-i18next'
import type { TotpCodeResponse } from '@/types'
import { Copy, Trash2 } from 'lucide-react'
import { useThemeStore } from '@/store/themeStore'

interface TotpCardProps {
  entry: TotpCodeResponse
  linkedTitle?: string | null
  onDelete: (id: number) => void
}

export default function TotpCard({ entry, linkedTitle, onDelete }: TotpCardProps) {
  const { t } = useTranslation()
  const isPixel = useThemeStore((s) => s.currentTheme) === 'pixel'
  const [secondsLeft, setSecondsLeft] = useState(entry.seconds_remaining)
  const [code, setCode] = useState(entry.current_code)
  const [copied, setCopied] = useState(false)
  const copiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (copiedTimerRef.current) clearTimeout(copiedTimerRef.current)
    }
  }, [])

  useEffect(() => {
    const interval = setInterval(() => {
      const remaining = entry.period - (Math.floor(Date.now() / 1000) % entry.period)
      setSecondsLeft(remaining)
      if (remaining === entry.period) {
        setCode(entry.current_code)
      }
    }, 1000)
    return () => clearInterval(interval)
  }, [entry])

  const progress = secondsLeft / entry.period
  const formattedCode = code.length > 3 ? `${code.slice(0, 3)} ${code.slice(3)}` : code

  const copy = useCallback(() => {
    navigator.clipboard.writeText(code).then(() => {
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000)
    })
    setCopied(true)
    if (copiedTimerRef.current) clearTimeout(copiedTimerRef.current)
    copiedTimerRef.current = setTimeout(() => setCopied(false), 2000)
  }, [code])

  return (
    <div data-testid={`totp-card-${entry.id}`} className={[
      'rounded-lg border border-border bg-card p-4 space-y-3',
      isPixel ? 'border-2 font-pixel' : '',
    ].join(' ')}>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <div className="font-medium truncate">
            {entry.issuer || entry.account_name}
          </div>
          {entry.issuer && entry.issuer !== entry.account_name && (
            <div className="text-xs text-muted-foreground truncate">{entry.account_name}</div>
          )}
          {entry.vault_entry_id && linkedTitle && (
            <div className="text-xs text-primary mt-0.5">{t('authenticator.linkedTo', { title: linkedTitle })}</div>
          )}
          {!entry.vault_entry_id && (
            <div className="text-xs text-muted-foreground mt-0.5">{t('authenticator.unlinked')}</div>
          )}
        </div>
        <button
          onClick={() => onDelete(entry.id)}
          className="rounded p-1.5 text-muted-foreground hover:bg-destructive hover:text-destructive-foreground shrink-0"
          title={t('authenticator.deleteConfirm')}
        >
          <Trash2 size={14} />
        </button>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative w-10 h-10 shrink-0">
          <svg viewBox="0 0 36 36" className="w-10 h-10 -rotate-90">
            <circle cx="18" cy="18" r="16" fill="none" stroke="currentColor" strokeWidth="2" className="text-muted/30" />
            <circle cx="18" cy="18" r="16" fill="none" stroke="currentColor" strokeWidth="2"
              strokeDasharray={`${progress * 100.5} 100.5`}
              className={secondsLeft <= 5 ? 'text-destructive' : 'text-primary'} />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center text-xs font-mono">
            {secondsLeft}
          </div>
        </div>

        <div className="flex-1 font-mono text-2xl tracking-widest select-all">
          <span className={secondsLeft <= 5 ? 'text-destructive animate-pulse' : ''}>
            {formattedCode}
          </span>
        </div>

        <button
          onClick={copy}
          className="rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground shrink-0"
          title={t('authenticator.copied') && !copied ? t('vault.copy') : t('authenticator.copied')}
        >
          <Copy size={16} />
        </button>
      </div>

      {copied && <div className="text-xs text-green-500">{t('authenticator.copied')}</div>}
    </div>
  )
}