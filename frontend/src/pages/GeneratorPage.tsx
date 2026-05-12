import { useState, useRef, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { useNavigate } from 'react-router-dom'
import { Copy, RefreshCw, Save } from 'lucide-react'
import { secureRandomPassword } from '@/utils/random'

export default function GeneratorPage() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const [length, setLength] = useState(16)
  const [useUpper, setUseUpper] = useState(true)
  const [useDigits, setUseDigits] = useState(true)
  const [useSpecial, setUseSpecial] = useState(true)
  const [password, setPassword] = useState('')
  const [copied, setCopied] = useState(false)
  const copiedTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    return () => {
      if (copiedTimerRef.current) clearTimeout(copiedTimerRef.current)
    }
  }, [])

  const chars = [
    'abcdefghijklmnopqrstuvwxyz',
    useUpper ? 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' : '',
    useDigits ? '0123456789' : '',
    useSpecial ? '!@#$%^&*()_+-=[]{}|;:,.<>?' : '',
  ].join('')

  const generate = () => {
    setPassword(secureRandomPassword(length, chars))
    setCopied(false)
  }

  const entropy = Math.log2(chars.length ** length)
  const copy = () => {
    navigator.clipboard.writeText(password).then(() => {
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000)
    })
    setCopied(true)
    if (copiedTimerRef.current) clearTimeout(copiedTimerRef.current)
    copiedTimerRef.current = setTimeout(() => setCopied(false), 2000)
  }

  const handleSaveToVault = () => {
    navigate('/vault', { state: { generatedPassword: password } })
  }

  return (
    <div className="mx-auto max-w-md space-y-6">
      <h2 className="text-xl font-semibold">{t('generator.title')}</h2>

      <div className="space-y-4 rounded-md border border-border bg-card p-4">
        <div className="flex items-center gap-2 rounded-md border border-input bg-background p-3">
          <code data-testid="generator-output" className="flex-1 break-all text-sm">{password || t('generator.clickGenerate')}</code>
          <button
            onClick={copy}
            disabled={!password}
            className="rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground disabled:opacity-30"
          >
            <Copy size={16} />
          </button>
        </div>
        {copied && <div data-testid="generator-copied" className="text-xs text-green-500">{t('generator.copied')}</div>}

        <div className="space-y-1">
          <div className="flex items-center justify-between text-sm">
            <span>{t('generator.length')}: {length}</span>
            <span className="text-xs text-muted-foreground">{Math.round(entropy)} {t('generator.entropy')}</span>
          </div>
          <input
            type="range"
            min={8}
            max={128}
            value={length}
            onChange={(e) => setLength(Number(e.target.value))}
            className="w-full accent-primary"
          />
        </div>

        <div className="space-y-2">
          {[
            { label: t('generator.uppercase'), checked: useUpper, set: setUseUpper },
            { label: t('generator.digits'), checked: useDigits, set: setUseDigits },
            { label: t('generator.special'), checked: useSpecial, set: setUseSpecial },
          ].map(({ label, checked, set }) => (
            <label key={label} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={checked}
                onChange={(e) => set(e.target.checked)}
                className="h-4 w-4 rounded border-border accent-primary"
              />
              {label}
            </label>
          ))}
        </div>

        <button
          data-testid="generator-generate-btn"
          onClick={generate}
          className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
        >
          <RefreshCw size={16} /> {t('generator.generate')}
        </button>

        {password && (
          <button
            data-testid="generator-save-to-vault-btn"
            onClick={handleSaveToVault}
            className="flex w-full items-center justify-center gap-2 rounded-md border border-primary bg-background px-4 py-2 text-sm font-medium text-primary hover:bg-primary/10"
          >
            <Save size={16} /> {t('generator.saveToVault')}
          </button>
        )}
      </div>
    </div>
  )
}