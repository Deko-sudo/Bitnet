import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import { api } from '@/api/client'
import type { TotpSetupResponse, VaultListItem } from '@/types'
import { X, QrCode, Key } from 'lucide-react'
import { useThemeStore } from '@/store/themeStore'
import { useQuery } from '@tanstack/react-query'

interface TotpSetupProps {
  onClose: () => void
  onVerified: () => void
}

export default function TotpSetup({ onClose, onVerified }: TotpSetupProps) {
  const { t } = useTranslation()
  const isPixel = useThemeStore((s) => s.currentTheme) === 'pixel'
  const [mode, setMode] = useState<'choose' | 'manual' | 'link' | 'paste'>('choose')
  const [issuer, setIssuer] = useState('')
  const [accountName, setAccountName] = useState('')
  const [secretKey, setSecretKey] = useState('')
  const [digits, setDigits] = useState(6)
  const [period, setPeriod] = useState(30)
  const [vaultEntryId, setVaultEntryId] = useState<number | null>(null)
  const [setupData, setSetupData] = useState<TotpSetupResponse | null>(null)
  const [verifyCode, setVerifyCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    return () => {
      setSecretKey('')
      setVerifyCode('')
    }
  }, [])

  const { data: entries = [] } = useQuery({
    queryKey: ['entries'],
    queryFn: async () => {
      const res = await api.get('/entries/')
      return res.data as VaultListItem[]
    },
  })

  const handleSetup = async () => {
    setLoading(true)
    setError('')
    try {
      const payload: Record<string, unknown> = {
        digits,
        period,
        vault_entry_id: vaultEntryId,
      }
      if (mode === 'paste' && secretKey.trim()) {
        payload.secret = secretKey.trim().replace(/\s/g, '')
        payload.issuer = issuer || null
        payload.account_name = accountName || secretKey.trim().slice(0, 8)
      } else if (mode === 'link') {
        if (!vaultEntryId) {
          setError(t('authenticator.selectLogin'))
          setLoading(false)
          return
        }
        const linkedEntry = entries.find((e) => e.id === vaultEntryId)
        payload.issuer = issuer || null
        payload.account_name = accountName || linkedEntry?.title || ''
      } else {
        if (!accountName.trim()) {
          setError(t('authenticator.accountName'))
          setLoading(false)
          return
        }
        payload.issuer = issuer || null
        payload.account_name = accountName
      }
      const res = await api.post('/totp/setup', payload)
      setSetupData(res.data)
    } catch (err: any) {
      setError(err.response?.data?.detail || t('common.saveError'))
    } finally {
      setLoading(false)
    }
  }

  const handleVerify = async () => {
    if (!setupData || !verifyCode.trim()) return
    setLoading(true)
    setError('')
    try {
      await api.post(`/totp/${setupData.id}/verify`, { code: verifyCode.trim() })
      onVerified()
      onClose()
    } catch (err: any) {
      setError(err.response?.data?.detail || t('authenticator.invalidCode'))
    } finally {
      setLoading(false)
    }
  }

  const renderForm = () => (
    <div className="space-y-4">
      {mode === 'choose' ? (
        <div className="space-y-3">
          <button
            onClick={() => setMode('paste')}
            className="w-full rounded-md border border-border bg-background px-4 py-3 text-sm text-left hover:bg-accent"
          >
            <div className="font-medium">{t('authenticator.pasteKey')}</div>
            <div className="text-xs text-muted-foreground mt-0.5">{t('authenticator.secretKey')}</div>
          </button>
          <button
            onClick={() => setMode('manual')}
            className="w-full rounded-md border border-border bg-background px-4 py-3 text-sm text-left hover:bg-accent"
          >
            {t('authenticator.enterManually')}
          </button>
          <button
            onClick={() => setMode('link')}
            className="w-full rounded-md border border-border bg-background px-4 py-3 text-sm text-left hover:bg-accent"
          >
            {t('authenticator.linkToLogin')}
          </button>
        </div>
      ) : (
        <>
          {mode === 'paste' && (
            <div className="space-y-3">
              <div className="space-y-1">
                <label className="text-sm font-medium">{t('authenticator.secretKey')} *</label>
                <input
                  type="text"
                  value={secretKey}
                  onChange={(e) => setSecretKey(e.target.value)}
                  placeholder={t('authenticator.secretKeyPlaceholder')}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm font-mono"
                  autoFocus
                />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium">{t('authenticator.issuer')}</label>
                <input
                  type="text"
                  value={issuer}
                  onChange={(e) => setIssuer(e.target.value)}
                  placeholder="Google, GitHub..."
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium">{t('authenticator.accountName')}</label>
                <input
                  type="text"
                  value={accountName}
                  onChange={(e) => setAccountName(e.target.value)}
                  placeholder={t('authenticator.standaloneKey')}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
            </div>
          )}

          {mode === 'manual' && (
            <>
              <div className="space-y-1">
                <label className="text-sm font-medium">{t('authenticator.issuer')}</label>
                <input
                  type="text"
                  value={issuer}
                  onChange={(e) => setIssuer(e.target.value)}
                  placeholder="Google, GitHub..."
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium">{t('authenticator.accountName')} *</label>
                <input
                  type="text"
                  value={accountName}
                  onChange={(e) => setAccountName(e.target.value)}
                  placeholder="user@example.com"
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </div>
            </>
          )}

          {mode === 'link' && (
            <div className="space-y-1">
              <label className="text-sm font-medium">{t('authenticator.selectLogin')}</label>
              <select
                value={vaultEntryId ?? ''}
                onChange={(e) => setVaultEntryId(e.target.value ? Number(e.target.value) : null)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value="">{t('authenticator.standaloneKey')}</option>
                {entries.map((e) => (
                  <option key={e.id} value={e.id}>{e.title}</option>
                ))}
              </select>
            </div>
          )}

          <div className="flex gap-4">
            <div className="space-y-1 flex-1">
              <label className="text-sm font-medium">{t('authenticator.digits')}</label>
              <select
                value={digits}
                onChange={(e) => setDigits(Number(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value={6}>6</option>
                <option value={8}>8</option>
              </select>
            </div>
            <div className="space-y-1 flex-1">
              <label className="text-sm font-medium">{t('authenticator.period')} (s)</label>
              <select
                value={period}
                onChange={(e) => setPeriod(Number(e.target.value))}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              >
                <option value={30}>30</option>
                <option value={60}>60</option>
              </select>
            </div>
          </div>

          <div className="flex gap-2">
            <button
              onClick={() => { setMode('choose'); setError('') }}
              className="flex-1 rounded-md border border-border bg-background px-4 py-2 text-sm hover:bg-accent"
            >
              {t('vault.cancel')}
            </button>
            <button
              onClick={handleSetup}
              disabled={loading || (mode === 'paste' ? !secretKey.trim() : mode === 'link' ? !vaultEntryId : !accountName.trim())}
              className="flex-1 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {loading ? t('authenticator.generating') : mode === 'paste' ? <><Key size={16} className="inline mr-1" /> {t('authenticator.addKey')}</> : <><QrCode size={16} className="inline mr-1" /> {t('authenticator.addKey')}</>}
            </button>
          </div>
        </>
      )}
    </div>
  )

  const renderVerify = () => (
    <div className="space-y-4">
      {setupData?.qr_code_base64 && mode !== 'paste' ? (
        <>
          <div className="flex justify-center">
            <img
              src={`data:image/png;base64,${setupData.qr_code_base64}`}
              alt="QR Code"
              className="w-48 h-48 rounded-md border border-border"
            />
          </div>
          <p className="text-sm text-muted-foreground text-center">{t('authenticator.scanQr')}</p>
        </>
      ) : (
        <p className="text-sm text-muted-foreground text-center">{t('authenticator.verifyCode')}</p>
      )}

      <div className="space-y-1">
        <label className="text-sm font-medium">{t('authenticator.verifyCode')}</label>
        <input
          type="text"
          value={verifyCode}
          onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, digits))}
          placeholder={digits === 6 ? '000000' : '00000000'}
          maxLength={digits}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-center text-lg tracking-widest font-mono"
          autoFocus
        />
      </div>

      <button
        onClick={handleVerify}
        disabled={loading || verifyCode.length !== digits}
        className="w-full rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {loading ? t('authenticator.verifying') : t('authenticator.verify')}
      </button>
    </div>
  )

  return (
    <div data-testid="totp-setup" className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
      <div className={[
        'w-full max-w-md max-h-[90vh] overflow-y-auto rounded-lg border border-border bg-card p-6 shadow-lg',
        isPixel ? 'border-4 border-primary font-pixel' : '',
      ].join(' ')}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">{t('authenticator.setupTitle')}</h2>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-accent">
            <X size={18} />
          </button>
        </div>

        {error && (
          <div className="mb-4 rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">{error}</div>
        )}

        {!setupData && renderForm()}
        {setupData && renderVerify()}
      </div>
    </div>
  )
}