import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/api/client'
import type { TotpCodeResponse, VaultListItem } from '@/types'
import TotpCard from '@/components/authenticator/TotpCard'
import TotpSetup from '@/components/authenticator/TotpSetup'
import { Plus, ShieldCheck, AlertTriangle } from 'lucide-react'
import { useThemeStore } from '@/store/themeStore'

export default function AuthenticatorPage() {
  const { t } = useTranslation()
  const isPixel = useThemeStore((s) => s.currentTheme) === 'pixel'
  const queryClient = useQueryClient()
  const [showSetup, setShowSetup] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null)
  const [keepOrDelete, setKeepOrDelete] = useState<{ totpId: number; entryTitle: string } | null>(null)

  const { data: totpEntries = [], isLoading } = useQuery({
    queryKey: ['totp'],
    queryFn: async () => {
      const res = await api.get('/totp/')
      return res.data as TotpCodeResponse[]
    },
    refetchInterval: 5000,
  })

  const { data: vaultEntries = [] } = useQuery({
    queryKey: ['entries'],
    queryFn: async () => {
      const res = await api.get('/entries/')
      return res.data as VaultListItem[]
    },
  })

  const [deleteError, setDeleteError] = useState('')

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      await api.delete(`/totp/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['totp'] })
      setDeleteConfirm(null)
      setKeepOrDelete(null)
      setDeleteError('')
    },
    onError: () => {
      setDeleteError(t('common.saveError'))
    },
  })

  const getLinkedTitle = (vaultEntryId: number | null) => {
    if (!vaultEntryId) return null
    return vaultEntries.find((e) => e.id === vaultEntryId)?.title ?? null
  }

  const handleDelete = (id: number) => {
    const entry = totpEntries.find((e) => e.id === id)
    if (entry?.vault_entry_id) {
      setKeepOrDelete({ totpId: id, entryTitle: getLinkedTitle(entry.vault_entry_id) || '' })
    } else {
      setDeleteConfirm(id)
    }
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">{t('authenticator.title')}</h2>
        <button
          data-testid="totp-add-btn"
          onClick={() => setShowSetup(true)}
          className={[
            'flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90',
            isPixel ? 'rounded-none border-2 border-primary bg-transparent' : '',
          ].join(' ')}
        >
          <Plus size={16} /> {t('authenticator.addKey')}
        </button>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[1, 2].map((i) => (
            <div key={i} className="h-24 animate-pulse rounded-md bg-muted" />
          ))}
        </div>
      ) : totpEntries.length === 0 ? (
        <div className={[
          'rounded-md border border-dashed border-border p-8 text-center text-sm text-muted-foreground',
          isPixel ? 'border-2' : '',
        ].join(' ')}>
          <ShieldCheck size={32} className="mx-auto mb-2 text-muted-foreground" />
          {t('authenticator.noKeys')}
        </div>
      ) : (
        <div className="space-y-3">
          {totpEntries.map((entry) => (
            <TotpCard
              key={entry.id}
              entry={entry}
              linkedTitle={getLinkedTitle(entry.vault_entry_id)}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}

      {showSetup && (
        <TotpSetup
          onClose={() => setShowSetup(false)}
          onVerified={() => {
            queryClient.invalidateQueries({ queryKey: ['totp'] })
          }}
        />
      )}

      {deleteConfirm !== null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className={[
            'w-full max-w-sm rounded-lg border border-border bg-card p-6 shadow-lg',
            isPixel ? 'border-4 border-destructive font-pixel' : '',
          ].join(' ')}>
            <div className="flex items-center gap-2 text-destructive mb-3">
              <AlertTriangle size={20} />
              <h3 className="font-semibold">{t('authenticator.deleteConfirm')}</h3>
            </div>
            <p className="text-sm text-muted-foreground mb-4">
              {t('authenticator.deleteWarning', { issuer: totpEntries.find((e) => e.id === deleteConfirm)?.issuer || '—' })}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="flex-1 rounded-md border border-border bg-background px-4 py-2 text-sm hover:bg-accent"
              >
                {t('vault.cancel')}
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm)}
                disabled={deleteMutation.isPending}
                className="flex-1 rounded-md bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {t('vault.delete')}
              </button>
            </div>
            {deleteError && (
              <div className="mt-2 rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">
                {deleteError}
              </div>
            )}
          </div>
        </div>
      )}

      {keepOrDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className={[
            'w-full max-w-sm rounded-lg border border-border bg-card p-6 shadow-lg',
            isPixel ? 'border-4 border-primary font-pixel' : '',
          ].join(' ')}>
            <h3 className="font-semibold mb-3">{t('authenticator.keepOrDelete')}</h3>
            <p className="text-sm text-muted-foreground mb-4">
              {t('authenticator.linkedTo', { title: keepOrDelete.entryTitle })}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setKeepOrDelete(null)}
                className="flex-1 rounded-md border border-border bg-background px-4 py-2 text-sm hover:bg-accent"
              >
                {t('authenticator.keepKey')}
              </button>
              <button
                onClick={() => {
                  deleteMutation.mutate(keepOrDelete.totpId)
                }}
                disabled={deleteMutation.isPending}
                className="flex-1 rounded-md bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
              >
                {t('authenticator.deleteKey')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}