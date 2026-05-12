import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '@/api/client'
import type { VaultEntry, VaultListItem } from '@/types'
import EntryEditor from '@/components/vault/EntryEditor'
import { Search, Plus, Copy, Eye, EyeOff, Trash2, Pencil, AlertTriangle } from 'lucide-react'
import { useThemeStore } from '@/store/themeStore'

async function fetchEntries(): Promise<VaultListItem[]> {
  const res = await api.get('/entries/')
  return res.data
}

async function fetchEntry(id: number): Promise<VaultEntry> {
  const res = await api.get(`/entries/${id}`)
  return res.data
}

export default function VaultPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const generatedPassword = (location.state as { generatedPassword?: string } | null)?.generatedPassword
  const [search, setSearch] = useState('')
  const [revealed, setRevealed] = useState<Set<number>>(new Set())
  const [loadingReveal, setLoadingReveal] = useState<Set<number>>(new Set())
  const [detailCache, setDetailCache] = useState<Record<number, VaultEntry>>({})
  const [editingEntry, setEditingEntry] = useState<VaultEntry | null>(null)
  const [showEditor, setShowEditor] = useState(!!generatedPassword)
  const [prefillPassword, setPrefillPassword] = useState(generatedPassword ?? '')

  useEffect(() => {
    return () => {
      setDetailCache({})
    }
  }, [])

  useEffect(() => {
    if (generatedPassword) {
      navigate('/vault', { replace: true, state: {} })
    }
  }, [generatedPassword, navigate])
  const [deleteConfirm, setDeleteConfirm] = useState<VaultListItem | null>(null)
  const isPixel = useThemeStore((s) => s.currentTheme) === 'pixel'
  const { t } = useTranslation()
  const queryClient = useQueryClient()

  const { data: entries = [], isLoading } = useQuery({
    queryKey: ['entries'],
    queryFn: fetchEntries,
  })

  const deleteMutation = useMutation({
    mutationFn: async (id: number) => {
      await api.delete(`/entries/${id}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['entries'] })
      setDeleteConfirm(null)
    },
  })

  const filtered = entries.filter((e) =>
    (e.title ?? '').toLowerCase().includes(search.toLowerCase())
  )

  const loadDetail = async (id: number): Promise<VaultEntry | undefined> => {
    if (detailCache[id]) return detailCache[id]
    try {
      const entry = await fetchEntry(id)
      setDetailCache((prev) => ({ ...prev, [id]: entry }))
      return entry
    } catch {
      return undefined
    }
  }

  const toggleReveal = async (id: number) => {
    if (loadingReveal.has(id)) return
    if (!revealed.has(id)) {
      setLoadingReveal((prev) => new Set(prev).add(id))
      const entry = await loadDetail(id)
      setLoadingReveal((prev) => {
        const next = new Set(prev)
        next.delete(id)
        return next
      })
      if (!entry) return
    } else {
      setDetailCache((prev) => {
        const next = { ...prev }
        if (next[id]) {
          next[id] = { ...next[id], password: '' }
        }
        return next
      })
    }
    setRevealed((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const copyToClipboard = async (id: number) => {
    const entry = await loadDetail(id)
    if (entry?.password) {
      await navigator.clipboard.writeText(entry.password)
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000)
    }
  }

  const handleEdit = async (item: VaultListItem) => {
    const entry = await loadDetail(item.id)
    if (entry) {
      setEditingEntry(entry)
      setShowEditor(true)
    }
  }

  const handleAdd = () => {
    setEditingEntry(null)
    setPrefillPassword('')
    setShowEditor(true)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">{t('vault.title')}</h2>
        <button
          data-testid="vault-add-btn"
          onClick={handleAdd}
          className={[
            'flex items-center gap-1 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90',
            isPixel ? 'rounded-none border-2 border-primary bg-transparent' : '',
          ].join(' ')}
        >
          <Plus size={16} /> {t('vault.addEntry')}
        </button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={16} />
        <input
          data-testid="vault-search"
          type="text"
          placeholder={t('vault.search')}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className={[
            'w-full rounded-md border border-input bg-background py-2 pl-9 pr-3 text-sm outline-none ring-offset-background focus:ring-2 focus:ring-ring',
            isPixel ? 'rounded-none border-2' : '',
          ].join(' ')}
        />
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-12 animate-pulse rounded-md bg-muted" />
          ))}
        </div>
      ) : filtered.length === 0 ? (
        <div data-testid="vault-empty" className={[
          'rounded-md border border-dashed border-border p-8 text-center text-sm text-muted-foreground',
          isPixel ? 'border-2' : '',
        ].join(' ')}>
          {t('vault.noEntries')}
        </div>
      ) : (
        <div data-testid="vault-list" className={[
          'divide-y divide-border rounded-md border border-border',
          isPixel ? 'border-2' : '',
        ].join(' ')}>
          {filtered.map((entry) => (
            <div key={entry.id} data-testid={`vault-entry-${entry.id}`} className="flex items-center gap-3 px-4 py-3 hover:bg-muted/50 transition-colors">
              <div className="flex-1 min-w-0 space-y-0.5">
                <div className="truncate text-sm font-medium">{entry.title}</div>
                <div className="text-xs text-muted-foreground font-mono">
                  {revealed.has(entry.id)
                    ? (detailCache[entry.id]?.password ?? t('vault.passwordMask'))
                    : t('vault.passwordMask')}
                </div>
              </div>

              <div className="flex items-center gap-0.5 shrink-0">
                <button
                  data-testid="vault-reveal-btn"
                  onClick={() => toggleReveal(entry.id)}
                  className="rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  title={t('vault.reveal')}
                >
                  {revealed.has(entry.id) ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <button
                  onClick={() => copyToClipboard(entry.id)}
                  className="rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  title={t('vault.copy')}
                >
                  <Copy size={14} />
                </button>
                <button
                  data-testid="vault-edit-btn"
                  onClick={() => handleEdit(entry)}
                  className="rounded p-1.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
                  title={t('vault.edit')}
                >
                  <Pencil size={14} />
                </button>
                <button
                  data-testid="vault-delete-btn"
                  onClick={() => setDeleteConfirm(entry)}
                  className="rounded p-1.5 text-muted-foreground hover:bg-destructive hover:text-destructive-foreground"
                  title={t('vault.delete')}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {showEditor && (
        <EntryEditor
          entry={editingEntry}
          prefillPassword={editingEntry ? undefined : prefillPassword}
          onClose={() => setShowEditor(false)}
          onSaved={() => {
            queryClient.invalidateQueries({ queryKey: ['entries'] })
            setDetailCache({})
          }}
        />
      )}

      {deleteConfirm && (
        <div data-testid="vault-delete-dialog" className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm p-4">
          <div className={[
            'w-full max-w-sm rounded-lg border border-border bg-card p-6 shadow-lg',
            isPixel ? 'border-4 border-destructive font-pixel' : '',
          ].join(' ')}>
            <div className="flex items-center gap-2 text-destructive mb-3">
              <AlertTriangle size={20} />
              <h3 className="font-semibold">{t('vault.deleteConfirm')}</h3>
            </div>
            <p className="text-sm text-muted-foreground mb-4">
              {t('vault.deleteWarning', { title: deleteConfirm.title })}
            </p>
            <div className="flex gap-2">
              <button
                onClick={() => setDeleteConfirm(null)}
                className="flex-1 rounded-md border border-border bg-background px-4 py-2 text-sm hover:bg-accent"
              >
                {t('vault.cancel')}
              </button>
              <button
                onClick={() => deleteMutation.mutate(deleteConfirm.id)}
                disabled={deleteMutation.isPending}
                className={[
                  'flex-1 rounded-md bg-destructive px-4 py-2 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50',
                  isPixel ? 'rounded-none' : '',
                ].join(' ')}
              >
                {deleteMutation.isPending ? t('common.deleting') : t('vault.delete')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
