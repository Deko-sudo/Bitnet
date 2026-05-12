import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api } from '@/api/client'
import { Download, Upload, AlertTriangle } from 'lucide-react'

interface BackupInfo {
  name: string
  created_at: string
  size_bytes?: number
}

export default function BackupPage() {
  const queryClient = useQueryClient()
  const [importError, setImportError] = useState('')
  const { t } = useTranslation()

  const { data: backups = [] } = useQuery({
    queryKey: ['backups'],
    queryFn: async () => {
      const res = await api.get('/backups/')
      return res.data as BackupInfo[]
    },
  })

  const [exportError, setExportError] = useState('')

  const exportCsv = async () => {
    try {
      setExportError('')
      const res = await api.get('/portability/export/csv', { responseType: 'blob' })
      downloadBlob(res.data, 'bitnet-export.csv', 'text/csv')
    } catch {
      setExportError(t('common.saveError'))
    }
  }

  const exportJson = async () => {
    try {
      setExportError('')
      const res = await api.get('/portability/export/jsonl', { responseType: 'blob' })
      downloadBlob(res.data, 'bitnet-export.jsonl', 'application/x-ndjson')
    } catch {
      setExportError(t('common.saveError'))
    }
  }

  const createBackup = useMutation({
    mutationFn: async () => {
      await api.post('/backups/')
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['backups'] })
    },
  })

  const handleFileImport = async (file: File, type: 'csv' | 'jsonl') => {
    setImportError('')
    const formData = new FormData()
    formData.append('file', file)
    try {
      const endpoint = type === 'csv' ? '/portability/import/csv' : '/portability/import/jsonl'
      await api.post(endpoint, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      queryClient.invalidateQueries({ queryKey: ['entries'] })
    } catch (err: any) {
      setImportError(err.response?.data?.detail ?? 'Import failed')
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    const file = e.dataTransfer.files[0]
    if (!file) return
    const ext = file.name.split('.').pop()?.toLowerCase()
    const type = ext === 'csv' ? 'csv' : 'jsonl'
    handleFileImport(file, type)
  }

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const ext = file.name.split('.').pop()?.toLowerCase()
    const type = ext === 'csv' ? 'csv' : 'jsonl'
    handleFileImport(file, type)
  }

  function downloadBlob(data: Blob, filename: string, _mimeType: string) {
    const url = URL.createObjectURL(data)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    setTimeout(() => URL.revokeObjectURL(url), 5000)
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <h2 className="text-xl font-semibold">{t('backup.title')}</h2>

      <div className="space-y-4 rounded-md border border-border bg-card p-4">
        <h3 className="text-sm font-medium">{t('backup.export')}</h3>
        <div className="flex gap-2">
          <button
            onClick={() => exportCsv()}
            className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm hover:bg-accent"
          >
            <Download size={14} /> {t('backup.csv')}
          </button>
          <button
            onClick={() => exportJson()}
            className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm hover:bg-accent"
          >
            <Download size={14} /> {t('backup.json')}
          </button>
          <button
            onClick={() => createBackup.mutate()}
            disabled={createBackup.isPending}
            className="flex items-center gap-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm hover:bg-accent disabled:opacity-50"
          >
            <Download size={14} /> {t('backup.encrypted')}
          </button>
        </div>
      </div>

      <div className="space-y-4 rounded-md border border-border bg-card p-4">
        <h3 className="text-sm font-medium">{t('backup.import')}</h3>
        <div
          onDrop={handleDrop}
          onDragOver={(e) => e.preventDefault()}
          onClick={() => document.getElementById('backup-file-input')?.click()}
          className="cursor-pointer rounded-md border border-dashed border-border p-6 text-center hover:bg-accent/50"
        >
          <Upload size={24} className="mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm text-muted-foreground">{t('backup.dragDrop')}</p>
          <input
            id="backup-file-input"
            type="file"
            accept=".csv,.jsonl,.json"
            onChange={handleFileInput}
            className="hidden"
          />
        </div>
        {importError && (
          <div className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {importError}
          </div>
        )}
        {exportError && (
          <div className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">
            {exportError}
          </div>
        )}
        <div className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/5 p-3 text-xs text-destructive">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          <span>{t('backup.restoreWarning')}</span>
        </div>
      </div>

      {backups.length > 0 && (
        <div className="space-y-4 rounded-md border border-border bg-card p-4">
          <h3 className="text-sm font-medium">{t('backup.history')}</h3>
          <div className="space-y-2">
            {backups.map((b) => (
              <div key={b.name} className="flex items-center justify-between rounded-md border border-border px-3 py-2 text-sm">
                <span className="truncate">{b.name}</span>
                <span className="text-xs text-muted-foreground">{new Date(b.created_at).toLocaleDateString()}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}