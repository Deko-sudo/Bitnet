import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { api } from '@/api/client'
import { ShieldCheck, ShieldAlert, ShieldX, CheckCircle } from 'lucide-react'

interface BreachAlert {
  id: string
  alert_type: string
  value_preview: string
  breach_count: number
  severity: string
  status: string
  detected_at: string
  details?: string
}

interface MonitoredItem {
  id: string
  item_type: string
  is_active: boolean
  last_checked?: string
  check_count: number
}

export default function BreachPage() {
  const queryClient = useQueryClient()
  const { t } = useTranslation()
  const [ackError, setAckError] = useState('')

  const { data: alerts = [], isLoading: alertsLoading } = useQuery({
    queryKey: ['breach-alerts'],
    queryFn: async () => {
      const res = await api.get('/breach/alerts/')
      return res.data as BreachAlert[]
    },
  })

  const { data: monitored = [], isLoading: monitoredLoading } = useQuery({
    queryKey: ['breach-monitored'],
    queryFn: async () => {
      const res = await api.get('/breach/monitored/')
      return res.data as MonitoredItem[]
    },
  })

  const ackMutation = useMutation({
    mutationFn: async (alertId: string) => {
      await api.patch(`/breach/alerts/${alertId}/acknowledge`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['breach-alerts'] })
    },
    onError: () => {
      setAckError(t('common.saveError'))
    },
  })

  const activeAlerts = alerts.filter((a) => a.status === 'new')
  const acknowledged = alerts.filter((a) => a.status === 'acknowledged')

  const loading = alertsLoading || monitoredLoading

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">{t('breach.title')}</h2>

      <div className="grid gap-4 md:grid-cols-3">
        {[
          { label: t('breach.monitored'), value: monitored.length, icon: ShieldCheck, color: 'text-primary' },
          { label: t('breach.alerts'), value: activeAlerts.length, icon: ShieldAlert, color: 'text-destructive' },
          { label: t('breach.acknowledged'), value: acknowledged.length, icon: ShieldX, color: 'text-muted-foreground' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-md border border-border bg-card p-4">
            <div className="flex items-center gap-2">
              <Icon className={color} size={20} />
              <span className="text-sm text-muted-foreground">{label}</span>
            </div>
            <div className="mt-1 text-2xl font-bold">{value}</div>
          </div>
        ))}
      </div>

      {loading ? (
        <div className="space-y-2">
          {[1, 2, 3].map((i) => (
            <div key={i} className="h-16 animate-pulse rounded-md bg-muted" />
          ))}
        </div>
      ) : activeAlerts.length > 0 ? (
        <div className="space-y-2">
          {activeAlerts.map((alert) => (
            <div key={alert.id} className="flex items-center justify-between rounded-md border border-destructive/50 bg-destructive/5 p-3">
              <div className="space-y-0.5">
                <div className="text-sm font-medium">{alert.alert_type} — {alert.value_preview}</div>
                <div className="text-xs text-muted-foreground">
                  {t('breach.severity')}: {alert.severity} | {t('breach.breachCount')}: {alert.breach_count} | {new Date(alert.detected_at).toLocaleDateString()}
                </div>
              </div>
              <button
                onClick={() => ackMutation.mutate(alert.id)}
                disabled={ackMutation.isPending}
                className="flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:opacity-50"
              >
                <CheckCircle size={12} /> {t('breach.acknowledge')}
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="rounded-md border border-dashed border-border p-8 text-center text-sm text-muted-foreground">
          {t('breach.noAlerts')}
        </div>
      )}
      {ackError && (
        <div className="rounded-md border border-destructive bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {ackError}
        </div>
      )}
    </div>
  )
}