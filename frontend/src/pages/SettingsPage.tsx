import { useState } from 'react'
import { useAuthStore } from '@/store/authStore'
import { useThemeStore, themes } from '@/store/themeStore'
import { Palette, Globe, Clock, LogOut } from 'lucide-react'
import { useTranslation } from 'react-i18next'
import i18n from '@/i18n'

const themeGrid = [
  'midnight', 'light', 'nord', 'dracula',
  'solarized-dark', 'solarized-light', 'high-contrast', 'forest',
  'coral', 'amethyst', 'slate', 'obsidian',
  'pixel', 'custom',
]

export default function SettingsPage() {
  const { t } = useTranslation()
  const { logout, lockTimeoutMinutes, setLockTimeout } = useAuthStore()
  const {
    currentTheme,
    setTheme,
    crtEnabled,
    setCrtEnabled,
  } = useThemeStore()

  const [lang, setLang] = useState(i18n.language ?? 'en')

  const handleLangChange = (l: string) => {
    setLang(l)
    i18n.changeLanguage(l)
  }

  return (
    <div className="mx-auto max-w-lg space-y-6">
      <h2 className="text-xl font-semibold">{t('settings.title')}</h2>

      <div className="space-y-4 rounded-md border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <Palette size={18} className="text-primary" />
          <h3 className="font-medium">{t('settings.theme')}</h3>
        </div>
        <div className="grid grid-cols-3 gap-2 sm:grid-cols-4">
          {themeGrid.map((key) => (
            <button
              key={key}
              onClick={() => setTheme(key)}
              className={[
                'rounded-md border px-2 py-2 text-xs transition-colors',
                currentTheme === key
                  ? 'border-primary bg-primary text-primary-foreground'
                  : 'border-border bg-background text-muted-foreground hover:bg-accent hover:text-accent-foreground',
                key === 'pixel' ? 'border-2 border-purple-500 text-purple-400' : '',
                key === 'custom' ? 'border-dashed' : '',
              ].join(' ')}
            >
              {key === 'custom' ? t('settings.customTheme') : themes[key]?.name ?? key}
            </button>
          ))}
        </div>

        {currentTheme === 'pixel' && (
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={crtEnabled}
              onChange={(e) => setCrtEnabled(e.target.checked)}
              className="h-4 w-4 accent-primary"
            />
            {t('settings.crtEffect')}
          </label>
        )}
      </div>

      <div className="space-y-4 rounded-md border border-border bg-card p-4">
        <div className="flex items-center gap-2">
          <Globe size={18} className="text-primary" />
          <h3 className="font-medium">{t('settings.language')}</h3>
        </div>
        <div className="flex gap-2">
          {[
            { code: 'en', label: 'English' },
            { code: 'ru', label: 'Русский' },
          ].map(({ code, label }) => (
            <button
              key={code}
              data-testid={`lang-${code}`}
              onClick={() => handleLangChange(code)}
              className={[
                'rounded-md border px-3 py-1.5 text-sm transition-colors',
                lang === code
                  ? 'border-primary bg-primary text-primary-foreground'
                  : 'border-border bg-background text-muted-foreground hover:bg-accent',
              ].join(' ')}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      <div className="space-y-4 rounded-md border border-border bg-card p-4">
        <div className="flex items-center gap-3">
          <Clock size={18} className="text-primary" />
          <h3 className="font-medium">{t('settings.autoLock')}</h3>
          <label className="ml-auto flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={lockTimeoutMinutes > 0}
              onChange={(e) => setLockTimeout(e.target.checked ? 5 : 0)}
              className="h-4 w-4 accent-primary"
            />
            <span className="text-sm text-muted-foreground">
              {lockTimeoutMinutes > 0 ? t('settings.autoLockOn') : t('settings.autoLockOff')}
            </span>
          </label>
        </div>
        {lockTimeoutMinutes > 0 && (
          <div className="flex items-center gap-3">
            <input
              type="range"
              min={1}
              max={60}
              value={lockTimeoutMinutes}
              onChange={(e) => setLockTimeout(Number(e.target.value))}
              className="flex-1 accent-primary"
            />
            <span className="w-20 text-right text-sm">{lockTimeoutMinutes} {t('settings.autoLockMin')}</span>
          </div>
        )}
      </div>

      <button
        onClick={logout}
        className="flex w-full items-center justify-center gap-2 rounded-md border border-destructive bg-destructive/10 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive hover:text-destructive-foreground"
      >
        <LogOut size={16} /> {t('nav.logout')}
      </button>
    </div>
  )
}
