import { NavLink } from 'react-router-dom'
import { useTranslation } from 'react-i18next'
import { useThemeStore } from '@/store/themeStore'
import { Shield, KeyRound, ShieldCheck, Fingerprint, Database, Wrench, LogOut } from 'lucide-react'
import { useAuthStore } from '@/store/authStore'

const navKeys = [
  { to: '/vault', icon: Shield, key: 'vault' },
  { to: '/generator', icon: KeyRound, key: 'generator' },
  { to: '/authenticator', icon: ShieldCheck, key: 'authenticator' },
  { to: '/breach', icon: Fingerprint, key: 'breach' },
  { to: '/backup', icon: Database, key: 'backup' },
  { to: '/settings', icon: Wrench, key: 'settings' },
] as const

export default function Sidebar() {
  const { currentTheme } = useThemeStore()
  const { t } = useTranslation()
  const logout = useAuthStore((s) => s.logout)
  const isPixel = currentTheme === 'pixel'

  return (
    <nav
      className={[
        'flex w-16 flex-col items-center gap-2 border-r border-border bg-card py-4',
        isPixel ? 'border-2 border-primary' : '',
      ].join(' ')}
      aria-label="Main navigation"
    >
      <div className="mb-4 text-lg font-bold text-primary">B</div>

      {navKeys.map(({ to, icon: Icon, key }) => (
        <NavLink
          key={to}
          to={to}
          className={({ isActive }) =>
            [
              'flex h-10 w-10 items-center justify-center rounded-md transition-colors',
              isActive
                ? 'bg-primary text-primary-foreground'
                : 'text-muted-foreground hover:bg-accent hover:text-accent-foreground',
              isPixel ? 'rounded-none border border-primary' : '',
            ].join(' ')
          }
          title={t(`nav.${key}`)}
          data-testid={`nav-${key}`}
        >
          <Icon size={20} />
        </NavLink>
      ))}

      <div className="mt-auto">
        <button
          onClick={logout}
          className={[
            'flex h-10 w-10 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-destructive hover:text-destructive-foreground',
            isPixel ? 'rounded-none border border-destructive' : '',
          ].join(' ')}
          data-testid="nav-logout"
          title={t('nav.logout')}
        >
          <LogOut size={20} />
        </button>
      </div>
    </nav>
  )
}
