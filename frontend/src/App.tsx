import { Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import { useEffect } from 'react'
import { useThemeStore } from '@/store/themeStore'
import Layout from '@/components/Layout'
import PrivateRoute from '@/components/PrivateRoute'
import ErrorBoundary from '@/components/ErrorBoundary'

const LoginPage = lazy(() => import('@/pages/LoginPage'))
const RegisterPage = lazy(() => import('@/pages/RegisterPage'))
const VaultPage = lazy(() => import('@/pages/VaultPage'))
const GeneratorPage = lazy(() => import('@/pages/GeneratorPage'))
const AuthenticatorPage = lazy(() => import('@/pages/AuthenticatorPage'))
const BreachPage = lazy(() => import('@/pages/BreachPage'))
const BackupPage = lazy(() => import('@/pages/BackupPage'))
const SettingsPage = lazy(() => import('@/pages/SettingsPage'))

function LoadingScreen() {
  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <div className="text-center">
        <div className="mb-4 h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
        <p className="text-sm text-muted-foreground">Loading...</p>
      </div>
    </div>
  )
}

function NotFoundPage() {
  return (
    <div className="flex h-screen items-center justify-center bg-background">
      <div className="text-center">
        <h1 className="text-4xl font-bold mb-2">404</h1>
        <p className="text-muted-foreground">Page not found</p>
      </div>
    </div>
  )
}

function App() {
  const { applyTheme } = useThemeStore()

  useEffect(() => {
    applyTheme()
  }, [applyTheme])

  return (
    <ErrorBoundary>
      <Suspense fallback={<LoadingScreen />}>
        <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/register" element={<RegisterPage />} />
        <Route element={<PrivateRoute />}>
          <Route element={<Layout />}>
            <Route path="/" element={<VaultPage />} />
            <Route path="/vault" element={<VaultPage />} />
            <Route path="/generator" element={<GeneratorPage />} />
            <Route path="/authenticator" element={<AuthenticatorPage />} />
            <Route path="/breach" element={<BreachPage />} />
            <Route path="/backup" element={<BackupPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Route>
        </Route>
        <Route path="*" element={<NotFoundPage />} />
      </Routes>
    </Suspense>
    </ErrorBoundary>
  )
}

export default App
