import { Outlet } from 'react-router-dom'
import { useSessionActivity } from '@/hooks/useSessionActivity'
import Sidebar from '@/components/Sidebar'
import Header from '@/components/Header'

export default function Layout() {
  useSessionActivity()

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-foreground">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-auto p-4">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
