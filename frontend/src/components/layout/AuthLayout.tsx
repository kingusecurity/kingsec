import { Outlet } from 'react-router-dom'
import { Shield } from 'lucide-react'

export function AuthLayout() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center justify-center gap-2">
          <Shield className="h-8 w-8 text-emerald-500" />
          <span className="text-2xl font-bold">KingSec</span>
        </div>
        <Outlet />
      </div>
    </div>
  )
}
