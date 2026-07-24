import { Shield } from 'lucide-react'
import { Card, CardHeader, CardTitle } from '@/components/ui/Card'
import { useAuthStore } from '@/store/auth'

export function AboutSection() {
  const user = useAuthStore((s) => s.user)

  return (
    <Card>
      <CardHeader>
        <CardTitle>About</CardTitle>
      </CardHeader>
      <div className="p-5 space-y-4">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-900/30">
            <Shield className="h-6 w-6 text-emerald-400" />
          </div>
          <div>
            <p className="text-base font-semibold text-text-primary">KingSec</p>
            <p className="text-sm text-text-secondary">Security Assessment Platform</p>
          </div>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <div>
            <p className="text-xs text-text-muted">Version</p>
            <p className="text-sm font-medium text-text-primary">1.0.0</p>
          </div>
          <div>
            <p className="text-xs text-text-muted">Logged in as</p>
            <p className="text-sm font-medium text-text-primary">{user?.username ?? '-'}</p>
          </div>
        </div>
      </div>
    </Card>
  )
}
