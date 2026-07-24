import { useNavigate } from 'react-router-dom'
import { ShieldOff, ArrowLeft } from 'lucide-react'
import { Button, Badge } from '@/components/ui'
import { useAuthStore } from '@/store/auth'

export function UnauthorizedPage() {
  const user = useAuthStore((s) => s.user)
  const navigate = useNavigate()

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-8">
      <div className="flex max-w-md flex-col items-center gap-6 text-center">
        <div className="flex h-24 w-24 items-center justify-center rounded-full bg-yellow-900/30">
          <ShieldOff className="h-12 w-12 text-yellow-400" />
        </div>
        <h1 className="text-2xl font-bold text-text-primary">Access Denied</h1>
        <p className="text-sm text-text-secondary">
          You do not have permission to access this section. Your current role does not meet the required access level.
        </p>
        {user && (
          <div className="flex items-center gap-2 text-sm text-text-secondary">
            <span>Your role:</span>
            <Badge variant="info">{user.role}</Badge>
          </div>
        )}
        <div className="flex gap-3">
          <Button variant="outline" iconLeft={<ArrowLeft className="h-4 w-4" />} onClick={() => navigate('/dashboard')}>
            Return to Dashboard
          </Button>
        </div>
      </div>
    </div>
  )
}
