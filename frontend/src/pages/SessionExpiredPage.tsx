import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { LogIn, Clock } from 'lucide-react'
import { Button } from '@/components/ui'
import { useAuthStore } from '@/store/auth'
import { clearTokens } from '@/api/client'

export function SessionExpiredPage() {
  const clearUser = useAuthStore((s) => s.clearUser)
  const navigate = useNavigate()

  useEffect(() => {
    clearTokens()
    clearUser()
  }, [clearUser])

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-8">
      <div className="flex max-w-md flex-col items-center gap-6 text-center">
        <div className="flex h-24 w-24 items-center justify-center rounded-full bg-blue-900/30">
          <Clock className="h-12 w-12 text-blue-400" />
        </div>
        <h1 className="text-2xl font-bold text-text-primary">Session Expired</h1>
        <p className="text-sm text-text-secondary">
          Your session has expired or you have been logged out. Please sign in again to continue.
        </p>
        <Button variant="primary" iconLeft={<LogIn className="h-4 w-4" />} onClick={() => navigate('/login')}>
          Return to Login
        </Button>
      </div>
    </div>
  )
}
