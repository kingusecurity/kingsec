import { useNavigate } from 'react-router-dom'
import { Search, Home } from 'lucide-react'
import { Button } from '@/components/ui'

export function NotFoundPage() {
  const { pathname } = window.location
  const navigate = useNavigate()

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-8">
      <div className="flex max-w-md flex-col items-center gap-6 text-center">
        <div className="flex h-24 w-24 items-center justify-center rounded-full bg-surface-tertiary">
          <Search className="h-12 w-12 text-text-muted" />
        </div>
        <h1 className="text-4xl font-bold text-text-primary">404</h1>
        <p className="text-lg text-text-primary">Page not found</p>
        <p className="text-sm text-text-secondary">
          The page <span className="font-mono text-text-muted">{pathname}</span> does not exist or may have been moved.
        </p>
        <div className="flex gap-3">
          <Button variant="primary" iconLeft={<Home className="h-4 w-4" />} onClick={() => navigate('/dashboard')}>
            Back to Dashboard
          </Button>
        </div>
      </div>
    </div>
  )
}
