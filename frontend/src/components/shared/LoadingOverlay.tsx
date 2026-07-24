import { cn } from '@/lib/utils'
import { Spinner } from '@/components/ui'

interface LoadingOverlayProps {
  loading: boolean
  message?: string
  fullPage?: boolean
  className?: string
}

export function LoadingOverlay({ loading, message = 'Loading...', fullPage, className }: LoadingOverlayProps) {
  if (!loading) return null

  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 bg-gray-950/80 backdrop-blur-sm',
        fullPage ? 'fixed inset-0 z-overlay' : 'absolute inset-0 z-10 rounded-lg',
        className,
      )}
      role="status"
      aria-label={message}
    >
      <Spinner size="lg" />
      <p className="text-sm text-text-muted">{message}</p>
    </div>
  )
}
