import { cn } from '@/lib/utils'
import { Spinner } from './Spinner'

interface LoadingStateProps {
  message?: string
  className?: string}
export function LoadingState({ message = 'Loading...', className }: LoadingStateProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-3 py-16 text-center',
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
