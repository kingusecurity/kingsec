import { cn } from '@/lib/utils'

interface ProgressProps {
  value?: number
  className?: string
  indeterminate?: boolean
}

export function Progress({ value, className, indeterminate }: ProgressProps) {
  return (
    <div
      className={cn(
        'relative h-2 w-full overflow-hidden rounded-full bg-surface-tertiary',
        className,
      )}
      role="progressbar"
      aria-valuenow={indeterminate ? undefined : value}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label="Progress"
    >
      <div
        className={cn(
          'h-full rounded-full bg-accent transition-all duration-slow',
          indeterminate && 'w-1/4 animate-progress-indeterminate',
          !indeterminate && 'transition-all',
        )}
        style={!indeterminate ? { width: `${Math.min(100, Math.max(0, value ?? 0))}%` } : undefined}
      />
    </div>
  )
}
