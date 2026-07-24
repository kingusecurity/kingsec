import { cn } from '@/lib/utils'

interface DividerProps {
  orientation?: 'horizontal' | 'vertical'
  className?: string
  label?: string
}

export function Divider({
  orientation = 'horizontal',
  className,
  label,
}: DividerProps) {
  if (orientation === 'vertical') {
    return (
      <div
        className={cn(
          'inline-block h-full w-px bg-border',
          className,
        )}
        role="separator"
        aria-orientation="vertical"
      />
    )
  }

  if (label) {
    return (
      <div className={cn('flex items-center gap-3', className)} role="separator">
        <div className="flex-1 border-t border-border" />
        <span className="text-xs text-text-muted">{label}</span>
        <div className="flex-1 border-t border-border" />
      </div>
    )
  }

  return (
    <div
      className={cn('h-px w-full bg-border', className)}
      role="separator"
      aria-orientation="horizontal"
    />
  )
}
