import { cn } from '@/lib/utils'

const variants = {
  default: 'bg-surface-secondary border-border',
  outlined: 'bg-surface border-border-light',
  elevated: 'bg-surface-elevated border-border shadow-theme-md',
  danger: 'bg-surface-secondary border-red-800/50',
  success: 'bg-surface-secondary border-emerald-800/50',
  warning: 'bg-surface-secondary border-yellow-800/50',
}

interface CardProps {
  variant?: keyof typeof variants
  className?: string
  children: React.ReactNode
  onClick?: () => void
}

interface CardHeaderProps {
  className?: string
  children: React.ReactNode
}

interface CardFooterProps {
  className?: string
  children: React.ReactNode
}

interface CardTitleProps {
  className?: string
  children: React.ReactNode
}

interface CardDescriptionProps {
  className?: string
  children: React.ReactNode
}

interface CardActionsProps {
  className?: string
  children: React.ReactNode
}

export function Card({ variant = 'default', className, children, onClick }: CardProps) {
  return (
    <div className={cn('rounded-xl border', variants[variant], className)} onClick={onClick}>
      {children}
    </div>
  )
}

export function CardHeader({ className, children }: CardHeaderProps) {
  return (
    <div className={cn('flex flex-col gap-1 px-5 pt-5', className)}>
      {children}
    </div>
  )
}

export function CardTitle({ className, children }: CardTitleProps) {
  return (
    <h3 className={cn('text-base font-semibold text-text-primary', className)}>
      {children}
    </h3>
  )
}

export function CardDescription({ className, children }: CardDescriptionProps) {
  return (
    <p className={cn('text-sm text-text-secondary', className)}>
      {children}
    </p>
  )
}

export function CardActions({ className, children }: CardActionsProps) {
  return (
    <div className={cn('flex items-center gap-2', className)}>
      {children}
    </div>
  )
}

export function CardFooter({ className, children }: CardFooterProps) {
  return (
    <div
      className={cn(
        'flex items-center justify-end gap-3 border-t border-border px-5 py-4',
        className,
      )}
    >
      {children}
    </div>
  )
}
