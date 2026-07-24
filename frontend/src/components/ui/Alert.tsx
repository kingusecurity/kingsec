import { AlertCircle, AlertTriangle, CheckCircle2, Info } from 'lucide-react'
import { cn } from '@/lib/utils'

const config = {
  success: {
    icon: CheckCircle2,
    container: 'border-emerald-800/50 bg-emerald-900/20',
    text: 'text-emerald-400',
  },
  warning: {
    icon: AlertTriangle,
    container: 'border-yellow-800/50 bg-yellow-900/20',
    text: 'text-yellow-400',
  },
  error: {
    icon: AlertCircle,
    container: 'border-red-800/50 bg-red-900/20',
    text: 'text-red-400',
  },
  info: {
    icon: Info,
    container: 'border-blue-800/50 bg-blue-900/20',
    text: 'text-blue-400',
  },
}

interface AlertProps {
  variant?: keyof typeof config
  title?: string
  children: React.ReactNode
  className?: string
  icon?: React.ReactNode
}

export function Alert({
  variant = 'info',
  title,
  children,
  className,
  icon,
}: AlertProps) {
  const c = config[variant]
  const Icon = c.icon

  return (
    <div
      className={cn(
        'flex gap-3 rounded-lg border p-4',
        c.container,
        className,
      )}
      role="alert"
    >
      <div className={cn('mt-0.5 shrink-0', c.text)}>
        {icon ?? <Icon className="h-5 w-5" />}
      </div>
      <div className="space-y-1">
        {title && (
          <p className={cn('text-sm font-medium', c.text)}>{title}</p>
        )}
        <div className="text-sm text-text-secondary">{children}</div>
      </div>
    </div>
  )
}
