import { cn } from '@/lib/utils'

const variants = {
  critical: 'bg-red-900/50 text-red-400 border-red-800',
  high: 'bg-orange-900/50 text-orange-400 border-orange-800',
  medium: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
  low: 'bg-blue-900/50 text-blue-400 border-blue-800',
  info: 'bg-gray-800 text-gray-400 border-gray-700',
  success: 'bg-emerald-900/50 text-emerald-400 border-emerald-800',
  warning: 'bg-yellow-900/50 text-yellow-400 border-yellow-800',
  neutral: 'bg-gray-800 text-gray-400 border-gray-700',
}

const sizes = {
  sm: 'px-1.5 py-0.5 text-[10px]',
  md: 'px-2 py-0.5 text-xs',
  lg: 'px-2.5 py-1 text-sm',
}

interface BadgeProps {
  variant?: keyof typeof variants
  size?: keyof typeof sizes
  className?: string
  children: React.ReactNode
}

export function Badge({
  variant = 'neutral',
  size = 'md',
  className,
  children,
}: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border font-medium',
        variants[variant],
        sizes[size],
        className,
      )}
    >
      {children}
    </span>
  )
}
