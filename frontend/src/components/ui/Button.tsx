import { forwardRef } from 'react'
import { cn } from '@/lib/utils'
import { Spinner } from './Spinner'

const variants = {
  primary:
    'bg-accent text-white hover:bg-emerald-400 focus-visible:ring-accent disabled:bg-accent/50',
  secondary:
    'bg-surface-tertiary text-text-primary hover:bg-gray-700 focus-visible:ring-gray-500 disabled:opacity-50',
  outline:
    'border border-border-light text-text-primary hover:bg-surface-tertiary focus-visible:ring-gray-500 disabled:opacity-50',
  ghost:
    'text-text-secondary hover:text-text-primary hover:bg-surface-tertiary focus-visible:ring-gray-500 disabled:opacity-50',
  danger:
    'bg-red-600 text-white hover:bg-red-500 focus-visible:ring-red-500 disabled:bg-red-600/50',
  success:
    'bg-emerald-600 text-white hover:bg-emerald-500 focus-visible:ring-emerald-500 disabled:bg-emerald-600/50',
}

const sizes = {
  xs: 'px-2 py-1 text-xs gap-1',
  sm: 'px-3 py-1.5 text-sm gap-1.5',
  md: 'px-4 py-2 text-sm gap-2',
  lg: 'px-6 py-2.5 text-base gap-2',
}

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: keyof typeof variants
  size?: keyof typeof sizes
  loading?: boolean
  iconLeft?: React.ReactNode
  iconRight?: React.ReactNode
  fullWidth?: boolean
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      className,
      variant = 'primary',
      size = 'md',
      loading = false,
      iconLeft,
      iconRight,
      fullWidth,
      children,
      disabled,
      ...props
    },
    ref,
  ) => {
    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={cn(
          'inline-flex items-center justify-center rounded-lg font-medium transition-all duration-fast',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-offset-surface',
          variants[variant],
          sizes[size],
          fullWidth && 'w-full',
          className,
        )}
        {...props}
      >
        {loading ? (
          <Spinner size="sm" className="shrink-0" />
        ) : (
          iconLeft && <span className="shrink-0">{iconLeft}</span>
        )}
        {children && <span>{children}</span>}
        {!loading && iconRight && <span className="shrink-0">{iconRight}</span>}
      </button>
    )
  },
)

Button.displayName = 'Button'
