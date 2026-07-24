import { forwardRef } from 'react'
import { cn } from '@/lib/utils'

interface ToggleProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: string
}

export const Toggle = forwardRef<HTMLInputElement, ToggleProps>(
  ({ className, label, id, disabled, ...props }, ref) => {
    const inputId = id ?? label?.toLowerCase().replace(/\s+/g, '-')

    return (
      <label
        htmlFor={inputId}
        className={cn(
          'inline-flex items-center gap-3',
          disabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer',
          className,
        )}
      >
        <div className="relative">
          <input
            ref={ref}
            id={inputId}
            type="checkbox"
            role="switch"
            disabled={disabled}
            className="peer sr-only"
            {...props}
          />
          <div
            className={cn(
              'h-6 w-10 rounded-full border border-border-light bg-surface-tertiary transition-colors',
              'peer-checked:bg-accent peer-checked:border-accent',
              'peer-focus-visible:ring-2 peer-focus-visible:ring-accent peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-surface',
              'peer-disabled:cursor-not-allowed peer-disabled:opacity-50',
            )}
          >
            <div
              className={cn(
                'h-5 w-5 rounded-full bg-white transition-transform duration-fast',
                'translate-x-0.5 translate-y-0.5',
                'peer-checked:translate-x-[18px]',
              )}
            />
          </div>
        </div>
        {label && (
          <span className="text-sm text-text-primary select-none">{label}</span>
        )}
      </label>
    )
  },
)

Toggle.displayName = 'Toggle'
