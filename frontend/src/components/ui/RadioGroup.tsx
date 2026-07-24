import { createContext, useContext, forwardRef } from 'react'
import { cn } from '@/lib/utils'

interface RadioGroupContextValue {
  value: string
  onValueChange: (value: string) => void
  name?: string
  disabled?: boolean
}

const RadioGroupContext = createContext<RadioGroupContextValue | null>(null)

interface RadioGroupProps {
  value: string
  onValueChange: (value: string) => void
  name?: string
  disabled?: boolean
  className?: string
  children: React.ReactNode
}

export function RadioGroup({
  value,
  onValueChange,
  name,
  disabled,
  className,
  children,
}: RadioGroupProps) {
  return (
    <RadioGroupContext.Provider value={{ value, onValueChange, name, disabled }}>
      <div className={cn('flex flex-col gap-2', className)} role="radiogroup">
        {children}
      </div>
    </RadioGroupContext.Provider>
  )
}

interface RadioGroupItemProps {
  value: string
  label?: string
  disabled?: boolean
  className?: string
}

export const RadioGroupItem = forwardRef<HTMLInputElement, RadioGroupItemProps>(
  ({ value, label, disabled: itemDisabled, className }, ref) => {
    const ctx = useContext(RadioGroupContext)
    if (!ctx) throw new Error('RadioGroupItem must be used within a RadioGroup')

    const isSelected = ctx.value === value
    const isDisabled = ctx.disabled || itemDisabled
    const inputId = `${ctx.name ?? 'radio'}-${value}`

    return (
      <label
        htmlFor={inputId}
        className={cn(
          'inline-flex items-center gap-2.5',
          isDisabled ? 'cursor-not-allowed opacity-50' : 'cursor-pointer',
          className,
        )}
      >
        <div className="relative flex h-5 w-5 shrink-0 items-center justify-center">
          <input
            ref={ref}
            id={inputId}
            type="radio"
            name={ctx.name}
            value={value}
            checked={isSelected}
            disabled={isDisabled}
            onChange={() => ctx.onValueChange(value)}
            className="peer sr-only"
          />
          <div
            className={cn(
              'flex h-5 w-5 items-center justify-center rounded-full border transition-colors',
              'border-border-light bg-surface',
              'peer-checked:border-accent',
              'peer-focus-visible:ring-2 peer-focus-visible:ring-accent peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-surface',
              'peer-disabled:cursor-not-allowed peer-disabled:opacity-50',
            )}
          >
            <div
              className={cn(
                'h-2.5 w-2.5 rounded-full bg-accent transition-opacity',
                isSelected ? 'opacity-100' : 'opacity-0',
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

RadioGroupItem.displayName = 'RadioGroupItem'
