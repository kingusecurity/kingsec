import { forwardRef, useCallback, useRef, useEffect } from 'react'
import { cn } from '@/lib/utils'

interface TextareaProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string
  helperText?: string
  error?: string
  autoResize?: boolean
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ className, label, helperText, error, autoResize, id, ...props }, forwardedRef) => {
    const inputId = id ?? label?.toLowerCase().replace(/\s+/g, '-')
    const internalRef = useRef<HTMLTextAreaElement | null>(null)

    const setRef = useCallback(
      (node: HTMLTextAreaElement | null) => {
        internalRef.current = node
        if (typeof forwardedRef === 'function') forwardedRef(node)
        else if (forwardedRef) forwardedRef.current = node
      },
      [forwardedRef],
    )

    useEffect(() => {
      if (!autoResize || !internalRef.current) return
      const el = internalRef.current
      el.style.height = 'auto'
      el.style.height = `${el.scrollHeight}px`
    }, [autoResize])

    const handleInput = useCallback(
      (e: React.ChangeEvent<HTMLTextAreaElement>) => {
        if (autoResize) {
          const el = e.target
          el.style.height = 'auto'
          el.style.height = `${el.scrollHeight}px`
        }
        props.onChange?.(e)
      },
      [autoResize, props.onChange],
    )

    return (
      <div className="space-y-1.5">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-sm font-medium text-text-secondary"
          >
            {label}
          </label>
        )}
        <textarea
          ref={setRef}
          id={inputId}
          className={cn(
            'flex min-h-[80px] w-full rounded-lg border bg-surface px-3 py-2 text-sm text-text-primary transition-colors',
            'placeholder:text-text-muted',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface',
            'disabled:cursor-not-allowed disabled:opacity-50',
            'resize-y',
            error
              ? 'border-red-500 focus-visible:ring-red-500'
              : 'border-border-light hover:border-gray-500',
            className,
          )}
          aria-invalid={!!error}
          aria-describedby={error ? `${inputId}-error` : helperText ? `${inputId}-helper` : undefined}
          onChange={handleInput}
          {...props}
        />
        {error && (
          <p id={`${inputId}-error`} className="text-xs text-red-400" role="alert">
            {error}
          </p>
        )}
        {helperText && !error && (
          <p id={`${inputId}-helper`} className="text-xs text-text-muted">
            {helperText}
          </p>
        )}
      </div>
    )
  },
)

Textarea.displayName = 'Textarea'
