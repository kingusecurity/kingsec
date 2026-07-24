import { createContext, useContext, useState, useRef, useEffect, useCallback } from 'react'
import { cn } from '@/lib/utils'
import { AnimatePresence, motion } from 'framer-motion'

interface DropdownContextValue {
  open: boolean
  setOpen: (v: boolean) => void
}

const DropdownContext = createContext<DropdownContextValue | null>(null)

interface DropdownMenuProps {
  children: React.ReactNode
}

export function DropdownMenu({ children }: DropdownMenuProps) {
  const [open, setOpen] = useState(false)

  return (
    <DropdownContext.Provider value={{ open, setOpen }}>
      {children}
    </DropdownContext.Provider>
  )
}

interface DropdownMenuTriggerProps {
  children: React.ReactNode
  className?: string
  asChild?: boolean
}

export function DropdownMenuTrigger({ children, className, asChild }: DropdownMenuTriggerProps) {
  const ctx = useContext(DropdownContext)
  if (!ctx) throw new Error('DropdownMenuTrigger must be used within DropdownMenu')

  if (asChild) {
    return (
      <div className={cn('inline-flex', className)} onClick={() => ctx.setOpen(!ctx.open)}>
        {children}
      </div>
    )
  }

  return (
    <button
      onClick={() => ctx.setOpen(!ctx.open)}
      className={cn('inline-flex', className)}
      aria-haspopup="true"
      aria-expanded={ctx.open}
    >
      {children}
    </button>
  )
}

interface DropdownMenuContentProps {
  children: React.ReactNode
  className?: string
  align?: 'start' | 'end'
}

export function DropdownMenuContent({
  children,
  className,
  align = 'start',
}: DropdownMenuContentProps) {
  const ctx = useContext(DropdownContext)
  const ref = useRef<HTMLDivElement>(null)
  if (!ctx) throw new Error('DropdownMenuContent must be used within DropdownMenu')

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') ctx.setOpen(false)
    },
    [ctx],
  )

  useEffect(() => {
    if (!ctx.open) return
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [ctx.open, handleKeyDown])

  useEffect(() => {
    if (!ctx.open) return
    const handleClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        ctx.setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [ctx.open])

  return (
    <AnimatePresence>
      {ctx.open && (
        <motion.div
          ref={ref}
          initial={{ opacity: 0, y: -4, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -4, scale: 0.95 }}
          transition={{ duration: 0.15 }}
          className={cn(
            'absolute top-full mt-1 z-dropdown min-w-[180px] rounded-lg border border-border bg-surface-secondary py-1 shadow-theme-lg',
            align === 'end' ? 'right-0' : 'left-0',
            className,
          )}
          role="menu"
        >
          {children}
        </motion.div>
      )}
    </AnimatePresence>
  )
}

interface DropdownMenuItemProps {
  children: React.ReactNode
  className?: string
  onClick?: () => void
  disabled?: boolean
  danger?: boolean
}

export function DropdownMenuItem({
  children,
  className,
  onClick,
  disabled,
  danger,
}: DropdownMenuItemProps) {
  const ctx = useContext(DropdownContext)

  return (
    <button
      className={cn(
        'flex w-full items-center gap-2 px-3 py-2 text-sm transition-colors',
        danger
          ? 'text-red-400 hover:bg-red-900/30'
          : 'text-text-secondary hover:text-text-primary hover:bg-surface-tertiary',
        disabled && 'opacity-50 cursor-not-allowed',
        className,
      )}
      onClick={() => {
        if (!disabled) {
          onClick?.()
          ctx?.setOpen(false)
        }
      }}
      disabled={disabled}
      role="menuitem"
    >
      {children}
    </button>
  )
}

interface DropdownMenuSeparatorProps {
  className?: string
}

export function DropdownMenuSeparator({ className }: DropdownMenuSeparatorProps) {
  return <div className={cn('my-1 border-t border-border', className)} />
}
