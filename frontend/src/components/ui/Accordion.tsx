import { createContext, useContext, useState, useCallback, useId } from 'react'
import { ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { AnimatePresence, motion } from 'framer-motion'

interface AccordionContextValue {
  openItems: string[]
  toggleItem: (value: string) => void
  baseId: string
}

const AccordionContext = createContext<AccordionContextValue | null>(null)

interface AccordionItemContextValue {
  value: string
}

const AccordionItemContext = createContext<AccordionItemContextValue | null>(null)

interface AccordionProps {
  className?: string
  children: React.ReactNode
  type?: 'single' | 'multiple'
  defaultValue?: string[]
}

export function Accordion({
  className,
  children,
  type = 'single',
  defaultValue = [],
}: AccordionProps) {
  const [openItems, setOpenItems] = useState<string[]>(defaultValue)
  const baseId = useId()

  const toggleItem = useCallback(
    (value: string) => {
      setOpenItems((prev) => {
        if (type === 'single') {
          return prev.includes(value) ? [] : [value]
        }
        return prev.includes(value)
          ? prev.filter((v) => v !== value)
          : [...prev, value]
      })
    },
    [type],
  )

  return (
    <AccordionContext.Provider value={{ openItems, toggleItem, baseId }}>
      <div className={cn('divide-y divide-border', className)}>
        {children}
      </div>
    </AccordionContext.Provider>
  )
}

interface AccordionItemProps {
  value: string
  className?: string
  children: React.ReactNode
}

export function AccordionItem({ value, className, children }: AccordionItemProps) {
  return (
    <AccordionItemContext.Provider value={{ value }}>
      <div className={className}>{children}</div>
    </AccordionItemContext.Provider>
  )
}

interface AccordionTriggerProps {
  className?: string
  children: React.ReactNode
}

export function AccordionTrigger({ className, children }: AccordionTriggerProps) {
  const ctx = useContext(AccordionContext)
  const itemCtx = useContext(AccordionItemContext)
  if (!ctx || !itemCtx) throw new Error('AccordionTrigger must be within Accordion > AccordionItem')

  const { value } = itemCtx
  const isOpen = ctx.openItems.includes(value)

  return (
    <button
      id={`${ctx.baseId}-trigger-${value}`}
      aria-expanded={isOpen}
      aria-controls={`${ctx.baseId}-panel-${value}`}
      onClick={() => ctx.toggleItem(value)}
      className={cn(
        'flex w-full items-center justify-between gap-3 py-3 text-sm font-medium text-text-primary transition-colors',
        'hover:text-text-primary',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-inset',
        className,
      )}
    >
      <span>{children}</span>
      <ChevronDown
        className={cn(
          'h-4 w-4 shrink-0 text-text-muted transition-transform duration-fast',
          isOpen && 'rotate-180',
        )}
      />
    </button>
  )
}

interface AccordionContentProps {
  className?: string
  children: React.ReactNode
}

export function AccordionContent({ className, children }: AccordionContentProps) {
  const ctx = useContext(AccordionContext)
  const itemCtx = useContext(AccordionItemContext)
  if (!ctx || !itemCtx) throw new Error('AccordionContent must be within Accordion > AccordionItem')

  const { value } = itemCtx
  const isOpen = ctx.openItems.includes(value)

  return (
    <AnimatePresence initial={false}>
      {isOpen && (
        <motion.div
          id={`${ctx.baseId}-panel-${value}`}
          role="region"
          aria-labelledby={`${ctx.baseId}-trigger-${value}`}
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: 'auto', opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          transition={{ duration: 0.2 }}
          className="overflow-hidden"
        >
          <div className={cn('pb-3 text-sm text-text-secondary', className)}>
            {children}
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
