import { useEffect, useCallback } from 'react'
import { X, Bell } from 'lucide-react'
import { cn } from '@/lib/utils'
import { AnimatePresence, motion } from 'framer-motion'
import { NotificationList } from './NotificationList'

interface NotificationDrawerProps {
  open: boolean
  onClose: () => void
}

export function NotificationDrawer({ open, onClose }: NotificationDrawerProps) {
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    },
    [onClose],
  )

  useEffect(() => {
    if (!open) return
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [open, handleKeyDown])

  useEffect(() => {
    if (!open) return
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = '' }
  }, [open])

  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-50">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="absolute inset-0 bg-black/60"
            onClick={onClose}
            aria-hidden="true"
          />
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            className={cn(
              'absolute right-0 top-0 h-full w-full max-w-md border-l border-border bg-surface-secondary shadow-theme-lg',
            )}
            role="dialog"
            aria-modal="true"
            aria-label="Notifications"
          >
            <div className="flex h-14 items-center justify-between border-b border-border px-5">
              <div className="flex items-center gap-2">
                <Bell className="h-5 w-5 text-accent" />
                <h2 className="text-base font-semibold text-text-primary">Notifications</h2>
              </div>
              <button
                onClick={onClose}
                className="rounded p-1 text-text-muted hover:text-text-primary transition-colors"
                aria-label="Close notifications"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="overflow-y-auto p-5" style={{ height: 'calc(100% - 3.5rem)' }}>
              <NotificationList />
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}
