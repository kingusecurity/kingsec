import { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react'
import { X, CheckCircle2, AlertTriangle, AlertCircle, Info } from 'lucide-react'
import { cn } from '@/lib/utils'
import { AnimatePresence, motion } from 'framer-motion'

type ToastVariant = 'success' | 'warning' | 'error' | 'info'

interface Toast {
  id: string
  variant: ToastVariant
  title: string
  message?: string
}

interface ToastContextValue {
  addToast: (toast: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void
}

const ToastContext = createContext<ToastContextValue | null>(null)

const iconMap: Record<ToastVariant, React.ComponentType<{ className?: string }>> = {
  success: CheckCircle2,
  warning: AlertTriangle,
  error: AlertCircle,
  info: Info,
}

const styleMap: Record<ToastVariant, string> = {
  success: 'border-emerald-800/50 bg-emerald-900/90',
  warning: 'border-yellow-800/50 bg-yellow-900/90',
  error: 'border-red-800/50 bg-red-900/90',
  info: 'border-blue-800/50 bg-blue-900/90',
}

const iconColorMap: Record<ToastVariant, string> = {
  success: 'text-emerald-400',
  warning: 'text-yellow-400',
  error: 'text-red-400',
  info: 'text-blue-400',
}

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback((t: Omit<Toast, 'id'>) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
    setToasts((prev) => [...prev, { ...t, id }])
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ addToast, removeToast }}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-toast flex flex-col gap-2 max-w-sm w-full pointer-events-none"
        aria-live="polite"
        aria-label="Notifications"
      >
        <AnimatePresence mode="popLayout">
          {toasts.map((t) => (
            <ToastItem key={t.id} toast={t} onDismiss={removeToast} />
          ))}
        </AnimatePresence>
      </div>
    </ToastContext.Provider>
  )
}

function ToastItem({
  toast,
  onDismiss,
}: {
  toast: Toast
  onDismiss: (id: string) => void
}) {
  const Icon = iconMap[toast.variant]
  const timerRef = useRef<ReturnType<typeof setTimeout>>(undefined)

  useEffect(() => {
    timerRef.current = setTimeout(() => onDismiss(toast.id), 5000)
    return () => clearTimeout(timerRef.current)
  }, [toast.id, onDismiss])

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 20, scale: 0.95 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      exit={{ opacity: 0, x: 100, scale: 0.95 }}
      transition={{ duration: 0.2 }}
      className={cn(
        'pointer-events-auto flex items-start gap-3 rounded-lg border p-4 shadow-theme-lg',
        styleMap[toast.variant],
      )}
      role="alert"
    >
      <Icon className={cn('mt-0.5 h-5 w-5 shrink-0', iconColorMap[toast.variant])} />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-white">{toast.title}</p>
        {toast.message && (
          <p className="mt-0.5 text-sm text-gray-300">{toast.message}</p>
        )}
      </div>
      <button
        onClick={() => onDismiss(toast.id)}
        className="shrink-0 rounded p-0.5 text-gray-400 hover:text-white transition-colors"
        aria-label="Dismiss"
      >
        <X className="h-4 w-4" />
      </button>
    </motion.div>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within a ToastProvider')
  return ctx
}

export const toast = {
  success: (title: string, message?: string) => {
    const event = new CustomEvent('kingsec-toast', {
      detail: { variant: 'success' as const, title, message },
    })
    window.dispatchEvent(event)
  },
  warning: (title: string, message?: string) => {
    const event = new CustomEvent('kingsec-toast', {
      detail: { variant: 'warning' as const, title, message },
    })
    window.dispatchEvent(event)
  },
  error: (title: string, message?: string) => {
    const event = new CustomEvent('kingsec-toast', {
      detail: { variant: 'error' as const, title, message },
    })
    window.dispatchEvent(event)
  },
  info: (title: string, message?: string) => {
    const event = new CustomEvent('kingsec-toast', {
      detail: { variant: 'info' as const, title, message },
    })
    window.dispatchEvent(event)
  },
}

export function ToastListener() {
  const { addToast } = useToast()

  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent).detail
      addToast(detail)
    }
    window.addEventListener('kingsec-toast', handler)
    return () => window.removeEventListener('kingsec-toast', handler)
  }, [addToast])

  return null
}
