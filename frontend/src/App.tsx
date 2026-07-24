import { useCallback } from 'react'
import { RouterProvider } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { router } from '@/routes'
import { ToastProvider, ToastListener } from '@/components/ui/Toast'
import { AppErrorBoundary } from '@/components/shared/ErrorBoundary'
import { useAuthInit } from '@/hooks/use-auth'
import { useKeyboardShortcuts } from '@/hooks/use-keyboard-shortcuts'
import { useUIStore } from '@/store/ui'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

function AppInit() {
  useAuthInit()
  return null
}

function GlobalShortcuts() {
  const closeMobileSidebar = useUIStore((s) => s.closeMobileSidebar)

  const escHandler = useCallback(() => {
    closeMobileSidebar()
  }, [closeMobileSidebar])

  useKeyboardShortcuts({ Escape: escHandler })

  return null
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AppErrorBoundary>
        <ToastProvider>
          <AppInit />
          <ToastListener />
          <GlobalShortcuts />
          <RouterProvider router={router} />
        </ToastProvider>
      </AppErrorBoundary>
    </QueryClientProvider>
  )
}
