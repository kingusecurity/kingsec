import { type ReactNode } from "react"
import { Toaster } from "sonner"
import { QueryClientProvider, QueryClient } from "@tanstack/react-query"
import { ErrorBoundary } from "@/shared/components/error-boundary"
import { OfflineBanner } from "@/shared/components/offline-banner"
import { SkipToContent } from "@/shared/components/skip-to-content"
import { PWAUpdateNotification } from "@/shared/components/pwa-update-notification"
import { PWAInstallPrompt } from "@/shared/components/pwa-install-prompt"

function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        retry: 1,
        refetchOnWindowFocus: false,
      },
      mutations: {
        retry: 0,
      },
    },
  })
}

let browserQueryClient: QueryClient | undefined

function getQueryClient(): QueryClient {
  if (typeof window === "undefined") {
    return makeQueryClient()
  }
  if (!browserQueryClient) {
    browserQueryClient = makeQueryClient()
  }
  return browserQueryClient
}

export function AppShell({ children }: { children: ReactNode }): React.ReactElement {
  const queryClient = getQueryClient()

  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <SkipToContent />
        {children}
        <OfflineBanner />
        <PWAUpdateNotification />
        <PWAInstallPrompt />
        <Toaster
          position="bottom-right"
          richColors
          closeButton
          duration={4000}
          toastOptions={{ className: "text-sm" }}
          aria-live="polite"
        />
      </QueryClientProvider>
    </ErrorBoundary>
  )
}
