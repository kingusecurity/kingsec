import { useEffect, useState, useCallback } from "react"
import { Shield, Download } from "lucide-react"
import { Button } from "@/shared/ui/button"

export function PWAInstallPrompt(): React.ReactElement | null {
  const [deferredPrompt, setDeferredPrompt] = useState<Event | null>(null)
  const [dismissed, setDismissed] = useState(false)

  useEffect(() => {
    const dismissedAt = localStorage.getItem("pwa-install-dismissed")
    if (dismissedAt && Date.now() - Number(dismissedAt) < 86400000) {
      setDismissed(true)
      return
    }

    const handler = (e: Event) => {
      e.preventDefault()
      setDeferredPrompt(e)
    }
    window.addEventListener("beforeinstallprompt", handler)
    return () => window.removeEventListener("beforeinstallprompt", handler)
  }, [])

  const handleInstall = useCallback(async () => {
    if (!deferredPrompt) return
    ;(deferredPrompt as { prompt: () => Promise<void> }).prompt()
    const { outcome } = await (deferredPrompt as { userChoice: Promise<{ outcome: string }> }).userChoice
    if (outcome === "accepted") {
      setDeferredPrompt(null)
      setDismissed(true)
    }
  }, [deferredPrompt])

  const handleDismiss = useCallback(() => {
    setDismissed(true)
    localStorage.setItem("pwa-install-dismissed", String(Date.now()))
  }, [])

  if (dismissed || !deferredPrompt) return null

  return (
    <div
      className="fixed bottom-4 left-4 z-[100] max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 shadow-xl"
      role="complementary"
      aria-label="Install KingSec"
    >
      <div className="flex items-start gap-3">
        <Shield className="mt-0.5 size-5 shrink-0 text-[hsl(var(--primary))]" aria-hidden="true" />
        <div className="flex-1">
          <p className="text-sm font-medium text-[hsl(var(--card-fg))]">Install KingSec</p>
          <p className="mt-1 text-xs text-[hsl(var(--muted-fg))]">
            Install KingSec as a desktop app for quick access and offline support.
          </p>
        </div>
      </div>
      <div className="mt-3 flex justify-end gap-2">
        <Button variant="ghost" size="sm" onClick={handleDismiss}>
          Not now
        </Button>
        <Button size="sm" onClick={handleInstall}>
          <Download className="mr-1 size-3" />
          Install
        </Button>
      </div>
    </div>
  )
}
