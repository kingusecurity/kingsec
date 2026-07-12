import { useEffect, useState, useCallback } from "react"
import { RefreshCw, Download } from "lucide-react"
import { Button } from "@/shared/ui/button"

interface UpdateInfo {
  isUpdateAvailable: boolean
  registration: ServiceWorkerRegistration | null
}

export function PWAUpdateNotification(): React.ReactElement | null {
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo>({ isUpdateAvailable: false, registration: null })
  const [installing, setInstalling] = useState(false)

  const handleUpdate = useCallback(async () => {
    const { registration } = updateInfo
    if (!registration?.waiting) return
    setInstalling(true)
    registration.waiting.postMessage({ type: "SKIP_WAITING" })
    window.location.reload()
  }, [updateInfo])

  useEffect(() => {
    if (!("serviceWorker" in navigator)) return
    let swRegistration: ServiceWorkerRegistration | null = null

    navigator.serviceWorker.ready.then((reg) => {
      swRegistration = reg
      reg.addEventListener("updatefound", () => {
        const newWorker = reg.installing
        if (!newWorker) return
        newWorker.addEventListener("statechange", () => {
          if (newWorker.state === "installed" && navigator.serviceWorker.controller) {
            setUpdateInfo({ isUpdateAvailable: true, registration: reg })
          }
        })
      })
    })

    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === "UPDATE_AVAILABLE") {
        setUpdateInfo({ isUpdateAvailable: true, registration: swRegistration })
      }
    }
    navigator.serviceWorker.addEventListener("message", handleMessage)
    return () => {
      navigator.serviceWorker.removeEventListener("message", handleMessage)
    }
  }, [])

  if (!updateInfo.isUpdateAvailable) return null

  return (
    <div
      className="fixed bottom-4 right-4 z-[100] max-w-sm rounded-lg border border-[hsl(var(--border))] bg-[hsl(var(--card))] p-4 shadow-xl"
      role="alert"
      aria-live="polite"
    >
      <div className="flex items-start gap-3">
        <Download className="mt-0.5 size-5 shrink-0 text-[hsl(var(--primary))]" aria-hidden="true" />
        <div className="flex-1">
          <p className="text-sm font-medium text-[hsl(var(--card-fg))]">Update available</p>
          <p className="mt-1 text-xs text-[hsl(var(--muted-fg))]">
            A new version of KingSec is ready. Reload to update.
          </p>
        </div>
      </div>
      <div className="mt-3 flex justify-end gap-2">
        <Button variant="ghost" size="sm" onClick={() => setUpdateInfo({ isUpdateAvailable: false, registration: null })}>
          Dismiss
        </Button>
        <Button size="sm" onClick={handleUpdate} disabled={installing}>
          <RefreshCw className={`mr-1 size-3 ${installing ? "animate-spin" : ""}`} />
          Update
        </Button>
      </div>
    </div>
  )
}
