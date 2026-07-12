import { useEffect, useState } from "react"
import { WifiOff } from "lucide-react"
import { cn } from "@/shared/lib/utils"

export function OfflineBanner(): React.ReactElement | null {
  const [offline, setOffline] = useState(!navigator.onLine)
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const handleOnline = () => {
      setOffline(false)
      setVisible(false)
    }
    const handleOffline = () => {
      setOffline(true)
      setVisible(true)
    }
    window.addEventListener("online", handleOnline)
    window.addEventListener("offline", handleOffline)
    return () => {
      window.removeEventListener("online", handleOnline)
      window.removeEventListener("offline", handleOffline)
    }
  }, [])

  if (!visible) return null

  return (
    <div
      className={cn(
        "fixed bottom-4 left-1/2 z-[100] -translate-x-1/2 rounded-lg border border-[hsl(var(--destructive))]/30 bg-[hsl(var(--destructive))] px-4 py-2 text-sm text-[hsl(var(--destructive-fg))] shadow-lg",
        "animate-in slide-in-from-bottom-4 fade-in-0 duration-300",
      )}
      role="status"
      aria-live="polite"
    >
      <div className="flex items-center gap-2">
        <WifiOff className="size-4" aria-hidden="true" />
        <span>You are offline. Some features may be unavailable.</span>
      </div>
    </div>
  )
}
