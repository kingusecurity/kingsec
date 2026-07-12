import { Bell } from "lucide-react"
import { cn } from "@/shared/lib/utils"
import { Button } from "@/shared/ui/button"
import { useNotificationCenter } from "../hooks/use-notification-center"
import { NotificationPanel } from "./notification-panel"

export function NotificationBell(): React.ReactElement {
  const {
    unreadCount,
    panelOpen,
    togglePanel,
    setPanelOpen,
    isConnected,
    sseError,
    reconnect,
  } = useNotificationCenter()

  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        className="relative size-9"
        onClick={togglePanel}
        aria-label={`Notifications${unreadCount > 0 ? ` (${unreadCount} unread)` : ""}`}
      >
        <Bell className="size-4" />
        {unreadCount > 0 && (
          <span
            className={cn(
              "absolute -right-0.5 -top-0.5 flex min-w-[18px] items-center justify-center rounded-full px-1 py-0.5 text-[10px] font-bold text-white",
              unreadCount > 99 ? "bg-[hsl(var(--destructive))]" : "bg-[hsl(var(--destructive))]",
            )}
          >
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
        <span
          className={cn(
            "absolute bottom-1 right-1 size-1.5 rounded-full",
            isConnected ? "bg-emerald-500" : "bg-red-500",
          )}
          title={isConnected ? "Connected" : "Disconnected"}
        />
      </Button>

      <NotificationPanel
        open={panelOpen}
        onClose={() => setPanelOpen(false)}
        isConnected={isConnected}
        sseError={sseError}
        onReconnect={reconnect}
      />
    </>
  )
}
