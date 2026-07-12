import { useCallback, useMemo } from "react"
import { X, WifiOff, Trash2, Inbox } from "lucide-react"
import { cn } from "@/shared/lib/utils"
import { Button } from "@/shared/ui/button"
import { EmptyState } from "@/shared/components/empty-state"
import { useNotificationStore, selectUnreadCount } from "../hooks/use-notification-store"
import { useNotificationActions } from "../hooks/use-notifications"
import { NotificationItem } from "./notification-item"
import { NotificationSkeleton } from "./notification-skeleton"
import { NotificationFilters } from "./notification-filters"
import type { Notification } from "../types"

interface NotificationPanelProps {
  open: boolean
  onClose: () => void
  isConnected: boolean
  sseError: string | null
  onReconnect: () => void
}

function matchesFilter(notification: Notification, filter: string): boolean {
  if (filter === "all") return true
  if (filter === "unread") return !notification.read
  return notification.category === filter
}

function matchesSearch(notification: Notification, search: string): boolean {
  if (!search) return true
  const q = search.toLowerCase()
  return (
    notification.title.toLowerCase().includes(q) ||
    notification.description.toLowerCase().includes(q)
  )
}

export function NotificationPanel({
  open,
  onClose,
  isConnected,
  sseError,
  onReconnect,
}: NotificationPanelProps): React.ReactElement {
  const allNotifications = useNotificationStore((s) => s.notifications)
  const filter = useNotificationStore((s) => s.filter)
  const search = useNotificationStore((s) => s.search)
  const setSearch = useNotificationStore((s) => s.setSearch)
  const unreadCount = useNotificationStore(selectUnreadCount)
  const { markRead, markUnread, deleteNotification, markAllRead, clearAll, isLoading } =
    useNotificationActions()

  const notifications = useMemo(
    () =>
      allNotifications
        .filter((n) => matchesFilter(n, filter))
        .filter((n) => matchesSearch(n, search)),
    [allNotifications, filter, search],
  )

  const handleMarkRead = useCallback(
    (id: string) => markRead(id),
    [markRead],
  )

  const handleMarkUnread = useCallback(
    (id: string) => markUnread(id),
    [markUnread],
  )

  const handleDelete = useCallback(
    (id: string) => deleteNotification(id),
    [deleteNotification],
  )

  const handleNotificationClick = useCallback(
    (notification: Notification) => {
      if (!notification.read) {
        markRead(notification.id)
      }
      if (notification.assessment_id) {
        window.location.href = `/assessments/${notification.assessment_id}`
        onClose()
      }
    },
    [markRead, onClose],
  )

  const emptyTitle = useMemo(() => {
    if (search) return "No matching notifications"
    return "No notifications yet"
  }, [search])

  const emptyDescription = useMemo(() => {
    if (search) return "Try adjusting your search terms"
    return "When events occur, notifications will appear here"
  }, [search])

  return (
    <>
      {open && (
        <div
          className="fixed inset-0 z-40 bg-black/40 transition-opacity"
          onClick={onClose}
          onKeyDown={(e) => {
            if (e.key === "Escape") onClose()
          }}
          role="button"
          tabIndex={0}
          aria-label="Close notifications"
        />
      )}

      <div
        className={cn(
          "fixed right-0 top-0 z-50 flex h-full w-full max-w-md flex-col border-l border-[hsl(var(--border))] bg-[hsl(var(--bg))] shadow-xl transition-transform duration-300",
          open ? "translate-x-0" : "translate-x-full",
        )}
        role="dialog"
        aria-label="Notification center"
      >
        <div className="flex items-center justify-between border-b border-[hsl(var(--border))] px-4 py-3">
          <div className="flex items-center gap-2">
            <h2 className="text-sm font-semibold text-[hsl(var(--fg))]">Notifications</h2>
            {unreadCount > 0 && (
              <span className="rounded-full bg-[hsl(var(--primary))] px-1.5 py-0.5 text-[10px] font-medium text-[hsl(var(--primary-fg))]">
                {unreadCount}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1">
            <div
              className={cn(
                "mr-1 size-2 rounded-full",
                isConnected ? "bg-emerald-500" : "bg-red-500",
              )}
              title={isConnected ? "Connected" : "Disconnected"}
            />
            {unreadCount > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={markAllRead}
                disabled={isLoading}
                className="text-xs"
              >
                Mark all read
              </Button>
            )}
            <Button variant="ghost" size="icon" className="size-8" onClick={onClose}>
              <X className="size-4" />
            </Button>
          </div>
        </div>

        {sseError && (
          <div className="flex items-center gap-2 border-b border-[hsl(var(--border))] bg-[hsl(var(--destructive))]/10 px-4 py-2 text-xs text-[hsl(var(--destructive))]">
            <WifiOff className="size-3 shrink-0" />
            <span className="flex-1">{sseError}</span>
            <Button variant="ghost" size="sm" onClick={onReconnect} className="h-6 text-xs">
              Retry
            </Button>
          </div>
        )}

        <div className="border-b border-[hsl(var(--border))]">
          <div className="px-4 pt-2">
            <input
              type="text"
              placeholder="Search notifications..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-md border border-[hsl(var(--border))] bg-[hsl(var(--bg-secondary))] px-3 py-1.5 text-sm text-[hsl(var(--fg))] placeholder:text-[hsl(var(--muted-fg))] focus:border-[hsl(var(--ring))] focus:outline-none"
              aria-label="Search notifications"
            />
          </div>
          <NotificationFilters />
        </div>

        <div className="flex-1 overflow-y-auto">
          <NotificationSkeleton count={0} />

          {notifications.length === 0 ? (
            <EmptyState
              icon={<Inbox className="size-12" />}
              title={emptyTitle}
              description={emptyDescription}
            />
          ) : (
            <div className="divide-y divide-[hsl(var(--border))]">
              {notifications.map((n) => (
                <NotificationItem
                  key={n.id}
                  notification={n}
                  onMarkRead={handleMarkRead}
                  onMarkUnread={handleMarkUnread}
                  onDelete={handleDelete}
                  onClick={handleNotificationClick}
                />
              ))}
            </div>
          )}
        </div>

        {notifications.length > 0 && (
          <div className="border-t border-[hsl(var(--border))] px-4 py-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={clearAll}
              disabled={isLoading}
              className="w-full text-xs text-[hsl(var(--destructive))]"
            >
              <Trash2 className="mr-1 size-3" />
              Clear all notifications
            </Button>
          </div>
        )}
      </div>
    </>
  )
}
