import { cn } from "@/shared/lib/utils"
import type { NotificationFilter } from "../types"
import { NOTIFICATION_CATEGORY_LABELS } from "../types"
import { useNotificationStore } from "../hooks/use-notification-store"

const FILTER_OPTIONS: NotificationFilter[] = ["all", "unread", "security", "reports", "users", "system"]

export function NotificationFilters(): React.ReactElement {
  const filter = useNotificationStore((s) => s.filter)
  const setFilter = useNotificationStore((s) => s.setFilter)
  const notifications = useNotificationStore((s) => s.notifications)

  function getCount(f: NotificationFilter): number {
    if (f === "all") return notifications.length
    if (f === "unread") return notifications.filter((n) => !n.read).length
    return notifications.filter((n) => n.category === f).length
  }

  return (
    <div className="flex gap-1 overflow-x-auto px-4 py-2">
      {FILTER_OPTIONS.map((f) => {
        const count = getCount(f)
        const active = filter === f
        return (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            className={cn(
              "shrink-0 rounded-full px-3 py-1 text-xs font-medium transition-colors",
              active
                ? "bg-[hsl(var(--primary))] text-[hsl(var(--primary-fg))]"
                : "text-[hsl(var(--fg-secondary))] hover:bg-[hsl(var(--bg-secondary))]",
            )}
          >
            {NOTIFICATION_CATEGORY_LABELS[f]}
            {count > 0 && (
              <span className="ml-1 opacity-60">{count}</span>
            )}
          </button>
        )
      })}
    </div>
  )
}
