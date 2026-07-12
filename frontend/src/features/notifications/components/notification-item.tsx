import { useMemo } from "react"
import {
  Radar,
  CheckCircle,
  XCircle,
  FileText,
  UserPlus,
  UserMinus,
  KeyRound,
  LogIn,
  LogOut,
  ShieldAlert,
  ScrollText,
  Activity,
} from "lucide-react"
import { cn } from "@/shared/lib/utils"
import { formatRelative } from "@/shared/lib/utils"
import type { Notification, NotificationType } from "../types"

const ICON_MAP: Record<NotificationType, React.ComponentType<{ className?: string }>> = {
  scan_started: Radar,
  scan_finished: CheckCircle,
  scan_failed: XCircle,
  report_generated: FileText,
  user_created: UserPlus,
  user_deleted: UserMinus,
  password_changed: KeyRound,
  login: LogIn,
  logout: LogOut,
  security_alert: ShieldAlert,
  audit_event: ScrollText,
  system_health: Activity,
}

const COLOR_MAP: Record<NotificationType, string> = {
  scan_started: "text-blue-500",
  scan_finished: "text-emerald-500",
  scan_failed: "text-red-500",
  report_generated: "text-violet-500",
  user_created: "text-blue-500",
  user_deleted: "text-red-500",
  password_changed: "text-amber-500",
  login: "text-emerald-500",
  logout: "text-slate-500",
  security_alert: "text-red-500",
  audit_event: "text-slate-500",
  system_health: "text-amber-500",
}

const SEVERITY_DOT: Record<string, string> = {
  error: "bg-red-500",
  warning: "bg-amber-500",
  success: "bg-emerald-500",
  info: "bg-blue-500",
}

interface NotificationItemProps {
  notification: Notification
  onMarkRead: (id: string) => void
  onMarkUnread: (id: string) => void
  onDelete: (id: string) => void
  onClick?: (notification: Notification) => void
}

export function NotificationItem({
  notification,
  onMarkRead,
  onMarkUnread,
  onDelete,
  onClick,
}: NotificationItemProps): React.ReactElement {
  const Icon = ICON_MAP[notification.type]
  const colorClass = COLOR_MAP[notification.type]
  const dotClass = SEVERITY_DOT[notification.severity] ?? "bg-slate-500"
  const relativeTime = useMemo(() => formatRelative(notification.created_at), [notification.created_at])

  return (
    <div
      className={cn(
        "group flex gap-3 px-4 py-3 transition-colors hover:bg-[hsl(var(--bg-secondary))]",
        !notification.read && "bg-[hsl(var(--bg-secondary))]/50",
      )}
      role="button"
      tabIndex={0}
      onClick={() => onClick?.(notification)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault()
          onClick?.(notification)
        }
      }}
    >
      <div className="relative mt-0.5 shrink-0">
        <Icon className={cn("size-4", colorClass)} />
        {!notification.read && (
          <span className={cn("absolute -right-1 -top-1 size-2 rounded-full", dotClass)} />
        )}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <p
            className={cn(
              "truncate text-sm",
              notification.read
                ? "text-[hsl(var(--fg-secondary))]"
                : "font-medium text-[hsl(var(--fg))]",
            )}
          >
            {notification.title}
          </p>
          <span className="shrink-0 text-xs text-[hsl(var(--muted-fg))]">{relativeTime}</span>
        </div>
        <p className="mt-0.5 line-clamp-2 text-xs text-[hsl(var(--fg-secondary))]">
          {notification.description}
        </p>
        <div className="mt-1.5 flex gap-1 opacity-0 transition-opacity group-hover:opacity-100">
          {notification.read ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onMarkUnread(notification.id)
              }}
              className="rounded px-1.5 py-0.5 text-xs text-[hsl(var(--fg-secondary))] hover:bg-[hsl(var(--bg-tertiary))] hover:text-[hsl(var(--fg))]"
            >
              Mark unread
            </button>
          ) : (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onMarkRead(notification.id)
              }}
              className="rounded px-1.5 py-0.5 text-xs text-[hsl(var(--fg-secondary))] hover:bg-[hsl(var(--bg-tertiary))] hover:text-[hsl(var(--fg))]"
            >
              Mark read
            </button>
          )}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              onDelete(notification.id)
            }}
            className="rounded px-1.5 py-0.5 text-xs text-[hsl(var(--destructive))] hover:bg-[hsl(var(--destructive))]/10"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  )
}
