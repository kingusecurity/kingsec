export type NotificationType =
  | "scan_started"
  | "scan_finished"
  | "scan_failed"
  | "report_generated"
  | "user_created"
  | "user_deleted"
  | "password_changed"
  | "login"
  | "logout"
  | "security_alert"
  | "audit_event"
  | "system_health"

export type NotificationSeverity = "info" | "warning" | "error" | "success"

export type NotificationCategory = "security" | "reports" | "users" | "system"

export type NotificationFilter = "all" | "unread" | NotificationCategory

export interface Notification {
  id: string
  type: NotificationType
  title: string
  description: string
  severity: NotificationSeverity
  category: NotificationCategory
  read: boolean
  created_at: string
  assessment_id?: string
  user_id?: string
  report_id?: string
  metadata?: Record<string, unknown>
}

export interface NotificationTypeConfig {
  icon: string
  color: string
  category: NotificationCategory
}

export const NOTIFICATION_TYPE_CONFIG: Record<NotificationType, NotificationTypeConfig> = {
  scan_started: { icon: "Radar", color: "text-blue-500", category: "system" },
  scan_finished: { icon: "CheckCircle", color: "text-emerald-500", category: "system" },
  scan_failed: { icon: "XCircle", color: "text-red-500", category: "system" },
  report_generated: { icon: "FileText", color: "text-violet-500", category: "reports" },
  user_created: { icon: "UserPlus", color: "text-blue-500", category: "users" },
  user_deleted: { icon: "UserMinus", color: "text-red-500", category: "users" },
  password_changed: { icon: "KeyRound", color: "text-amber-500", category: "users" },
  login: { icon: "LogIn", color: "text-emerald-500", category: "security" },
  logout: { icon: "LogOut", color: "text-slate-500", category: "security" },
  security_alert: { icon: "ShieldAlert", color: "text-red-500", category: "security" },
  audit_event: { icon: "ScrollText", color: "text-slate-500", category: "system" },
  system_health: { icon: "Activity", color: "text-amber-500", category: "system" },
}

export const NOTIFICATION_CATEGORY_LABELS: Record<NotificationCategory | "all" | "unread", string> = {
  all: "All",
  unread: "Unread",
  security: "Security",
  reports: "Reports",
  users: "Users",
  system: "System",
}

export interface NotificationListParams {
  limit?: number
  offset?: number
  category?: NotificationCategory
  unread_only?: boolean
  search?: string
}

export interface NotificationListResponse {
  items: Notification[]
  total: number
  unread_count: number
  has_more: boolean
}
