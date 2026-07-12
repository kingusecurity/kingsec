import type { GlobalSSEEvent } from "./use-global-sse"
import type { Notification, NotificationType, NotificationSeverity, NotificationCategory } from "../types"
import { NOTIFICATION_TYPE_CONFIG } from "../types"

const SEVERITY_MAP: Record<string, NotificationSeverity> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "info",
  info: "info",
}

function eventTypeToNotificationType(eventType: string): NotificationType | null {
  switch (eventType) {
    case "assessment.created":
      return "scan_started"
    case "assessment.started":
      return "scan_started"
    case "assessment.completed":
      return "scan_finished"
    case "assessment.failed":
      return "scan_failed"
    case "assessment.cancelled":
      return "system_health"
    case "assessment.deleted":
      return "audit_event"
    case "report.ready":
      return "report_generated"
    case "notification":
      return "security_alert"
    default:
      return null
  }
}

function deriveSeverity(event: GlobalSSEEvent): NotificationSeverity {
  if (event.severity_counts) {
    if (event.severity_counts.critical > 0) return "error"
    if (event.severity_counts.high > 0) return "error"
    if (event.severity_counts.medium > 0) return "warning"
  }
  if (event.event_type.includes("failed")) return "error"
  if (event.event_type.includes("completed")) return "success"
  return "info"
}

function deriveTitle(type: NotificationType, event: GlobalSSEEvent): string {
  switch (type) {
    case "scan_started":
      return "Scan Started"
    case "scan_finished":
      return "Scan Completed"
    case "scan_failed":
      return "Scan Failed"
    case "report_generated":
      return "Report Ready"
    case "security_alert":
      return "Security Alert"
    case "audit_event":
      return "Audit Event"
    case "system_health":
      return "System Update"
    default:
      return event.event_type.replace(/[._]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())
  }
}

function deriveDescription(event: GlobalSSEEvent, type: NotificationType): string {
  if (event.message) return event.message

  switch (type) {
    case "scan_started":
      return "A new scan has been initiated"
    case "scan_finished":
      return "The scan has completed successfully"
    case "scan_failed":
      return "The scan encountered an error and failed"
    case "report_generated":
      return "Your report has been generated and is ready for download"
    case "security_alert":
      return "A security event has been detected"
    case "audit_event":
      return "An audit event has been recorded"
    case "system_health":
      return "System status update"
    default:
      return "Event occurred"
  }
}

export function sseEventToNotification(event: GlobalSSEEvent): Notification | null {
  const type = eventTypeToNotificationType(event.event_type)
  if (!type) return null

  const config = NOTIFICATION_TYPE_CONFIG[type]
  const severity = deriveSeverity(event)

  return {
    id: `sse-${event.event_type}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type,
    title: deriveTitle(type, event),
    description: deriveDescription(event, type),
    severity,
    category: config.category,
    read: false,
    created_at: event.timestamp || new Date().toISOString(),
    assessment_id: event.assessment_id,
  }
}
