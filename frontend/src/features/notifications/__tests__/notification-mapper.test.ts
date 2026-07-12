import { describe, it, expect } from "vitest"
import { sseEventToNotification } from "../hooks/use-notification-mapper"
import type { GlobalSSEEvent } from "../hooks/use-global-sse"

function makeSSEEvent(overrides: Partial<GlobalSSEEvent> = {}): GlobalSSEEvent {
  return {
    event_type: "assessment.completed",
    assessment_id: "a1",
    message: "Scan completed",
    timestamp: new Date().toISOString(),
    ...overrides,
  }
}

describe("SSE Event to Notification Mapper", () => {
  it("maps assessment.completed to scan_finished", () => {
    const event = makeSSEEvent({ event_type: "assessment.completed" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("scan_finished")
    expect(notification!.category).toBe("system")
    expect(notification!.title).toBe("Scan Completed")
  })

  it("maps assessment.failed to scan_failed", () => {
    const event = makeSSEEvent({ event_type: "assessment.failed" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("scan_failed")
    expect(notification!.severity).toBe("error")
  })

  it("maps assessment.created to scan_started", () => {
    const event = makeSSEEvent({ event_type: "assessment.created" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("scan_started")
  })

  it("maps assessment.started to scan_started", () => {
    const event = makeSSEEvent({ event_type: "assessment.started" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("scan_started")
  })

  it("maps report.ready to report_generated", () => {
    const event = makeSSEEvent({ event_type: "report.ready" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("report_generated")
    expect(notification!.category).toBe("reports")
  })

  it("maps assessment.cancelled to system_health", () => {
    const event = makeSSEEvent({ event_type: "assessment.cancelled" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("system_health")
  })

  it("maps assessment.deleted to audit_event", () => {
    const event = makeSSEEvent({ event_type: "assessment.deleted" })
    const notification = sseEventToNotification(event)
    expect(notification).not.toBeNull()
    expect(notification!.type).toBe("audit_event")
  })

  it("returns null for unknown event types", () => {
    const event = makeSSEEvent({ event_type: "unknown.event" })
    expect(sseEventToNotification(event)).toBeNull()
  })

  it("derives severity from severity_counts", () => {
    const event = makeSSEEvent({
      event_type: "assessment.completed",
      severity_counts: { critical: 2, high: 1, medium: 0, low: 3 },
    })
    const notification = sseEventToNotification(event)
    expect(notification!.severity).toBe("error")
  })

  it("derives success severity for completed events", () => {
    const event = makeSSEEvent({ event_type: "assessment.completed" })
    const notification = sseEventToNotification(event)
    expect(notification!.severity).toBe("success")
  })

  it("generates unique IDs", () => {
    const event = makeSSEEvent()
    const n1 = sseEventToNotification(event)
    const n2 = sseEventToNotification(event)
    expect(n1!.id).not.toBe(n2!.id)
  })

  it("includes assessment_id when present", () => {
    const event = makeSSEEvent({ assessment_id: "a-123" })
    const notification = sseEventToNotification(event)
    expect(notification!.assessment_id).toBe("a-123")
  })

  it("uses message from event when available", () => {
    const event = makeSSEEvent({ message: "Custom message" })
    const notification = sseEventToNotification(event)
    expect(notification!.description).toBe("Custom message")
  })

  it("defaults to new timestamp when event has none", () => {
    const event = makeSSEEvent({ timestamp: "" })
    const notification = sseEventToNotification(event)
    expect(notification!.created_at).toBeTruthy()
  })
})
