import { describe, it, expect, beforeEach } from "vitest"
import { useNotificationStore, selectFilteredNotifications, selectUnreadCount } from "../hooks/use-notification-store"
import type { Notification } from "../types"

function makeNotification(overrides: Partial<Notification> = {}): Notification {
  return {
    id: `n-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    type: "scan_started",
    title: "Scan Started",
    description: "A scan has been initiated",
    severity: "info",
    category: "system",
    read: false,
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

describe("Notification Store", () => {
  beforeEach(() => {
    useNotificationStore.setState({
      notifications: [],
      filter: "all",
      search: "",
      panelOpen: false,
      hasMore: false,
      total: 0,
    })
  })

  it("adds a notification", () => {
    const n = makeNotification({ id: "n1" })
    useNotificationStore.getState().addNotification(n)
    const state = useNotificationStore.getState()
    expect(state.notifications).toHaveLength(1)
    expect(state.notifications[0].id).toBe("n1")
    expect(state.total).toBe(1)
  })

  it("adds multiple notifications without duplicates", () => {
    const n1 = makeNotification({ id: "n1" })
    const n2 = makeNotification({ id: "n2" })
    const n3 = makeNotification({ id: "n1" })
    useNotificationStore.getState().addNotifications([n1, n2, n3])
    expect(useNotificationStore.getState().notifications).toHaveLength(2)
  })

  it("marks notification as read", () => {
    const n = makeNotification({ id: "n1", read: false })
    useNotificationStore.getState().addNotification(n)
    useNotificationStore.getState().markRead("n1")
    expect(useNotificationStore.getState().notifications[0].read).toBe(true)
  })

  it("marks notification as unread", () => {
    const n = makeNotification({ id: "n1", read: true })
    useNotificationStore.getState().addNotification(n)
    useNotificationStore.getState().markUnread("n1")
    expect(useNotificationStore.getState().notifications[0].read).toBe(false)
  })

  it("marks all as read", () => {
    useNotificationStore.getState().addNotification(makeNotification({ id: "n1", read: false }))
    useNotificationStore.getState().addNotification(makeNotification({ id: "n2", read: false }))
    useNotificationStore.getState().markAllRead()
    const state = useNotificationStore.getState()
    expect(state.notifications.every((n) => n.read)).toBe(true)
  })

  it("removes a notification", () => {
    useNotificationStore.getState().addNotification(makeNotification({ id: "n1" }))
    useNotificationStore.getState().addNotification(makeNotification({ id: "n2" }))
    useNotificationStore.getState().removeNotification("n1")
    const state = useNotificationStore.getState()
    expect(state.notifications).toHaveLength(1)
    expect(state.notifications[0].id).toBe("n2")
    expect(state.total).toBe(1)
  })

  it("clears all notifications", () => {
    useNotificationStore.getState().addNotification(makeNotification({ id: "n1" }))
    useNotificationStore.getState().addNotification(makeNotification({ id: "n2" }))
    useNotificationStore.getState().clearAll()
    const state = useNotificationStore.getState()
    expect(state.notifications).toHaveLength(0)
    expect(state.total).toBe(0)
  })

  it("sets filter", () => {
    useNotificationStore.getState().setFilter("security")
    expect(useNotificationStore.getState().filter).toBe("security")
  })

  it("sets search", () => {
    useNotificationStore.getState().setSearch("test query")
    expect(useNotificationStore.getState().search).toBe("test query")
  })

  it("toggles panel", () => {
    expect(useNotificationStore.getState().panelOpen).toBe(false)
    useNotificationStore.getState().togglePanel()
    expect(useNotificationStore.getState().panelOpen).toBe(true)
    useNotificationStore.getState().togglePanel()
    expect(useNotificationStore.getState().panelOpen).toBe(false)
  })

  it("returns unread count", () => {
    useNotificationStore.getState().addNotification(makeNotification({ id: "n1", read: false }))
    useNotificationStore.getState().addNotification(makeNotification({ id: "n2", read: true }))
    useNotificationStore.getState().addNotification(makeNotification({ id: "n3", read: false }))
    expect(selectUnreadCount(useNotificationStore.getState())).toBe(2)
  })

  it("filters by category", () => {
    useNotificationStore.getState().addNotification(
      makeNotification({ id: "n1", category: "security", type: "security_alert" }),
    )
    useNotificationStore.getState().addNotification(
      makeNotification({ id: "n2", category: "reports", type: "report_generated" }),
    )
    useNotificationStore.getState().addNotification(
      makeNotification({ id: "n3", category: "security", type: "login" }),
    )
    useNotificationStore.getState().setFilter("security")
    expect(selectFilteredNotifications(useNotificationStore.getState())).toHaveLength(2)
  })

  it("filters by unread", () => {
    useNotificationStore.getState().addNotification(makeNotification({ id: "n1", read: false }))
    useNotificationStore.getState().addNotification(makeNotification({ id: "n2", read: true }))
    useNotificationStore.getState().setFilter("unread")
    expect(selectFilteredNotifications(useNotificationStore.getState())).toHaveLength(1)
  })

  it("filters by search", () => {
    useNotificationStore.getState().addNotification(
      makeNotification({ id: "n1", title: "Scan Complete", description: "All good" }),
    )
    useNotificationStore.getState().addNotification(
      makeNotification({ id: "n2", title: "Security Alert", description: "Critical issue" }),
    )
    useNotificationStore.getState().setSearch("security")
    expect(selectFilteredNotifications(useNotificationStore.getState())).toHaveLength(1)
    expect(selectFilteredNotifications(useNotificationStore.getState())[0].id).toBe("n2")
  })

  it("limits stored notifications to 500", () => {
    for (let i = 0; i < 510; i++) {
      useNotificationStore.getState().addNotification(makeNotification({ id: `n-${i}` }))
    }
    expect(useNotificationStore.getState().notifications.length).toBe(500)
  })
})
