import { describe, it, expect, vi, beforeEach } from "vitest"
import {
  listNotifications,
  getNotification,
  markNotificationRead,
  markNotificationUnread,
  deleteNotification,
  markAllNotificationsRead,
  clearAllNotifications,
  getUnreadCount,
} from "../api/notifications"
import { apiClient } from "@/shared/api/client"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
  },
}))

describe("Notifications API", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("listNotifications calls GET /notifications", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({
      data: { items: [], total: 0, unread_count: 0, has_more: false },
    })
    const result = await listNotifications({ limit: 20, offset: 0 })
    expect(apiClient.get).toHaveBeenCalled()
    expect(result.total).toBe(0)
  })

  it("listNotifications builds query params correctly", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({
      data: { items: [], total: 0, unread_count: 0, has_more: false },
    })
    await listNotifications({ limit: 10, offset: 5, category: "security", unread_only: true, search: "test" })
    const callUrl = vi.mocked(apiClient.get).mock.calls[0][0] as string
    expect(callUrl).toContain("limit=10")
    expect(callUrl).toContain("offset=5")
    expect(callUrl).toContain("category=security")
    expect(callUrl).toContain("unread_only=true")
    expect(callUrl).toContain("search=test")
  })

  it("getNotification calls GET /notifications/:id", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { id: "n1", title: "Test" } })
    const result = await getNotification("n1")
    expect(apiClient.get).toHaveBeenCalledWith("/notifications/n1")
    expect(result.id).toBe("n1")
  })

  it("markNotificationRead calls PATCH /notifications/:id/read", async () => {
    vi.mocked(apiClient.patch).mockResolvedValue({ data: { id: "n1", read: true } })
    await markNotificationRead("n1")
    expect(apiClient.patch).toHaveBeenCalledWith("/notifications/n1/read")
  })

  it("markNotificationUnread calls PATCH /notifications/:id/unread", async () => {
    vi.mocked(apiClient.patch).mockResolvedValue({ data: { id: "n1", read: false } })
    await markNotificationUnread("n1")
    expect(apiClient.patch).toHaveBeenCalledWith("/notifications/n1/unread")
  })

  it("deleteNotification calls DELETE /notifications/:id", async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({})
    await deleteNotification("n1")
    expect(apiClient.delete).toHaveBeenCalledWith("/notifications/n1")
  })

  it("markAllNotificationsRead calls POST /notifications/read-all", async () => {
    vi.mocked(apiClient.post).mockResolvedValue({})
    await markAllNotificationsRead()
    expect(apiClient.post).toHaveBeenCalledWith("/notifications/read-all")
  })

  it("clearAllNotifications calls DELETE /notifications", async () => {
    vi.mocked(apiClient.delete).mockResolvedValue({})
    await clearAllNotifications()
    expect(apiClient.delete).toHaveBeenCalledWith("/notifications")
  })

  it("getUnreadCount calls GET /notifications/unread-count", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { count: 5 } })
    const result = await getUnreadCount()
    expect(apiClient.get).toHaveBeenCalledWith("/notifications/unread-count")
    expect(result.count).toBe(5)
  })
})
