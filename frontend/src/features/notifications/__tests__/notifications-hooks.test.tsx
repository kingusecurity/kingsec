import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, waitFor, act } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import {
  useNotificationList,
  useMarkNotificationRead,
  useMarkNotificationUnread,
  useDeleteNotification,
  useMarkAllNotificationsRead,
  useClearAllNotifications,
  notificationKeys,
} from "../hooks/use-notifications"
import { useNotificationStore } from "../hooks/use-notification-store"
import * as notificationsApi from "../api/notifications"
import type { ReactNode } from "react"

vi.mock("../api/notifications", () => ({
  listNotifications: vi.fn(),
  markNotificationRead: vi.fn(),
  markNotificationUnread: vi.fn(),
  deleteNotification: vi.fn(),
  markAllNotificationsRead: vi.fn(),
  clearAllNotifications: vi.fn(),
  getUnreadCount: vi.fn(),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

describe("Notification hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    useNotificationStore.setState({
      notifications: [],
      filter: "all",
      search: "",
      panelOpen: false,
      hasMore: false,
      total: 0,
    })
  })

  describe("notificationKeys", () => {
    it("generates correct cache keys", () => {
      expect(notificationKeys.all).toEqual(["notifications"])
      expect(notificationKeys.lists()).toEqual(["notifications", "list"])
      expect(notificationKeys.list({ limit: 10 })).toEqual(["notifications", "list", { limit: 10 }])
      expect(notificationKeys.unreadCount()).toEqual(["notifications", "unread-count"])
    })
  })

  describe("useNotificationList", () => {
    it("fetches notifications and syncs to store", async () => {
      const notifications = [
        { id: "n1", title: "Test", read: false },
        { id: "n2", title: "Test 2", read: true },
      ]
      vi.mocked(notificationsApi.listNotifications).mockResolvedValue({
        items: notifications as any,
        total: 2,
        unread_count: 1,
        has_more: false,
      })
      const { result } = renderHook(() => useNotificationList(), { wrapper: createWrapper() })
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(result.current.data?.items).toHaveLength(2)
    })
  })

  describe("useMarkNotificationRead", () => {
    it("optimistically marks as read", async () => {
      vi.mocked(notificationsApi.markNotificationRead).mockResolvedValue({} as any)
      useNotificationStore.setState({
        notifications: [{ id: "n1", read: false } as any],
      })
      const { result } = renderHook(() => useMarkNotificationRead(), { wrapper: createWrapper() })
      act(() => result.current.mutate("n1"))
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(useNotificationStore.getState().notifications[0].read).toBe(true)
    })
  })

  describe("useMarkNotificationUnread", () => {
    it("optimistically marks as unread", async () => {
      vi.mocked(notificationsApi.markNotificationUnread).mockResolvedValue({} as any)
      useNotificationStore.setState({
        notifications: [{ id: "n1", read: true } as any],
      })
      const { result } = renderHook(() => useMarkNotificationUnread(), { wrapper: createWrapper() })
      act(() => result.current.mutate("n1"))
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(useNotificationStore.getState().notifications[0].read).toBe(false)
    })
  })

  describe("useDeleteNotification", () => {
    it("optimistically removes notification", async () => {
      vi.mocked(notificationsApi.deleteNotification).mockResolvedValue(undefined)
      useNotificationStore.setState({
        notifications: [{ id: "n1", read: false } as any, { id: "n2", read: true } as any],
      })
      const { result } = renderHook(() => useDeleteNotification(), { wrapper: createWrapper() })
      act(() => result.current.mutate("n1"))
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(useNotificationStore.getState().notifications).toHaveLength(1)
      expect(useNotificationStore.getState().notifications[0].id).toBe("n2")
    })
  })

  describe("useMarkAllNotificationsRead", () => {
    it("optimistically marks all as read", async () => {
      vi.mocked(notificationsApi.markAllNotificationsRead).mockResolvedValue(undefined)
      useNotificationStore.setState({
        notifications: [
          { id: "n1", read: false } as any,
          { id: "n2", read: false } as any,
        ],
      })
      const { result } = renderHook(() => useMarkAllNotificationsRead(), { wrapper: createWrapper() })
      act(() => result.current.mutate())
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(useNotificationStore.getState().notifications.every((n) => n.read)).toBe(true)
    })
  })

  describe("useClearAllNotifications", () => {
    it("optimistically clears all notifications", async () => {
      vi.mocked(notificationsApi.clearAllNotifications).mockResolvedValue(undefined)
      useNotificationStore.setState({
        notifications: [
          { id: "n1", read: false } as any,
          { id: "n2", read: true } as any,
        ],
      })
      const { result } = renderHook(() => useClearAllNotifications(), { wrapper: createWrapper() })
      act(() => result.current.mutate())
      await waitFor(() => expect(result.current.isSuccess).toBe(true))
      expect(useNotificationStore.getState().notifications).toHaveLength(0)
    })
  })
})
