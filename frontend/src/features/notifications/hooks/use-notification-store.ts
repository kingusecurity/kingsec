import { create } from "zustand"
import { persist } from "zustand/middleware"
import type { Notification, NotificationFilter } from "../types"

interface NotificationState {
  notifications: Notification[]
  filter: NotificationFilter
  search: string
  panelOpen: boolean
  hasMore: boolean
  total: number
}

interface NotificationActions {
  addNotification: (notification: Notification) => void
  addNotifications: (notifications: Notification[]) => void
  markRead: (id: string) => void
  markUnread: (id: string) => void
  markAllRead: () => void
  removeNotification: (id: string) => void
  clearAll: () => void
  setFilter: (filter: NotificationFilter) => void
  setSearch: (search: string) => void
  setPanelOpen: (open: boolean) => void
  togglePanel: () => void
  setHasMore: (hasMore: boolean) => void
  setTotal: (total: number) => void
}

function matchesFilter(notification: Notification, filter: NotificationFilter): boolean {
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

export const useNotificationStore = create<NotificationState & NotificationActions>()(
  persist(
    (set) => ({
      notifications: [],
      filter: "all",
      search: "",
      panelOpen: false,
      hasMore: false,
      total: 0,

      addNotification: (notification) =>
        set((state) => ({
          notifications: [notification, ...state.notifications].slice(0, 500),
          total: state.total + 1,
        })),

      addNotifications: (notifications) =>
        set((state) => {
          const existingIds = new Set(state.notifications.map((n) => n.id))
          const batchIds = new Set<string>()
          const newOnes = notifications.filter((n) => {
            if (existingIds.has(n.id) || batchIds.has(n.id)) return false
            batchIds.add(n.id)
            return true
          })
          return {
            notifications: [...newOnes, ...state.notifications].slice(0, 500),
            total: state.total + newOnes.length,
          }
        }),

      markRead: (id) =>
        set((state) => ({
          notifications: state.notifications.map((n) =>
            n.id === id ? { ...n, read: true } : n,
          ),
        })),

      markUnread: (id) =>
        set((state) => ({
          notifications: state.notifications.map((n) =>
            n.id === id ? { ...n, read: false } : n,
          ),
        })),

      markAllRead: () =>
        set((state) => ({
          notifications: state.notifications.map((n) => ({ ...n, read: true })),
        })),

      removeNotification: (id) =>
        set((state) => ({
          notifications: state.notifications.filter((n) => n.id !== id),
          total: Math.max(0, state.total - 1),
        })),

      clearAll: () => set({ notifications: [], total: 0 }),

      setFilter: (filter) => set({ filter }),

      setSearch: (search) => set({ search }),

      setPanelOpen: (panelOpen) => set({ panelOpen }),

      togglePanel: () => set((state) => ({ panelOpen: !state.panelOpen })),

      setHasMore: (hasMore) => set({ hasMore }),

      setTotal: (total) => set({ total }),
    }),
    {
      name: "kingsec-notifications",
      partialize: (state) => ({
        notifications: state.notifications,
        total: state.total,
      }),
    },
  ),
)

export function selectUnreadCount(state: NotificationState): number {
  return state.notifications.filter((n) => !n.read).length
}

export function selectFilteredNotifications(state: NotificationState): Notification[] {
  return state.notifications
    .filter((n) => matchesFilter(n, state.filter))
    .filter((n) => matchesSearch(n, state.search))
}
