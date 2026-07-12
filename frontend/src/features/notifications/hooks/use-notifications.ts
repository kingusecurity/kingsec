import { useCallback } from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  listNotifications,
  markNotificationRead,
  markNotificationUnread,
  deleteNotification,
  markAllNotificationsRead,
  clearAllNotifications,
} from "../api/notifications"
import { useNotificationStore } from "./use-notification-store"
import { getApiError } from "@/shared/api/error-handler"
import type { NotificationListParams } from "../types"

export const notificationKeys = {
  all: ["notifications"] as const,
  lists: () => [...notificationKeys.all, "list"] as const,
  list: (params?: NotificationListParams) => [...notificationKeys.lists(), params] as const,
  unreadCount: () => [...notificationKeys.all, "unread-count"] as const,
}

export function useNotificationList(params?: NotificationListParams) {
  const store = useNotificationStore()
  return useQuery({
    queryKey: notificationKeys.list(params),
    queryFn: () => listNotifications(params),
    placeholderData: (prev) => prev,
    onSuccess: (data) => {
      store.addNotifications(data.items)
      store.setTotal(data.total)
      store.setHasMore(data.has_more)
    },
  })
}

export function useMarkNotificationRead() {
  const queryClient = useQueryClient()
  const store = useNotificationStore()

  return useMutation({
    mutationFn: (id: string) => markNotificationRead(id),
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: notificationKeys.all })
      store.markRead(id)
      return { id }
    },
    onError: (err, id, context) => {
      if (context?.id) {
        store.markUnread(context.id)
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: notificationKeys.all })
    },
  })
}

export function useMarkNotificationUnread() {
  const queryClient = useQueryClient()
  const store = useNotificationStore()

  return useMutation({
    mutationFn: (id: string) => markNotificationUnread(id),
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: notificationKeys.all })
      store.markUnread(id)
      return { id }
    },
    onError: (err, id, context) => {
      if (context?.id) {
        store.markRead(context.id)
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: notificationKeys.all })
    },
  })
}

export function useDeleteNotification() {
  const queryClient = useQueryClient()
  const store = useNotificationStore()

  return useMutation({
    mutationFn: (id: string) => deleteNotification(id),
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: notificationKeys.all })
      const notification = store.notifications.find((n) => n.id === id)
      store.removeNotification(id)
      return { id, notification }
    },
    onError: (err, id, context) => {
      if (context?.notification) {
        store.addNotification(context.notification)
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: notificationKeys.all })
    },
  })
}

export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient()
  const store = useNotificationStore()

  return useMutation({
    mutationFn: () => markAllNotificationsRead(),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: notificationKeys.all })
      store.markAllRead()
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: notificationKeys.all })
    },
  })
}

export function useClearAllNotifications() {
  const queryClient = useQueryClient()
  const store = useNotificationStore()

  return useMutation({
    mutationFn: () => clearAllNotifications(),
    onMutate: async () => {
      await queryClient.cancelQueries({ queryKey: notificationKeys.all })
      const previous = store.notifications
      store.clearAll()
      return { previous }
    },
    onError: (err, _vars, context) => {
      if (context?.previous) {
        context.previous.forEach((n) => store.addNotification(n))
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: notificationKeys.all })
    },
  })
}

export function useNotificationActions() {
  const markRead = useMarkNotificationRead()
  const markUnread = useMarkNotificationUnread()
  const deleteNotification = useDeleteNotification()
  const markAllRead = useMarkAllNotificationsRead()
  const clearAll = useClearAllNotifications()

  const isLoading = markRead.isPending || markUnread.isPending || deleteNotification.isPending

  return {
    markRead: markRead.mutate,
    markUnread: markUnread.mutate,
    deleteNotification: deleteNotification.mutate,
    markAllRead: markAllRead.mutate,
    clearAll: clearAll.mutate,
    isLoading,
  }
}
