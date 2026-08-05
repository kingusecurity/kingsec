import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { notificationsApi } from '@/api/notifications'
import type { NotificationListParams } from '@/api/notifications'
import { toast } from '@/components/ui/Toast'

export function useNotifications(params?: NotificationListParams) {
  return useQuery({
    queryKey: ['notifications', params],
    queryFn: () => notificationsApi.list(params),
  })
}

export function useNotification(id: string) {
  return useQuery({
    queryKey: ['notifications', id],
    queryFn: () => notificationsApi.get(id),
    enabled: !!id,
  })
}

export function useMarkNotificationRead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => notificationsApi.markRead(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
    },
  })
}

export function useMarkAllNotificationsRead() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: () => notificationsApi.markAllRead(),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
      toast.success(
        'Notifications marked as read',
        result.marked_read === 1 ? '1 notification marked as read' : `${result.marked_read} notifications marked as read`,
      )
    },
  })
}

export function useDeleteNotification() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (id: string) => notificationsApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] })
    },
  })
}
