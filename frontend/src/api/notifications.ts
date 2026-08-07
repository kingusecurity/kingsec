import { apiRequest } from './client'

export interface Notification {
  id: string
  user_id: string
  title: string
  message: string
  channel: string
  status: string
  priority: string
  event_type: string
  retry_count: number
  max_retries: number
  created_at: string
  updated_at: string
  read_at: string | null
  error_message: string | null
}

export interface NotificationListResponse {
  notifications: Notification[]
  total: number
  limit: number
  offset: number
}

export type NotificationListParams = Record<string, string | number | boolean | undefined | null> & {
  limit?: number
  offset?: number
  read?: boolean
  channel?: string
  priority?: string
  status?: string
}

export const notificationsApi = {
  list: (params?: NotificationListParams) =>
    apiRequest<NotificationListResponse>('/notifications', { params }),

  get: (id: string) =>
    apiRequest<Notification>('/notifications/' + id),

  markRead: (id: string) =>
    apiRequest<void>('/notifications/' + id + '/read', { method: 'POST' }),

  markAllRead: () =>
    apiRequest<{ marked_read: number }>('/notifications/mark-all-read', { method: 'POST' }),

  delete: (id: string) =>
    apiRequest<void>('/notifications/' + id, { method: 'DELETE' }),
}
