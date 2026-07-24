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

export const notificationsApi = {
  list: (params?: { limit?: number; offset?: number }) =>
    apiRequest<NotificationListResponse>('/notifications', { params }),

  get: (id: string) =>
    apiRequest<Notification>('/notifications/' + id),

  markRead: (id: string) =>
    apiRequest<void>('/notifications/' + id + '/read', { method: 'POST' }),

  delete: (id: string) =>
    apiRequest<void>('/notifications/' + id, { method: 'DELETE' }),
}
