import { apiRequest } from './client'

export interface Notification {
  id: string
  title: string
  message?: string
  type: string
  severity: string
  read: boolean
  created_at: string
  assessment_id?: string
}

export interface NotificationListResponse {
  items: Notification[]
  total: number
}

export const notificationsApi = {
  list: (params?: { limit?: number; offset?: number; read?: boolean }) =>
    apiRequest<NotificationListResponse>('/notifications', { params }),

  get: (id: string) =>
    apiRequest<Notification>('/notifications/' + id),

  markRead: (id: string) =>
    apiRequest<void>('/notifications/' + id + '/read', { method: 'POST' }),

  delete: (id: string) =>
    apiRequest<void>('/notifications/' + id, { method: 'DELETE' }),
}
