import { apiClient } from "@/shared/api/client"
import type {
  NotificationListParams,
  NotificationListResponse,
  Notification,
} from "../types"

function buildQueryString(params: NotificationListParams): string {
  const qs = new URLSearchParams()
  if (params.limit) qs.set("limit", String(params.limit))
  if (params.offset) qs.set("offset", String(params.offset))
  if (params.category) qs.set("category", params.category)
  if (params.unread_only) qs.set("unread_only", "true")
  if (params.search) qs.set("search", params.search)
  return qs.toString()
}

export async function listNotifications(params?: NotificationListParams): Promise<NotificationListResponse> {
  const qs = buildQueryString(params ?? {})
  const { data } = await apiClient.get(`/notifications${qs ? `?${qs}` : ""}`)
  return data
}

export async function getNotification(id: string): Promise<Notification> {
  const { data } = await apiClient.get(`/notifications/${id}`)
  return data
}

export async function markNotificationRead(id: string): Promise<Notification> {
  const { data } = await apiClient.patch(`/notifications/${id}/read`)
  return data
}

export async function markNotificationUnread(id: string): Promise<Notification> {
  const { data } = await apiClient.patch(`/notifications/${id}/unread`)
  return data
}

export async function deleteNotification(id: string): Promise<void> {
  await apiClient.delete(`/notifications/${id}`)
}

export async function markAllNotificationsRead(): Promise<void> {
  await apiClient.post("/notifications/read-all")
}

export async function clearAllNotifications(): Promise<void> {
  await apiClient.delete("/notifications")
}

export async function getUnreadCount(): Promise<{ count: number }> {
  const { data } = await apiClient.get("/notifications/unread-count")
  return data
}
