import { apiClient } from "@/shared/api/client"
import type { User, CreateUserRequest, UpdateUserRequest, ResetPasswordRequest, UserSession, UserAuditEntry } from "../types"

export async function listUsers(params?: { limit?: number; offset?: number }): Promise<{ items: User[]; total: number }> {
  const response = await apiClient.get<{ items: User[]; total: number }>("/auth/users", { params })
  return response.data
}

export async function getUser(userId: string): Promise<User> {
  const response = await apiClient.get<User>(`/auth/users/${userId}`)
  return response.data
}

export async function createUser(data: CreateUserRequest): Promise<User> {
  const response = await apiClient.post<User>("/auth/users", data)
  return response.data
}

export async function updateUser(userId: string, data: UpdateUserRequest): Promise<User> {
  const response = await apiClient.patch<User>(`/auth/users/${userId}`, data)
  return response.data
}

export async function deleteUser(userId: string): Promise<void> {
  await apiClient.delete(`/auth/users/${userId}`)
}

export async function resetPassword(userId: string, data: ResetPasswordRequest): Promise<void> {
  await apiClient.post(`/auth/users/${userId}/reset-password`, data)
}

export async function getUserSessions(userId: string): Promise<UserSession[]> {
  const response = await apiClient.get<UserSession[]>(`/auth/users/${userId}/sessions`)
  return response.data
}

export async function revokeSession(userId: string, sessionId: string): Promise<void> {
  await apiClient.delete(`/auth/users/${userId}/sessions/${sessionId}`)
}

export async function getUserAuditEntries(userId: string, params?: { limit?: number; offset?: number }): Promise<{ items: UserAuditEntry[]; total: number }> {
  const response = await apiClient.get<{ items: UserAuditEntry[]; total: number }>(`/auth/users/${userId}/audit`, { params })
  return response.data
}
