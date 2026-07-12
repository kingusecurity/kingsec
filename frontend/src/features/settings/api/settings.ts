import { apiClient } from "@/shared/api/client"
import type { ProfileSettings, ApiKey, SystemInfo } from "../types"

export async function getProfileSettings(): Promise<ProfileSettings> {
  const response = await apiClient.get<ProfileSettings>("/auth/me")
  return response.data
}

export async function updateProfileSettings(data: ProfileSettings): Promise<ProfileSettings> {
  const response = await apiClient.patch<ProfileSettings>("/auth/me", data)
  return response.data
}

export async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
  await apiClient.post("/auth/change-password", {
    current_password: currentPassword,
    new_password: newPassword,
  })
}

export async function logoutAllSessions(): Promise<void> {
  await apiClient.post("/auth/logout-all")
}

export async function getActiveSessions(): Promise<Array<{ session_id: string; ip_address: string; user_agent: string; created_at: string; last_active: string }>> {
  const response = await apiClient.get("/auth/sessions")
  return response.data
}

export async function revokeSession(sessionId: string): Promise<void> {
  await apiClient.delete(`/auth/sessions/${sessionId}`)
}

export async function listApiKeys(): Promise<ApiKey[]> {
  const response = await apiClient.get<ApiKey[]>("/auth/api-keys")
  return response.data
}

export async function generateApiKey(name: string): Promise<ApiKey & { raw_key: string }> {
  const response = await apiClient.post<ApiKey & { raw_key: string }>("/auth/api-keys", { name })
  return response.data
}

export async function revokeApiKey(keyId: string): Promise<void> {
  await apiClient.delete(`/auth/api-keys/${keyId}`)
}

export async function getSystemInfo(): Promise<SystemInfo> {
  const response = await apiClient.get<SystemInfo>("/system/info")
  return response.data
}
