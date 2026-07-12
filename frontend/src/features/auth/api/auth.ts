import { apiClient } from "@/shared/api/client"
import type { AuthRequest, AuthResponse, User } from "../types"

export async function loginApi(data: AuthRequest): Promise<AuthResponse> {
  const formData = new URLSearchParams()
  formData.append("username", data.username)
  formData.append("password", data.password)

  const response = await apiClient.post<AuthResponse>("/auth/login", formData, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  })
  return response.data
}

export async function getMeApi(): Promise<User> {
  const response = await apiClient.get<User>("/auth/me")
  return response.data
}

export async function refreshTokenApi(refreshToken: string): Promise<AuthResponse> {
  const response = await apiClient.post<AuthResponse>("/auth/refresh", {
    refresh_token: refreshToken,
  })
  return response.data
}
