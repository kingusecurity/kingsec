import { apiClient } from "@/shared/api/client"

export async function fetchAuditSummary(limit = 100): Promise<{
  items: Array<{
    action: string
    resource_type: string
    success: boolean
    timestamp: string
    username: string
  }>
  total: number
}> {
  const { data } = await apiClient.get(`/audit?limit=${limit}&offset=0`)
  return data
}

export async function fetchHealth(): Promise<{ status: string }> {
  const { data } = await apiClient.get("/health")
  return data
}

export async function fetchUsers(): Promise<{
  items: Array<{
    user_id: string
    username: string
    role: string
    is_active: boolean
  }>
  total: number
}> {
  const { data } = await apiClient.get("/auth/users?limit=100&offset=0")
  return data
}
