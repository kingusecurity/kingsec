import { apiClient } from "@/shared/api/client"
import type { AuditSummaryEntry } from "../types"

export async function fetchAuditSummary(): Promise<{ items: AuditSummaryEntry[]; total: number }> {
  const response = await apiClient.get("/audit", { params: { limit: 20, offset: 0 } })
  return response.data
}

export async function fetchHealth(): Promise<{ status: string }> {
  const response = await apiClient.get("/health")
  return response.data
}
