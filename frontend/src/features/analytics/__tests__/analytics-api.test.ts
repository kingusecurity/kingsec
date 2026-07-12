import { describe, it, expect, vi, beforeEach } from "vitest"
import { fetchAuditSummary, fetchHealth, fetchUsers } from "../api/analytics"
import { apiClient } from "@/shared/api/client"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
  },
}))

describe("Analytics API", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("fetchAuditSummary calls GET /audit", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { items: [], total: 0 } })
    const result = await fetchAuditSummary(50)
    expect(apiClient.get).toHaveBeenCalledWith("/audit?limit=50&offset=0")
    expect(result.total).toBe(0)
  })

  it("fetchHealth calls GET /health", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { status: "healthy" } })
    const result = await fetchHealth()
    expect(apiClient.get).toHaveBeenCalledWith("/health")
    expect(result.status).toBe("healthy")
  })

  it("fetchUsers calls GET /auth/users", async () => {
    vi.mocked(apiClient.get).mockResolvedValue({ data: { items: [], total: 0 } })
    const result = await fetchUsers()
    expect(apiClient.get).toHaveBeenCalledWith("/auth/users?limit=100&offset=0")
    expect(result.total).toBe(0)
  })
})
