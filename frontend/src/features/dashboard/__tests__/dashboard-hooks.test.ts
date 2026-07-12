import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock("sonner", () => ({
  toast: { success: vi.fn(), error: vi.fn() },
}))

import { dashboardKeys } from "../hooks/use-dashboard"
import { apiClient } from "@/shared/api/client"
import { renderHook, waitFor, act } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createElement, type ReactNode } from "react"
import { useDashboardKPIs } from "../hooks/use-dashboard"

const mockGet = vi.mocked(apiClient.get)

function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
}

function createWrapper(): { wrapper: React.FC<{ children: ReactNode }>; queryClient: QueryClient } {
  const queryClient = createTestQueryClient()
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client: queryClient }, children)
  return { wrapper, queryClient }
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe("dashboardKeys", () => {
  it("returns correct key structure", () => {
    expect(dashboardKeys.all).toEqual(["dashboard"])
    expect(dashboardKeys.kpis()).toEqual(["dashboard", "kpis"])
    expect(dashboardKeys.auditSummary()).toEqual(["dashboard", "auditSummary"])
    expect(dashboardKeys.health()).toEqual(["dashboard", "health"])
  })
})

describe("useDashboardKPIs", () => {
  it("computes KPIs from assessment list", async () => {
    const { wrapper } = createWrapper()

    mockGet.mockResolvedValue({
      data: {
        items: [
          { assessment_id: "1", target: "10.0.0.1", status: "COMPLETED", is_authorized: true, created_at: "2024-01-01T00:00:00Z", findings_count: 5 },
          { assessment_id: "2", target: "10.0.0.2", status: "RUNNING", is_authorized: true, created_at: "2024-01-02T00:00:00Z", findings_count: 0 },
          { assessment_id: "3", target: "10.0.0.3", status: "FAILED", is_authorized: true, created_at: "2024-01-03T00:00:00Z", findings_count: 2 },
          { assessment_id: "4", target: "10.0.0.4", status: "COMPLETED", is_authorized: true, created_at: "2024-01-03T00:00:00Z", findings_count: 3 },
        ],
        total: 4,
        limit: 500,
        offset: 0,
      },
    })

    const { result } = renderHook(() => useDashboardKPIs(), { wrapper })

    await waitFor(() => {
      expect(result.current.kpis).not.toBeNull()
    })

    expect(result.current.kpis?.totalAssessments).toBe(4)
    expect(result.current.kpis?.running).toBe(1)
    expect(result.current.kpis?.completed).toBe(2)
    expect(result.current.kpis?.failed).toBe(1)
  })

  it("computes status distribution", async () => {
    const { wrapper } = createWrapper()

    mockGet.mockResolvedValue({
      data: {
        items: [
          { assessment_id: "1", target: "a", status: "COMPLETED", is_authorized: true, created_at: "2024-01-01T00:00:00Z", findings_count: 0 },
          { assessment_id: "2", target: "b", status: "COMPLETED", is_authorized: true, created_at: "2024-01-01T00:00:00Z", findings_count: 0 },
          { assessment_id: "3", target: "c", status: "RUNNING", is_authorized: true, created_at: "2024-01-01T00:00:00Z", findings_count: 0 },
        ],
        total: 3,
        limit: 500,
        offset: 0,
      },
    })

    const { result } = renderHook(() => useDashboardKPIs(), { wrapper })

    await waitFor(() => {
      expect(result.current.statusDistribution.length).toBeGreaterThan(0)
    })

    const completed = result.current.statusDistribution.find((d) => d.name === "Completed")
    expect(completed?.value).toBe(2)
  })

  it("computes assessments over time", async () => {
    const { wrapper } = createWrapper()

    mockGet.mockResolvedValue({
      data: {
        items: [
          { assessment_id: "1", target: "a", status: "COMPLETED", is_authorized: true, created_at: "2024-01-15T10:00:00Z", findings_count: 0 },
          { assessment_id: "2", target: "b", status: "RUNNING", is_authorized: true, created_at: "2024-01-15T14:00:00Z", findings_count: 0 },
          { assessment_id: "3", target: "c", status: "FAILED", is_authorized: true, created_at: "2024-01-16T08:00:00Z", findings_count: 0 },
        ],
        total: 3,
        limit: 500,
        offset: 0,
      },
    })

    const { result } = renderHook(() => useDashboardKPIs(), { wrapper })

    await waitFor(() => {
      expect(result.current.assessmentsOverTime.length).toBe(2)
    })

    expect(result.current.assessmentsOverTime[0].count).toBe(2)
    expect(result.current.assessmentsOverTime[1].count).toBe(1)
  })
})
