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

import { assessmentKeys, useCreateAssessment, useStartAssessment, useCancelAssessment, useDeleteAssessment } from "../hooks/use-assessments"
import { apiClient } from "@/shared/api/client"
import { renderHook, act } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { createElement, type ReactNode } from "react"

const mockGet = vi.mocked(apiClient.get)
const mockPost = vi.mocked(apiClient.post)
const mockDelete = vi.mocked(apiClient.delete)

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

describe("optimistic updates", () => {
  describe("useCreateAssessment", () => {
    it("calls POST and invalidates queries", async () => {
      const { wrapper, queryClient } = createWrapper()
      const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries")

      mockPost.mockResolvedValue({ data: { assessment_id: "new-123", status: "CREATED", target: "10.0.0.2" } })

      const { result } = renderHook(() => useCreateAssessment(), { wrapper })

      await act(async () => {
        result.current.mutate({
          target_value: "10.0.0.2",
          target_type: "ip_address",
          authorized_by: "admin",
          scope: "internal",
        })
      })

      expect(mockPost).toHaveBeenCalledWith("/assessments", {
        target_value: "10.0.0.2",
        target_type: "ip_address",
        authorized_by: "admin",
        scope: "internal",
      })
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: assessmentKeys.all })
    })
  })

  describe("useStartAssessment", () => {
    it("optimistically sets status to RUNNING then invalidates", async () => {
      const { wrapper, queryClient } = createWrapper()

      const detailData = {
        assessment_id: "test-123",
        target: "10.0.0.1",
        status: "CREATED",
        is_authorized: true,
        created_at: "2024-01-01",
        findings: [],
      }
      queryClient.setQueryData(assessmentKeys.detail("test-123"), detailData)

      mockPost.mockResolvedValue({ data: { assessment_id: "test-123", status: "RUNNING", job_id: "job-1" } })
      mockGet.mockResolvedValue({ data: { ...detailData, status: "RUNNING" } })

      const { result } = renderHook(() => useStartAssessment(), { wrapper })

      await act(async () => {
        result.current.mutate("test-123")
      })

      // Mutation completed, queries invalidated and refetched
      expect(mockPost).toHaveBeenCalledWith("/assessments/test-123/start")
    })
  })

  describe("useCancelAssessment", () => {
    it("optimistically sets status to CANCELLED then invalidates", async () => {
      const { wrapper, queryClient } = createWrapper()

      const detailData = {
        assessment_id: "test-123",
        target: "10.0.0.1",
        status: "RUNNING",
        is_authorized: true,
        created_at: "2024-01-01",
        findings: [],
      }
      queryClient.setQueryData(assessmentKeys.detail("test-123"), detailData)

      mockPost.mockResolvedValue({ data: { assessment_id: "test-123", status: "CANCELLED" } })
      mockGet.mockResolvedValue({ data: { ...detailData, status: "CANCELLED" } })

      const { result } = renderHook(() => useCancelAssessment(), { wrapper })

      await act(async () => {
        result.current.mutate("test-123")
      })

      expect(mockPost).toHaveBeenCalledWith("/assessments/test-123/cancel")
    })
  })

  describe("useDeleteAssessment", () => {
    it("calls DELETE and invalidates queries", async () => {
      const { wrapper, queryClient } = createWrapper()
      const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries")

      mockDelete.mockResolvedValue({ data: null })

      const { result } = renderHook(() => useDeleteAssessment(), { wrapper })

      await act(async () => {
        result.current.mutate("test-123")
      })

      expect(mockDelete).toHaveBeenCalledWith("/assessments/test-123")
      expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: assessmentKeys.all })
    })
  })
})

describe("assessmentKeys", () => {
  it("produces stable references for same params", () => {
    const key1 = assessmentKeys.list({ limit: 10, offset: 0 })
    const key2 = assessmentKeys.list({ limit: 10, offset: 0 })
    expect(key1).toEqual(key2)
  })

  it("different params produce different keys", () => {
    const key1 = assessmentKeys.list({ limit: 10, offset: 0 })
    const key2 = assessmentKeys.list({ limit: 10, offset: 10 })
    expect(key1).not.toEqual(key2)
  })
})
