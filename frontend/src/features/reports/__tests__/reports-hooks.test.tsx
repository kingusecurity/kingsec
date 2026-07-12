import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, waitFor } from "@testing-library/react"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { useGenerateReport, useDownloadReport, reportKeys } from "../hooks/use-reports"
import * as reportsApi from "../api/reports"
import type { ReactNode } from "react"

vi.mock("../api/reports", () => ({
  generateReport: vi.fn(),
  downloadReportBlob: vi.fn(),
}))

function createWrapper() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
}

describe("Report hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe("reportKeys", () => {
    it("generates correct cache keys", () => {
      expect(reportKeys.all).toEqual(["reports"])
      expect(reportKeys.byAssessment("abc")).toEqual(["reports", "abc"])
    })
  })

  describe("useGenerateReport", () => {
    it("calls generateReport and returns data", async () => {
      const mockData = {
        assessment_id: "test-id",
        verdict: "pass",
        action_required: false,
        highest_severity: null,
        total_findings: 0,
        severity_counts: [],
        artifact_media_type: "application/pdf",
        artifact_filename: "report.pdf",
        artifact_bytes: 512,
      }
      vi.mocked(reportsApi.generateReport).mockResolvedValue(mockData as any)

      const { result } = renderHook(() => useGenerateReport(), { wrapper: createWrapper() })

      result.current.mutate("test-id")

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true)
      })

      expect(reportsApi.generateReport).toHaveBeenCalledWith("test-id")
      expect(result.current.data?.assessment_id).toBe("test-id")
    })

    it("handles errors", async () => {
      vi.mocked(reportsApi.generateReport).mockRejectedValue(new Error("Not found"))

      const { result } = renderHook(() => useGenerateReport(), { wrapper: createWrapper() })

      result.current.mutate("bad-id")

      await waitFor(() => {
        expect(result.current.isError).toBe(true)
      })
    })
  })

  describe("useDownloadReport", () => {
    it("calls downloadReportBlob", async () => {
      vi.mocked(reportsApi.downloadReportBlob).mockResolvedValue(undefined)

      const { result } = renderHook(() => useDownloadReport(), { wrapper: createWrapper() })

      result.current.mutate({
        assessmentId: "test-id",
        filename: "report.pdf",
        mediaType: "application/pdf",
      })

      await waitFor(() => {
        expect(result.current.isSuccess).toBe(true)
      })

      expect(reportsApi.downloadReportBlob).toHaveBeenCalledWith("test-id", "report.pdf", "application/pdf")
    })
  })
})
