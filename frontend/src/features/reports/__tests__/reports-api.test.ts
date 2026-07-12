import { describe, it, expect, vi, beforeEach } from "vitest"
import {
  generateReport,
  downloadReportBlob,
  getReportViewUrl,
} from "../api/reports"
import { apiClient } from "@/shared/api/client"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    post: vi.fn(),
    get: vi.fn(),
    defaults: { baseURL: "" },
  },
}))

describe("Reports API", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe("generateReport", () => {
    it("calls POST /assessments/:id/report", async () => {
      const mockResponse = {
        data: {
          report_id: "rpt-001",
          assessment_id: "test-id",
          verdict: "fail",
          action_required: true,
          highest_severity: "HIGH",
          total_findings: 3,
          severity_counts: [{ severity: "HIGH", count: 2 }, { severity: "MEDIUM", count: 1 }],
          artifact_media_type: "application/pdf",
          artifact_filename: "report.pdf",
          artifact_bytes: 1024,
          generated_at: "2025-01-01T00:00:00Z",
          generated_by: "admin",
          report_version: 1,
          sha256_checksum: "abc123",
        },
      }
      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await generateReport("test-id")

      expect(apiClient.post).toHaveBeenCalledWith("/assessments/test-id/report")
      expect(result.report_id).toBe("rpt-001")
      expect(result.assessment_id).toBe("test-id")
      expect(result.verdict).toBe("fail")
      expect(result.generated_by).toBe("admin")
      expect(result.sha256_checksum).toBe("abc123")
    })
  })

  describe("downloadReportBlob", () => {
    it("creates blob URL and triggers download", async () => {
      const mockData = new ArrayBuffer(1024)
      vi.mocked(apiClient.get).mockResolvedValue({ data: mockData })

      const mockAnchor = { href: "", download: "", click: vi.fn() }
      const createElementSpy = vi.spyOn(document, "createElement").mockReturnValue(mockAnchor as unknown as HTMLAnchorElement)
      const appendChildSpy = vi.spyOn(document.body, "appendChild").mockImplementation(() => mockAnchor as unknown as Node)
      const removeChildSpy = vi.spyOn(document.body, "removeChild").mockImplementation(() => mockAnchor as unknown as Node)

      await downloadReportBlob("test-id", "report.pdf", "application/pdf")

      expect(apiClient.get).toHaveBeenCalledWith("/assessments/test-id/report", {
        responseType: "blob",
        onDownloadProgress: expect.any(Function),
      })
      expect(mockAnchor.download).toBe("report.pdf")
      expect(mockAnchor.click).toHaveBeenCalled()

      createElementSpy.mockRestore()
      appendChildSpy.mockRestore()
      removeChildSpy.mockRestore()
    })

    it("calls onDownloadProgress during download", async () => {
      const mockData = new ArrayBuffer(1024)
      vi.mocked(apiClient.get).mockImplementation((_url, config: any) => {
        if (config?.onDownloadProgress) {
          config.onDownloadProgress({ loaded: 512, total: 1024 })
          config.onDownloadProgress({ loaded: 1024, total: 1024 })
        }
        return Promise.resolve({ data: mockData })
      })

      const onProgress = vi.fn()
      const mockAnchor = { href: "", download: "", click: vi.fn() }
      vi.spyOn(document, "createElement").mockReturnValue(mockAnchor as unknown as HTMLAnchorElement)
      vi.spyOn(document.body, "appendChild").mockImplementation(() => mockAnchor as unknown as Node)
      vi.spyOn(document.body, "removeChild").mockImplementation(() => mockAnchor as unknown as Node)

      await downloadReportBlob("test-id", "report.pdf", "application/pdf", onProgress)

      expect(onProgress).toHaveBeenCalledWith({ loaded: 512, total: 1024, percent: 50 })
      expect(onProgress).toHaveBeenCalledWith({ loaded: 1024, total: 1024, percent: 100 })
    })
  })

  describe("getReportViewUrl", () => {
    it("returns correct view URL", () => {
      const url = getReportViewUrl("test-id")
      expect(url).toBe("/assessments/test-id/report")
    })
  })
})
