import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
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
        },
      }
      vi.mocked(apiClient.post).mockResolvedValue(mockResponse)

      const result = await generateReport("test-id")

      expect(apiClient.post).toHaveBeenCalledWith("/assessments/test-id/report")
      expect(result.assessment_id).toBe("test-id")
      expect(result.verdict).toBe("fail")
      expect(result.total_findings).toBe(3)
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
      })
      expect(mockAnchor.download).toBe("report.pdf")
      expect(mockAnchor.click).toHaveBeenCalled()

      createElementSpy.mockRestore()
      appendChildSpy.mockRestore()
      removeChildSpy.mockRestore()
    })
  })

  describe("getReportViewUrl", () => {
    it("returns correct view URL", async () => {
      const url = await getReportViewUrl("test-id")
      expect(url).toBe("/assessments/test-id/report")
    })
  })
})
