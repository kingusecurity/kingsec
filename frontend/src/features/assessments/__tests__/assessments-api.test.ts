import { describe, it, expect, vi, beforeEach } from "vitest"
import {
  listAssessments,
  getAssessment,
  createAssessment,
  startAssessment,
  cancelAssessment,
  deleteAssessment,
  generateReport,
} from "../api/assessments"

vi.mock("@/shared/api/client", () => ({
  apiClient: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}))

import { apiClient } from "@/shared/api/client"

const mockGet = vi.mocked(apiClient.get)
const mockPost = vi.mocked(apiClient.post)
const mockDelete = vi.mocked(apiClient.delete)

beforeEach(() => {
  vi.clearAllMocks()
})

describe("assessment API", () => {
  describe("listAssessments", () => {
    it("calls GET /assessments with default params", async () => {
      const mockData = { items: [], total: 0, limit: 50, offset: 0 }
      mockGet.mockResolvedValue({ data: mockData })

      const result = await listAssessments()

      expect(mockGet).toHaveBeenCalledWith("/assessments", { params: { limit: 50, offset: 0 } })
      expect(result).toEqual(mockData)
    })

    it("passes custom limit and offset", async () => {
      mockGet.mockResolvedValue({ data: { items: [], total: 10, limit: 10, offset: 10 } })

      await listAssessments({ limit: 10, offset: 10 })

      expect(mockGet).toHaveBeenCalledWith("/assessments", { params: { limit: 10, offset: 10 } })
    })
  })

  describe("getAssessment", () => {
    it("calls GET /assessments/:id", async () => {
      const mockDetail = { assessment_id: "abc-123", target: "10.0.0.1", status: "COMPLETED", is_authorized: true, created_at: "2024-01-01T00:00:00Z", findings: [] }
      mockGet.mockResolvedValue({ data: mockDetail })

      const result = await getAssessment("abc-123")

      expect(mockGet).toHaveBeenCalledWith("/assessments/abc-123")
      expect(result).toEqual(mockDetail)
    })
  })

  describe("createAssessment", () => {
    it("calls POST /assessments with body", async () => {
      const body = { target_value: "10.0.0.1", target_type: "ip_address", authorized_by: "admin", scope: "internal" }
      const mockResp = { assessment_id: "new-123", status: "CREATED", target: "10.0.0.1" }
      mockPost.mockResolvedValue({ data: mockResp })

      const result = await createAssessment(body)

      expect(mockPost).toHaveBeenCalledWith("/assessments", body)
      expect(result).toEqual(mockResp)
    })
  })

  describe("startAssessment", () => {
    it("calls POST /assessments/:id/start", async () => {
      mockPost.mockResolvedValue({ data: { assessment_id: "abc-123", status: "RUNNING", job_id: "job-1" } })

      const result = await startAssessment("abc-123")

      expect(mockPost).toHaveBeenCalledWith("/assessments/abc-123/start")
      expect(result.status).toBe("RUNNING")
    })
  })

  describe("cancelAssessment", () => {
    it("calls POST /assessments/:id/cancel", async () => {
      mockPost.mockResolvedValue({ data: { assessment_id: "abc-123", status: "CANCELLED" } })

      const result = await cancelAssessment("abc-123")

      expect(mockPost).toHaveBeenCalledWith("/assessments/abc-123/cancel")
      expect(result.status).toBe("CANCELLED")
    })
  })

  describe("deleteAssessment", () => {
    it("calls DELETE /assessments/:id", async () => {
      mockDelete.mockResolvedValue({ data: null })

      await deleteAssessment("abc-123")

      expect(mockDelete).toHaveBeenCalledWith("/assessments/abc-123")
    })
  })

  describe("generateReport", () => {
    it("calls POST /assessments/:id/report", async () => {
      const mockReport = {
        assessment_id: "abc-123",
        verdict: "pass",
        action_required: false,
        highest_severity: null,
        total_findings: 0,
        severity_counts: [],
        artifact_media_type: "application/pdf",
        artifact_filename: "report.pdf",
        artifact_bytes: 100,
      }
      mockPost.mockResolvedValue({ data: mockReport })

      const result = await generateReport("abc-123")

      expect(mockPost).toHaveBeenCalledWith("/assessments/abc-123/report")
      expect(result.artifact_filename).toBe("report.pdf")
    })
  })
})
