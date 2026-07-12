import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  exportToCSV,
  exportToJSON,
  exportKPIsToCSV,
  exportTrendsToCSV,
  exportAnalyticsToJSON,
} from "../lib/export"
import type { ExecutiveKPIs, TrendData, RiskAnalytics } from "../types"

describe("Analytics Export", () => {
  const clickSpy = vi.fn()
  const appendChildSpy = vi.fn()
  const removeChildSpy = vi.fn()
  const revokeObjectURLSpy = vi.fn()
  let createObjectURLSpy: ReturnType<typeof vi.fn>

  beforeEach(() => {
    vi.clearAllMocks()
    vi.spyOn(document, "createElement").mockImplementation(() => ({
      href: "",
      download: "",
      click: clickSpy,
      style: {},
    }))
    appendChildSpy.mockImplementation(() => {})
    removeChildSpy.mockImplementation(() => {})
    vi.spyOn(document.body, "appendChild").mockImplementation(appendChildSpy)
    vi.spyOn(document.body, "removeChild").mockImplementation(removeChildSpy)
    createObjectURLSpy = vi.fn(() => "blob:http://localhost/fake-url")
    vi.stubGlobal("URL", {
      createObjectURL: createObjectURLSpy,
      revokeObjectURL: revokeObjectURLSpy,
    })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it("exportToCSV generates correct CSV content", () => {
    const data = [
      { name: "test", value: 123 },
      { name: "test2", value: 456 },
    ]
    exportToCSV(data, "test-file")
    expect(document.createElement).toHaveBeenCalledWith("a")
    expect(appendChildSpy).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
    expect(removeChildSpy).toHaveBeenCalled()
  })

  it("exportToCSV handles empty data", () => {
    exportToCSV([], "empty-file")
    expect(document.createElement).not.toHaveBeenCalled()
  })

  it("exportToCSV escapes special characters", () => {
    const data = [{ name: 'has,comma', value: 1 }]
    exportToCSV(data, "escape-test")
    expect(document.createElement).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })

  it("exportToJSON generates valid JSON", () => {
    const data = { key: "value" }
    exportToJSON(data, "test-json")
    expect(document.createElement).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })

  it("exportKPIsToCSV exports KPI metrics", () => {
    const kpis: ExecutiveKPIs = {
      totalAssessments: 100,
      running: 5,
      completed: 80,
      failed: 10,
      cancelled: 5,
      criticalFindings: 15,
      highFindings: 25,
      reportsGenerated: 80,
      averageScanDuration: 300,
      successRate: 80,
      lastUpdated: "2025-01-01T00:00:00Z",
    }
    exportKPIsToCSV(kpis)
    expect(document.createElement).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })

  it("exportTrendsToCSV exports trend data", () => {
    const trends: TrendData[] = [
      { date: "2025-01-01", assessments: 5, findings: 10, reports: 3, failed: 1 },
      { date: "2025-01-02", assessments: 8, findings: 15, reports: 5, failed: 2 },
    ]
    exportTrendsToCSV(trends)
    expect(document.createElement).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })

  it("exportAnalyticsToJSON exports full analytics data", () => {
    const kpis: ExecutiveKPIs = {
      totalAssessments: 50,
      running: 2,
      completed: 40,
      failed: 5,
      cancelled: 3,
      criticalFindings: 8,
      highFindings: 12,
      reportsGenerated: 40,
      averageScanDuration: 250,
      successRate: 80,
      lastUpdated: "2025-01-01T00:00:00Z",
    }
    const trends: TrendData[] = [
      { date: "2025-01-01", assessments: 5, findings: 10, reports: 3, failed: 1 },
    ]
    const risk: RiskAnalytics = {
      severityDistribution: [],
      riskScore: 75,
      vulnerabilityDensity: 2.5,
      topTargets: [],
      topCategories: [],
    }
    exportAnalyticsToJSON(kpis, trends, risk)
    expect(document.createElement).toHaveBeenCalled()
    expect(clickSpy).toHaveBeenCalled()
  })
})
