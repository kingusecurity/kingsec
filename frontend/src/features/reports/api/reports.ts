import { apiClient } from "@/shared/api/client"
import type { ReportData } from "../types"

export async function generateReport(assessmentId: string): Promise<ReportData> {
  const response = await apiClient.post<ReportData>(`/assessments/${assessmentId}/report`)
  return response.data
}

export async function downloadReportBlob(assessmentId: string, filename: string, mediaType: string): Promise<void> {
  const response = await apiClient.get(`/assessments/${assessmentId}/report`, {
    responseType: "blob",
  })
  const blob = new Blob([response.data], { type: mediaType })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

export async function getReportViewUrl(assessmentId: string): Promise<string> {
  const baseUrl = apiClient.defaults.baseURL ?? ""
  return `${baseUrl}/assessments/${assessmentId}/report`
}
