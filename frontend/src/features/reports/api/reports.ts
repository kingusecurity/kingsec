import { apiClient } from "@/shared/api/client"
import type { ReportData, DownloadProgress } from "../types"

export async function generateReport(assessmentId: string): Promise<ReportData> {
  const response = await apiClient.post<ReportData>(`/assessments/${assessmentId}/report`)
  return response.data
}

export async function downloadReportBlob(
  assessmentId: string,
  filename: string,
  mediaType: string,
  onProgress?: (progress: DownloadProgress) => void,
): Promise<void> {
  const response = await apiClient.get(`/assessments/${assessmentId}/report`, {
    responseType: "blob",
    onDownloadProgress: (e) => {
      if (onProgress && e.total) {
        onProgress({
          loaded: e.loaded,
          total: e.total,
          percent: Math.round((e.loaded / e.total) * 100),
        })
      }
    },
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

export function getReportViewUrl(assessmentId: string): string {
  const baseUrl = apiClient.defaults.baseURL ?? ""
  return `${baseUrl}/assessments/${assessmentId}/report`
}
