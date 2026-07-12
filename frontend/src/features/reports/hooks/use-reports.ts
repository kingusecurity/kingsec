import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { generateReport, downloadReportBlob } from "../api/reports"
import { assessmentKeys } from "@/features/assessments/hooks/use-assessments"
import { getApiError } from "@/shared/api/error-handler"

export const reportKeys = {
  all: ["reports"] as const,
  byAssessment: (id: string) => [...reportKeys.all, id] as const,
}

export function useGenerateReport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (assessmentId: string) => generateReport(assessmentId),
    onSuccess: (data) => {
      queryClient.setQueryData(reportKeys.byAssessment(data.assessment_id), data)
      queryClient.invalidateQueries({ queryKey: assessmentKeys.all })
      toast.success("Report generated")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useDownloadReport() {
  return useMutation({
    mutationFn: ({ assessmentId, filename, mediaType }: { assessmentId: string; filename: string; mediaType: string }) =>
      downloadReportBlob(assessmentId, filename, mediaType),
    onSuccess: () => {
      toast.success("Report downloaded")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}
