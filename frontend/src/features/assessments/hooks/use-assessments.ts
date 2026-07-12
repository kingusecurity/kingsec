import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  listAssessments,
  createAssessment,
  startAssessment,
  cancelAssessment,
  deleteAssessment,
  generateReport,
} from "../api/assessments"
import type { ListAssessmentsParams, CreateAssessmentRequest } from "../types"
import { getApiError } from "@/shared/api/error-handler"

export const ASSESSMENT_QUERY_KEY = "assessments"

export function useAssessments(params: ListAssessmentsParams) {
  return useQuery({
    queryKey: [ASSESSMENT_QUERY_KEY, params],
    queryFn: () => listAssessments(params),
    refetchInterval: 30_000,
  })
}

export function useCreateAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateAssessmentRequest) => createAssessment(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ASSESSMENT_QUERY_KEY] })
      toast.success("Assessment created")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useStartAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => startAssessment(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ASSESSMENT_QUERY_KEY] })
      toast.success("Assessment started")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useCancelAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => cancelAssessment(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ASSESSMENT_QUERY_KEY] })
      toast.success("Assessment cancelled")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useDeleteAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteAssessment(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [ASSESSMENT_QUERY_KEY] })
      toast.success("Assessment deleted")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}

export function useGenerateReport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => generateReport(id),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: [ASSESSMENT_QUERY_KEY] })
      const blob = new Blob([Uint8Array.from(atob(data.artifact_bytes.toString()), (c) => c.charCodeAt(0))], {
        type: data.artifact_media_type,
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = data.artifact_filename
      a.click()
      URL.revokeObjectURL(url)
      toast.success("Report generated")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
  })
}
