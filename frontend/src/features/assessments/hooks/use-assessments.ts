import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  listAssessments,
  getAssessment,
  createAssessment,
  startAssessment,
  cancelAssessment,
  deleteAssessment,
  generateReport,
} from "../api/assessments"
import type {
  ListAssessmentsParams,
  CreateAssessmentRequest,
  AssessmentSummary,
  ListAssessmentsResponse,
} from "../types"
import { getApiError } from "@/shared/api/error-handler"

export const assessmentKeys = {
  all: ["assessments"] as const,
  lists: () => [...assessmentKeys.all, "list"] as const,
  list: (params: ListAssessmentsParams) => [...assessmentKeys.lists(), params] as const,
  details: () => [...assessmentKeys.all, "detail"] as const,
  detail: (id: string) => [...assessmentKeys.details(), id] as const,
}

export function useAssessments(params: ListAssessmentsParams) {
  return useQuery({
    queryKey: assessmentKeys.list(params),
    queryFn: () => listAssessments(params),
    refetchInterval: 30_000,
  })
}

export function useAssessmentDetail(id: string) {
  return useQuery({
    queryKey: assessmentKeys.detail(id),
    queryFn: () => getAssessment(id),
  })
}

export function useCreateAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateAssessmentRequest) => createAssessment(data),
    onMutate: async (data) => {
      await queryClient.cancelQueries({ queryKey: assessmentKeys.lists() })
      const previous = queryClient.getQueryData<ListAssessmentsResponse>(assessmentKeys.list({ limit: 50, offset: 0 }))
      if (previous) {
        queryClient.setQueryData<ListAssessmentsResponse>(
          assessmentKeys.list({ limit: 50, offset: 0 }),
          {
            ...previous,
            items: [
              {
                assessment_id: `temp-${Date.now()}`,
                target: data.target_value,
                status: "CREATED",
                is_authorized: true,
                created_at: new Date().toISOString(),
                findings_count: 0,
              },
              ...previous.items,
            ],
            total: previous.total + 1,
          },
        )
      }
      return { previous }
    },
    onError: (err, _data, context) => {
      if (context?.previous) {
        queryClient.setQueryData(assessmentKeys.list({ limit: 50, offset: 0 }), context.previous)
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: assessmentKeys.all })
    },
  })
}

export function useStartAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => startAssessment(id),
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: assessmentKeys.detail(id) })
      const previous = queryClient.getQueryData(assessmentKeys.detail(id))
      queryClient.setQueryData(assessmentKeys.detail(id), (old: AssessmentSummary | undefined) =>
        old ? { ...old, status: "RUNNING" as const } : old,
      )
      return { previous }
    },
    onError: (err, id, context) => {
      if (context?.previous) {
        queryClient.setQueryData(assessmentKeys.detail(id), context.previous)
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: (_data, _err, id) => {
      queryClient.invalidateQueries({ queryKey: assessmentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: assessmentKeys.lists() })
    },
  })
}

export function useCancelAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => cancelAssessment(id),
    onMutate: async (id) => {
      await queryClient.cancelQueries({ queryKey: assessmentKeys.detail(id) })
      const previous = queryClient.getQueryData(assessmentKeys.detail(id))
      queryClient.setQueryData(assessmentKeys.detail(id), (old: AssessmentSummary | undefined) =>
        old ? { ...old, status: "CANCELLED" as const } : old,
      )
      return { previous }
    },
    onError: (err, id, context) => {
      if (context?.previous) {
        queryClient.setQueryData(assessmentKeys.detail(id), context.previous)
      }
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: (_data, _err, id) => {
      queryClient.invalidateQueries({ queryKey: assessmentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: assessmentKeys.lists() })
    },
  })
}

export function useDeleteAssessment() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteAssessment(id),
    onSuccess: () => {
      toast.success("Assessment deleted")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: assessmentKeys.all })
    },
  })
}

export function useGenerateReport() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => generateReport(id),
    onSuccess: (data) => {
      const byteChars = atob(data.artifact_bytes.toString())
      const bytes = new Uint8Array(byteChars.length)
      for (let i = 0; i < byteChars.length; i++) {
        bytes[i] = byteChars.charCodeAt(i)
      }
      const blob = new Blob([bytes], { type: data.artifact_media_type })
      const url = URL.createObjectURL(blob)
      const a = document.createElement("a")
      a.href = url
      a.download = data.artifact_filename
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success("Report downloaded")
    },
    onError: (err) => {
      const e = getApiError(err)
      toast.error(e.detail)
    },
    onSettled: (_data, _err, id) => {
      queryClient.invalidateQueries({ queryKey: assessmentKeys.detail(id) })
    },
  })
}
