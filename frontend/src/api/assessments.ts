import { apiRequest } from './client'
import type {
  ListAssessmentsResponse,
  AssessmentResponse,
  CreateAssessmentBody,
  CreateAssessmentResponse,
  GenerateReportResponse,
  AssessmentListParams,
} from '@/types/api'

export const assessmentsApi = {
  list: (params?: AssessmentListParams) =>
    apiRequest<ListAssessmentsResponse>('/assessments', { params: params as Record<string, string | number | undefined> | undefined }),

  get: (id: string) =>
    apiRequest<AssessmentResponse>(`/assessments/${id}`),

  create: (data: CreateAssessmentBody) =>
    apiRequest<CreateAssessmentResponse>('/assessments', { method: 'POST', body: data }),

  start: (id: string) =>
    apiRequest<{ assessment_id: string; status: string; job_id: string | null }>(`/assessments/${id}/start`, { method: 'POST', body: {} }),

  cancel: (id: string) =>
    apiRequest<{ assessment_id: string; status: string }>(`/assessments/${id}/cancel`, { method: 'POST', body: {} }),

  report: (id: string) =>
    apiRequest<GenerateReportResponse>(`/assessments/${id}/report`, { method: 'POST', body: {} }),

  delete: (id: string) =>
    apiRequest<void>(`/assessments/${id}`, { method: 'DELETE' }),
}
