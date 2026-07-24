import { apiRequest } from './client'
import type {
  ListAssessmentsResponse,
  AssessmentResponse,
  CreateAssessmentBody,
  CreateAssessmentResponse,
  GenerateReportResponse,
} from '@/types/api'

export const assessmentsApi = {
  list: (params?: { limit?: number; offset?: number }) =>
    apiRequest<ListAssessmentsResponse>('/assessments', { params }),

  get: (id: string) =>
    apiRequest<AssessmentResponse>(`/assessments/${id}`),

  create: (data: CreateAssessmentBody) =>
    apiRequest<CreateAssessmentResponse>('/assessments', { method: 'POST', body: data }),

  start: (id: string) =>
    apiRequest<{ assessment_id: string; status: string; job_id?: string }>(
      `/assessments/${id}/start`,
      { method: 'POST', body: {} },
    ),

  cancel: (id: string) =>
    apiRequest<{ assessment_id: string; status: string }>(
      `/assessments/${id}/cancel`,
      { method: 'POST', body: {} },
    ),

  report: (id: string) =>
    apiRequest<GenerateReportResponse>(`/assessments/${id}/report`, { method: 'POST', body: {} }),

  delete: (id: string) =>
    apiRequest<void>(`/assessments/${id}`, { method: 'DELETE' }),
}
