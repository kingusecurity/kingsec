import { apiRequest, getAccessToken } from './client'
import type {
  ListAssessmentsResponse,
  AssessmentResponse,
  CreateAssessmentBody,
  CreateAssessmentResponse,
  GenerateReportResponse,
  AssessmentListParams,
  StartAssessmentResponse,
  CancelAssessmentResponse,
  DeleteAssessmentResponse,
} from '@/types/api'

export const assessmentsApi = {
  list: (params?: AssessmentListParams) =>
    apiRequest<ListAssessmentsResponse>('/assessments', { params: params as Record<string, string | number | undefined> | undefined }),

  get: (id: string) =>
    apiRequest<AssessmentResponse>(`/assessments/${id}`),

  findings: (id: string) =>
    apiRequest<{ findings: import('@/types/api').FindingResponse[] }>(`/assessments/${id}/findings`),

  create: (data: CreateAssessmentBody) =>
    apiRequest<CreateAssessmentResponse>('/assessments', { method: 'POST', body: data }),

  start: (id: string) =>
    apiRequest<StartAssessmentResponse>(`/assessments/${id}/start`, { method: 'POST', body: {} }),

  cancel: (id: string) =>
    apiRequest<CancelAssessmentResponse>(`/assessments/${id}/cancel`, { method: 'POST', body: {} }),

  report: (id: string) =>
    apiRequest<GenerateReportResponse>(`/assessments/${id}/report`, { method: 'POST', body: {} }),

  delete: (id: string) =>
    apiRequest<DeleteAssessmentResponse>(`/assessments/${id}`, { method: 'DELETE' }),

  getReportDownloadUrl: (assessmentId: string, artifactFilename: string): string => {
    const token = getAccessToken()
    return `/api/v1/assessments/${assessmentId}/report/download/${artifactFilename}?token=${token}`
  },
}
