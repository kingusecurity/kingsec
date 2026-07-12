import { apiClient } from "@/shared/api/client"
import type {
  ListAssessmentsResponse,
  ListAssessmentsParams,
  CreateAssessmentRequest,
  CreateAssessmentResponse,
  StartAssessmentResponse,
  CancelAssessmentResponse,
  AssessmentDetail,
  GenerateReportResponse,
} from "../types"

export async function listAssessments(params: ListAssessmentsParams = {}): Promise<ListAssessmentsResponse> {
  const response = await apiClient.get<ListAssessmentsResponse>("/assessments", {
    params: { limit: params.limit ?? 50, offset: params.offset ?? 0 },
  })
  return response.data
}

export async function getAssessment(id: string): Promise<AssessmentDetail> {
  const response = await apiClient.get<AssessmentDetail>(`/assessments/${id}`)
  return response.data
}

export async function createAssessment(data: CreateAssessmentRequest): Promise<CreateAssessmentResponse> {
  const response = await apiClient.post<CreateAssessmentResponse>("/assessments", data)
  return response.data
}

export async function startAssessment(id: string): Promise<StartAssessmentResponse> {
  const response = await apiClient.post<StartAssessmentResponse>(`/assessments/${id}/start`)
  return response.data
}

export async function cancelAssessment(id: string): Promise<CancelAssessmentResponse> {
  const response = await apiClient.post<CancelAssessmentResponse>(`/assessments/${id}/cancel`)
  return response.data
}

export async function deleteAssessment(id: string): Promise<void> {
  await apiClient.delete(`/assessments/${id}`)
}

export async function generateReport(id: string): Promise<GenerateReportResponse> {
  const response = await apiClient.post<GenerateReportResponse>(`/assessments/${id}/report`)
  return response.data
}
