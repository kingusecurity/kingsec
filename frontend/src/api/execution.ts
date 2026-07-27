import { apiRequest } from './client'
import type {
  ExecutionStatus,
  ExecutionEventsResponse,
  ExecutionProgressResponse,
} from '@/types/execution'

export const executionApi = {
  status: (assessmentId: string) =>
    apiRequest<ExecutionStatus>(`/assessments/${assessmentId}/execution/status`),

  events: (assessmentId: string) =>
    apiRequest<ExecutionEventsResponse>(`/assessments/${assessmentId}/execution/events`),

  progress: (assessmentId: string) =>
    apiRequest<ExecutionProgressResponse>(`/assessments/${assessmentId}/execution/progress`),

  cancel: (assessmentId: string) =>
    apiRequest<{ assessment_id: string; status: string }>(
      `/assessments/${assessmentId}/execution/cancel`,
      { method: 'POST', body: {} },
    ),
}
