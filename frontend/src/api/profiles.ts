import { apiRequest } from './client'

export interface AssessmentProfile {
  id: string
  name: string
  description: string
  supported_target_types: string[]
  scanners: string[]
  estimated_duration_minutes: number
  required_scanners: string[]
  tags: string[]
}

export interface PlanScannerEntry {
  scanner_id: string
  name: string
  selected: boolean
  skip_state: string | null
  reason: string
}

export interface ExecutionPlan {
  profile_id: string
  profile_name: string
  target_value: string
  target_type: string
  selected_scanners: PlanScannerEntry[]
  skipped_scanners: PlanScannerEntry[]
  unavailable_scanners: PlanScannerEntry[]
  warnings: string[]
  estimated_duration_minutes: number
  can_proceed: boolean
}

export interface PlanRequestBody {
  target: string
  target_type: string
}

export const profilesApi = {
  list: () =>
    apiRequest<AssessmentProfile[]>('/profiles'),

  get: (profileId: string) =>
    apiRequest<AssessmentProfile>(`/profiles/${profileId}`),

  plan: (profileId: string, body: PlanRequestBody) =>
    apiRequest<ExecutionPlan>(`/profiles/${profileId}/plan`, { method: 'POST', body }),
}
