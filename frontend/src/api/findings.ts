import { apiRequest } from './client'
import type { FindingsListParams, FindingDetail } from '@/types/api'

export interface ListFindingsResponse {
  items: FindingDetail[]
  total: number
  limit: number
  offset: number
}

export const findingsApi = {
  list: (params?: FindingsListParams) =>
    apiRequest<ListFindingsResponse>('/findings', { params: params as Record<string, string | number | undefined> | undefined }),

  get: (id: string) =>
    apiRequest<FindingDetail>(`/findings/${id}`),
}
