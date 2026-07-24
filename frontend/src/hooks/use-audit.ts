import { useQuery } from '@tanstack/react-query'
import { auditApi } from '@/api/audit'
import type { AuditListParams } from '@/api/audit'

export function useAuditLog(params?: AuditListParams) {
  return useQuery({
    queryKey: ['audit', params],
    queryFn: () => auditApi.list(params),
  })
}

export function useAuditEntry(id: string) {
  return useQuery({
    queryKey: ['audit', id],
    queryFn: () => auditApi.get(id),
    enabled: !!id,
  })
}
