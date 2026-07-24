import { PageContainer, PageHeader } from '@/components/layout/PageContainer'
import { RolePermissionsPanel } from '@/components/features/admin/RolePermissionsPanel'
import { useRoles } from '@/hooks/use-admin'

export function RolesPage() {
  const { data, isLoading, error, refetch } = useRoles()

  return (
    <PageContainer>
      <PageHeader title="Roles & Permissions" description="View system roles and their access permissions" />
      <RolePermissionsPanel
        roles={data?.roles}
        isLoading={isLoading}
        error={error as Error | null}
        onRetry={() => refetch()}
      />
    </PageContainer>
  )
}
