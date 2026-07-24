import { Users, UserCheck, UserX, Shield, UserCog, Eye } from 'lucide-react'
import { PageContainer, PageHeader, StatGrid } from '@/components/layout/PageContainer'
import { AdminStatCard } from '@/components/features/admin/AdminStatCard'
import { ErrorState } from '@/components/ui/ErrorState'
import { useAdminStats } from '@/hooks/use-admin'

export function AdminDashboardPage() {
  const { data: stats, isLoading, error, refetch } = useAdminStats()

  if (error) {
    return (
      <PageContainer>
        <PageHeader title="Administration" description="User and role management overview" />
        <ErrorState title="Failed to load admin stats" message={(error as Error).message} onRetry={refetch} />
      </PageContainer>
    )
  }

  return (
    <PageContainer>
      <PageHeader title="Administration" description="User and role management overview" />

      <StatGrid columns={3}>
        <AdminStatCard icon={Users} label="Total Users" value={stats?.total_users} loading={isLoading} />
        <AdminStatCard icon={UserCheck} label="Active Users" value={stats?.active_users} loading={isLoading} />
        <AdminStatCard icon={UserX} label="Disabled Users" value={stats?.disabled_users} loading={isLoading} />
      </StatGrid>

      <StatGrid columns={3}>
        <AdminStatCard icon={Shield} label="Administrators" value={stats?.admin_count} loading={isLoading} />
        <AdminStatCard icon={UserCog} label="Analysts" value={stats?.analyst_count} loading={isLoading} />
        <AdminStatCard icon={Eye} label="Viewers" value={stats?.viewer_count} loading={isLoading} />
      </StatGrid>
    </PageContainer>
  )
}
