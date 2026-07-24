import { useDashboardSummary, useDashboardSeverity, useDashboardJobs } from '@/hooks/use-dashboard'
import { Shield, Activity, TrendingUp, AlertTriangle } from 'lucide-react'

export function DashboardPage() {
  const { data: summary, isLoading: summaryLoading } = useDashboardSummary()
  const { data: severity } = useDashboardSeverity()
  const { data: jobs } = useDashboardJobs()

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Dashboard</h1>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={Shield}
          label="Total Scans"
          value={summary?.total_scans ?? '-'}
          loading={summaryLoading}
        />
        <StatCard
          icon={AlertTriangle}
          label="Critical"
          value={severity?.critical ?? '-'}
          loading={summaryLoading}
          color="text-red-500"
        />
        <StatCard
          icon={Activity}
          label="Pending Jobs"
          value={jobs?.pending ?? '-'}
          loading={summaryLoading}
        />
        <StatCard
          icon={TrendingUp}
          label="Completed"
          value={jobs?.completed ?? '-'}
          loading={summaryLoading}
          color="text-emerald-500"
        />
      </div>
    </div>
  )
}

interface StatCardProps {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string | number
  loading?: boolean
  color?: string
}

function StatCard({ icon: Icon, label, value, loading, color }: StatCardProps) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 p-4">
      <div className="flex items-center gap-3">
        <Icon className={`h-5 w-5 ${color ?? 'text-gray-400'}`} />
        <span className="text-sm text-gray-400">{label}</span>
      </div>
      <p className={`mt-2 text-2xl font-semibold ${loading ? 'animate-pulse' : ''}`}>
        {loading ? '...' : value}
      </p>
    </div>
  )
}
