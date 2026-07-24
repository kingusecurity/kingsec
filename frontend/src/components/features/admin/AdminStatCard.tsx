import { memo } from 'react'
import { Card } from '@/components/ui/Card'
import { Skeleton } from '@/components/ui/Skeleton'

interface AdminStatCardProps {
  label: string
  value: number | undefined
  icon: React.ComponentType<{ className?: string }>
  loading?: boolean
}

export const AdminStatCard = memo(function AdminStatCard({ label, value, icon: Icon, loading }: AdminStatCardProps) {
  return (
    <Card>
      <div className="flex items-center gap-4 p-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent/10" aria-hidden="true">
          <Icon className="h-5 w-5 text-accent" />
        </div>
        <div className="min-w-0">
          <p className="text-xs text-text-muted">{label}</p>
          {loading ? (
            <Skeleton className="h-7 w-16 mt-0.5" />
          ) : (
            <p className="text-2xl font-bold text-text-primary">{value ?? 0}</p>
          )}
        </div>
      </div>
    </Card>
  )
})
